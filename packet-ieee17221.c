/* packet-ieee17221.c
 * Dissector for IEEE P1722.1
 * Copyright 2011, Andy Lucas <andy@xmos.com>
 *
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>

#include <epan/packet.h>
#include <epan/etypes.h>

/* 1722.1 ADP Offsets */
#define ADP_CD_OFFSET                       0
#define ADP_VERSION_OFFSET                  1
#define ADP_VALID_TIME_OFFSET               2
#define ADP_CD_LENGTH_OFFSET                3
#define ADP_ENTITY_GUID_OFFSET              4
#define ADP_VENDOR_ID_OFFSET                12
#define ADP_MODEL_ID_OFFSET                 16
#define ADP_ENTITY_CAP_OFFSET               20
#define ADP_TALKER_STREAM_SRCS_OFFSET       24
#define ADP_TALKER_CAP_OFFSET               26
#define ADP_LISTENER_STREAM_SINKS_OFFSET    28
#define ADP_LISTENER_CAP_OFFSET             30
#define ADP_CONTROLLER_CAP_OFFSET           32
#define ADP_AVAIL_INDEX_OFFSET              36
#define ADP_AS_GM_ID_OFFSET                 40
#define ADP_DEF_AUDIO_FORMAT_OFFSET         48
#define ADP_CHAN_FORMAT_OFFSET              50
#define ADP_DEF_VIDEO_FORMAT_OFFSET         52
#define ADP_ASSOC_ID_OFFSET                 56
#define ADP_ENTITY_TYPE_OFFSET              64

/* Bit Field Masks */

#define ADP_MSG_TYPE_MASK                   0x0f
#define ADP_VALID_TIME_MASK                 0xf8
#define ADP_CD_LENGTH_MASK                  0x07ff

/* message_type */

#define ADP_ENTITY_AVAILABLE_MESSAGE        0x00
#define ADP_ENTITY_DEPARTING_MESSAGE        0x01
#define ADP_ENTITY_DISCOVER_MESSAGE         0x02

/* entity_capabilities_flags                            */
#define ADP_AVDECC_IP_BITMASK                0x01
#define ADP_ZERO_CONF_BITMASK                0x02
#define ADP_GATEWAY_ENTITY_BITMASK           0x04
#define ADP_AVDECC_CONTROL_BITMASK           0x08
#define ADP_LEGACY_AVC_BITMASK               0x10
#define ADP_ASSOC_ID_SUPPORT_BITMASK         0x20
#define ADP_ASSOC_ID_VALID_BITMASK           0x40

/* talker capabilities flags                            */
#define ADP_TALK_IMPLEMENTED_BITMASK         0x0001
#define ADP_TALK_OTHER_SRC_BITMASK           0x0200
#define ADP_TALK_CONTROL_SRC_BITMASK         0x0400
#define ADP_TALK_MEDIA_CLK_SRC_BITMASK       0x0800
#define ADP_TALK_SMPTE_SRC_BITMASK           0x1000
#define ADP_TALK_MIDI_SRC_BITMASK            0x2000
#define ADP_TALK_AUDIO_SRC_BITMASK           0x4000
#define ADP_TALK_VIDEO_SRC_BITMASK           0x8000

/* listener capabilities flags                            */
#define ADP_LIST_IMPLEMENTED_BITMASK         0x0001
#define ADP_LIST_OTHER_SINK_BITMASK          0x0200
#define ADP_LIST_CONTROL_SINK_BITMASK        0x0400
#define ADP_LIST_MEDIA_CLK_SINK_BITMASK      0x0800
#define ADP_LIST_SMPTE_SINK_BITMASK          0x1000
#define ADP_LIST_MIDI_SINK_BITMASK           0x2000
#define ADP_LIST_AUDIO_SINK_BITMASK          0x4000
#define ADP_LIST_VIDEO_SINK_BITMASK          0x8000

/* Controller capabilities flags                        */
#define ADP_CONT_IMPLEMENTED_BITMASK         0x00000001
#define ADP_CONT_LAYER3_PROXY_BITMASK        0x00000002

/* Default audio formats fields */
#define ADP_DEF_AUDIO_SAMPLE_RATES_MASK      0xFC
#define ADP_DEF_AUDIO_MAX_CHANS_MASK         0x03FC
#define ADP_DEF_AUDIO_SAF_MASK               0x0002
#define ADP_DEF_AUDIO_FLOAT_MASK             0x0001

/* Default sample rates flags */
#define ADP_SAMP_RATE_44K1_BITMASK           0x01<<2
#define ADP_SAMP_RATE_48K_BITMASK            0x02<<2
#define ADP_SAMP_RATE_88K2_BITMASK           0x04<<2
#define ADP_SAMP_RATE_96K_BITMASK            0x08<<2
#define ADP_SAMP_RATE_176K4_BITMASK          0x10<<2
#define ADP_SAMP_RATE_192K_BITMASK           0x20<<2

/* channel_formats flags */

#define ADP_CHAN_FORMAT_MONO                        (0x00000001)
#define ADP_CHAN_FORMAT_2CH                         (0x00000002)
#define ADP_CHAN_FORMAT_3CH                         (0x00000004)
#define ADP_CHAN_FORMAT_4CH                         (0x00000008)
#define ADP_CHAN_FORMAT_5CH                         (0x00000010)
#define ADP_CHAN_FORMAT_6CH                         (0x00000020)
#define ADP_CHAN_FORMAT_7CH                         (0x00000040)
#define ADP_CHAN_FORMAT_8CH                         (0x00000080)
#define ADP_CHAN_FORMAT_10CH                        (0x00000100)
#define ADP_CHAN_FORMAT_12CH                        (0x00000200)
#define ADP_CHAN_FORMAT_14CH                        (0x00000400)
#define ADP_CHAN_FORMAT_16CH                        (0x00000800)
#define ADP_CHAN_FORMAT_18CH                        (0x00001000)
#define ADP_CHAN_FORMAT_20CH                        (0x00002000)
#define ADP_CHAN_FORMAT_22CH                        (0x00004000)
#define ADP_CHAN_FORMAT_24CH                        (0x00008000)

/******************************************************************************/
/* 1722.1 ACMP Offsets */
#define ACMP_CD_OFFSET                      0
#define ACMP_VERSION_OFFSET                 1
#define ACMP_STATUS_FIELD_OFFSET            2
#define ACMP_CD_LENGTH_OFFSET               3
#define ACMP_STREAM_ID_OFFSET               4
#define ACMP_CONTROLLER_GUID_OFFSET         12
#define ACMP_TALKER_GUID_OFFSET             20
#define ACMP_LISTENER_GUID_OFFSET           28
#define ACMP_TALKER_UNIQUE_ID_OFFSET        36
#define ACMP_LISTENER_UNIQUE_ID_OFFSET      38
#define ACMP_DEST_MAC_OFFSET                40
#define ACMP_CONNECTION_COUNT_OFFSET        46
#define ACMP_SEQUENCE_ID_OFFSET             48
#define ACMP_FLAGS_OFFSET                   50
#define ACMP_DEFAULT_FORMAT_OFFSET          52

/* Bit Field Masks */

#define ACMP_MSG_TYPE_MASK                  0x0f
#define ACMP_STATUS_FIELD_MASK              0xf8
#define ACMP_CD_LENGTH_MASK                 0x07ff

/* message_type */

#define ACMP_CONNECT_TX_COMMAND             0
#define ACMP_CONNECT_TX_RESPONSE            1
#define ACMP_DISCONNECT_TX_COMMAND          2
#define ACMP_DISCONNECT_TX_RESPONSE         3
#define ACMP_GET_TX_STATE_COMMAND           4
#define ACMP_GET_TX_STATE_RESPONSE          5
#define ACMP_CONNECT_RX_COMMAND             6
#define ACMP_CONNECT_RX_RESPONSE            7
#define ACMP_DISCONNECT_RX_COMMAND          8
#define ACMP_DISCONNECT_RX_RESPONSE         9
#define ACMP_GET_RX_STATE_COMMAND           10
#define ACMP_GET_RX_STATE_RESPONSE          11
#define ACMP_GET_TX_CONNECTION_COMMAND      12
#define ACMP_GET_TX_CONNECTION_RESPONSE     13

/* status_field */

#define ACMP_STATUS_SUCCESS                             0
#define ACMP_STATUS_LISTENER_UNKNOWN_ID                 1
#define ACMP_STATUS_TALKER_UNKNOWN_ID                   2
#define ACMP_STATUS_TALKER_DEST_MAC_FAIL                3
#define ACMP_STATUS_TALKER_NO_STREAM_INDEX              4
#define ACMP_STATUS_TALKER_NO_BANDWIDTH                 5
#define ACMP_STATUS_TALKER_EXCLUSIVE                    6
#define ACMP_STATUS_LISTENER_TALKER_TIMEOUT             7
#define ACMP_STATUS_LISTENER_EXCLUSIVE                  8
#define ACMP_STATUS_STATE_UNAVAILABLE                   9
#define ACMP_STATUS_NOT_CONNECTED                       10
#define ACMP_STATUS_NO_SUCH_CONNECTION                  11
#define ACMP_STATUS_COULD_NOT_SEND_MESSAGE              12
#define ACMP_STATUS_LISTENER_DEFAULT_FORMAT_INVALID     13
#define ACMP_STATUS_TALKER_DEFAULT_FORMAT_INVALID       14
#define ACMP_STATUS_DEFAULT_SET_DIFFERENT               15
#define ACMP_STATUS_NOT_SUPPORTED                       31

/* ACMP flags                                   */
#define ACMP_FLAG_CLASS_B_BITMASK               0x0001
#define ACMP_FLAG_FAST_CONNECT_BITMASK          0x0002
#define ACMP_FLAG_SAVED_STATE_BITMASK           0x0004
#define ACMP_FLAG_STREAMING_WAIT_BITMASK        0x0008


static const value_string adp_message_type_vals[] = {
    {ADP_ENTITY_AVAILABLE_MESSAGE,       "ENTITY_AVAILABLE"},
    {ADP_ENTITY_DEPARTING_MESSAGE,       "ENTITY_DEPARTING"},
    {ADP_ENTITY_DISCOVER_MESSAGE,        "ENTITY_DISCOVER"},
    {0,                                  NULL }
};

static const value_string acmp_message_type_vals[] = {
    {ACMP_CONNECT_TX_COMMAND,           "CONNECT_TX_COMMAND"},
    {ACMP_CONNECT_TX_RESPONSE,          "CONNECT_TX_RESPONSE"},
    {ACMP_DISCONNECT_TX_COMMAND,        "DISCONNECT_TX_COMMAND"},
    {ACMP_DISCONNECT_TX_RESPONSE,       "DISCONNECT_TX_RESPONSE"},
    {ACMP_GET_TX_STATE_COMMAND,         "GET_TX_STATE_COMMAND"},
    {ACMP_GET_TX_STATE_RESPONSE,        "GET_TX_STATE_RESPONSE"},
    {ACMP_CONNECT_RX_COMMAND,           "CONNECT_RX_COMMAND"},
    {ACMP_CONNECT_RX_RESPONSE,          "CONNECT_RX_RESPONSE"},
    {ACMP_DISCONNECT_RX_COMMAND,        "DISCONNECT_RX_COMMAND"},
    {ACMP_DISCONNECT_RX_RESPONSE,       "DISCONNECT_RX_RESPONSE"},
    {ACMP_GET_RX_STATE_COMMAND,         "GET_RX_STATE_COMMAND"},
    {ACMP_GET_RX_STATE_RESPONSE,        "GET_RX_STATE_RESPONSE"},
    {ACMP_GET_TX_CONNECTION_COMMAND,    "GET_TX_CONNECTION_COMMAND"},
    {ACMP_GET_TX_CONNECTION_RESPONSE,   "GET_TX_CONNECTION_RESPONSE"},
    {0,                                  NULL }
};

static const value_string acmp_status_field_vals[] = {
    {ACMP_STATUS_SUCCESS,                               "SUCCESS"},
    {ACMP_STATUS_LISTENER_UNKNOWN_ID,                   "LISTENER_UNKNOWN_ID"},
    {ACMP_STATUS_TALKER_UNKNOWN_ID,                     "TALKER_UNKNOWN_ID"},
    {ACMP_STATUS_TALKER_DEST_MAC_FAIL,                  "TALKER_DEST_MAC_FAIL"},
    {ACMP_STATUS_TALKER_NO_STREAM_INDEX,                "TALKER_NO_STREAM_INDEX"},
    {ACMP_STATUS_TALKER_NO_BANDWIDTH,                   "TALKER_NO_BANDWIDTH"},
    {ACMP_STATUS_TALKER_EXCLUSIVE,                      "TALKER_EXCLUSIVE"},
    {ACMP_STATUS_LISTENER_TALKER_TIMEOUT,               "LISTENER_TALKER_TIMEOUT"},
    {ACMP_STATUS_LISTENER_EXCLUSIVE,                    "LISTENER_EXCLUSIVE"},
    {ACMP_STATUS_STATE_UNAVAILABLE,                     "STATE_UNAVAILABLE"},
    {ACMP_STATUS_NOT_CONNECTED,                         "NOT_CONNECTED"},
    {ACMP_STATUS_NO_SUCH_CONNECTION,                    "NO_SUCH_CONNECTION"},
    {ACMP_STATUS_COULD_NOT_SEND_MESSAGE,                "COULD_NOT_SEND_MESSAGE"},
    {ACMP_STATUS_LISTENER_DEFAULT_FORMAT_INVALID,       "LISTENER_DEFAULT_FORMAT_INVALID"},
    {ACMP_STATUS_TALKER_DEFAULT_FORMAT_INVALID,         "TALKER_DEFAULT_FORMAT_INVALID"},
    {ACMP_STATUS_DEFAULT_SET_DIFFERENT,                 "DEFAULT_SET_DIFFERENT"},
    {ACMP_STATUS_NOT_SUPPORTED,                         "NOT_SUPPORTED"},
    {0,                                  NULL }
};

/**********************************************************/
/* Initialize the protocol and registered fields          */
/**********************************************************/
static int proto_17221 = -1;

/* AVDECC Discovery Protocol Data Unit (ADPDU) */
static int hf_adp_message_type = -1;
static int hf_adp_valid_time = -1;
static int hf_adp_cd_length = -1;
static int hf_adp_entity_guid = -1;
static int hf_adp_vendor_id = -1;
static int hf_adp_model_id = -1;
static int hf_adp_entity_cap = -1;
static int hf_adp_talker_stream_srcs = -1;
static int hf_adp_talker_cap = -1;
static int hf_adp_listener_stream_sinks = -1;
static int hf_adp_listener_cap = -1;
static int hf_adp_controller_cap = -1;
static int hf_adp_avail_index = -1;
static int hf_adp_as_gm_id = -1;
static int hf_adp_def_aud_format = -1;
static int hf_adp_def_vid_format = -1;
static int hf_adp_assoc_id = -1;
static int hf_adp_entity_type = -1;

/* Entity Capabilties Flags */
static int hf_adp_entity_cap_avdecc_ip = -1;
static int hf_adp_entity_cap_zero_conf = -1;
static int hf_adp_entity_cap_gateway_entity = -1;
static int hf_adp_entity_cap_avdecc_control = -1;
static int hf_adp_entity_cap_legacy_avc = -1;
static int hf_adp_entity_cap_assoc_id_support = -1;
static int hf_adp_entity_cap_assoc_id_valid = -1;

/* Talker Capabilities Flags */
static int hf_adp_talk_cap_implement = -1;
static int hf_adp_talk_cap_other_src = -1;
static int hf_adp_talk_cap_control_src = -1;
static int hf_adp_talk_cap_media_clk_src = -1;
static int hf_adp_talk_cap_smpte_src = -1;
static int hf_adp_talk_cap_midi_src = -1;
static int hf_adp_talk_cap_audio_src = -1;
static int hf_adp_talk_cap_video_src = -1;

/* Listener Capabilities Flags */
static int hf_adp_list_cap_implement = -1;
static int hf_adp_list_cap_other_sink = -1;
static int hf_adp_list_cap_control_sink = -1;
static int hf_adp_list_cap_media_clk_sink = -1;
static int hf_adp_list_cap_smpte_sink = -1;
static int hf_adp_list_cap_midi_sink = -1;
static int hf_adp_list_cap_audio_sink = -1;
static int hf_adp_list_cap_video_sink = -1;

/* Controller Capabilities Flags */ 
static int hf_adp_cont_cap_implement = -1;
static int hf_adp_cont_cap_layer3_proxy = -1;

/* Default Audio Format */
static int hf_adp_def_aud_sample_rates = -1;
static int hf_adp_def_aud_max_chan = -1;
static int hf_adp_def_aud_saf_flag = -1;
static int hf_adp_def_aud_float_flag = -1;
static int hf_adp_def_aud_chan_formats = -1;

/* Default Audio Sample Rates */
static int hf_adp_samp_rate_44k1 = -1;
static int hf_adp_samp_rate_48k = -1;
static int hf_adp_samp_rate_88k2 = -1;
static int hf_adp_samp_rate_96k = -1;
static int hf_adp_samp_rate_176k4 = -1;
static int hf_adp_samp_rate_192k = -1;

/* Audio Channel Formats */
static int hf_adp_chan_format_mono = -1;
static int hf_adp_chan_format_2ch = -1;
static int hf_adp_chan_format_3ch = -1;
static int hf_adp_chan_format_4ch = -1;
static int hf_adp_chan_format_5ch = -1;
static int hf_adp_chan_format_6ch = -1;
static int hf_adp_chan_format_7ch = -1;
static int hf_adp_chan_format_8ch = -1;
static int hf_adp_chan_format_10ch = -1;
static int hf_adp_chan_format_12ch = -1;
static int hf_adp_chan_format_14ch = -1;
static int hf_adp_chan_format_16ch = -1;
static int hf_adp_chan_format_18ch = -1;
static int hf_adp_chan_format_20ch = -1;
static int hf_adp_chan_format_22ch = -1;
static int hf_adp_chan_format_24ch = -1;

/******************************************************************* */
/* AVDECC Connection Management Protocol Data Unit (ACMPDU) */
static int hf_acmp_message_type = -1;
static int hf_acmp_status_field = -1;
static int hf_acmp_cd_length = -1;
static int hf_acmp_stream_id = -1;
static int hf_acmp_controller_guid = -1;
static int hf_acmp_talker_guid = -1;
static int hf_acmp_listener_guid = -1;
static int hf_acmp_talker_unique_id = -1;
static int hf_acmp_listener_unique_id = -1;
static int hf_acmp_stream_dest_mac = -1;
static int hf_acmp_connection_count = -1;
static int hf_acmp_sequence_id = -1;
static int hf_acmp_flags = -1;
static int hf_acmp_default_format = -1;

/* ACMP Flags */
static int hf_acmp_flags_class_b = -1;
static int hf_acmp_flags_fast_connect = -1;
static int hf_acmp_flags_saved_state = -1;
static int hf_acmp_flags_streaming_wait = -1;

/* Initialize the subtree pointers */
/* ADP */
static int ett_adp_ent_cap = -1;
static int ett_adp_talk_cap = -1;
static int ett_adp_list_cap = -1;
static int ett_adp_cont_cap = -1;
static int ett_adp_aud_format = -1;
static int ett_adp_samp_rates = -1;
static int ett_adp_chan_format = -1;
/* ACMP */
static int ett_acmp_flags = -1;

static int ett_1722 = -1;

static const value_string avb_bool_vals[] = {
    {1, "True"},
    {0, "False"},
    {0,              NULL          }};
    
static void dissect_17221_adp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *adp_tree = NULL;
    proto_item *ent_cap_ti = NULL;
    proto_item *talk_cap_ti = NULL;
    proto_item *list_cap_ti = NULL;
    proto_item *cont_cap_ti = NULL;
    proto_item *aud_format_ti = NULL;
    proto_item *samp_rates_ti = NULL;
    proto_item *chan_format_ti = NULL;
    
    proto_tree *ent_cap_flags_tree = NULL;
    proto_tree *talk_cap_flags_tree = NULL;
    proto_tree *list_cap_flags_tree = NULL;
    proto_tree *cont_cap_flags_tree = NULL;
    proto_tree *aud_format_tree = NULL;
    proto_tree *samp_rates_tree = NULL;
    proto_tree *chan_format_tree = NULL;
       
    adp_tree = proto_item_add_subtree(tree, proto_17221);
    
    proto_tree_add_item(adp_tree, hf_adp_message_type, tvb, ADP_VERSION_OFFSET, 1, FALSE);
    proto_tree_add_item(adp_tree, hf_adp_valid_time, tvb, ADP_VALID_TIME_OFFSET, 1, FALSE);
    proto_tree_add_item(adp_tree, hf_adp_cd_length, tvb, ADP_CD_LENGTH_OFFSET, 1, FALSE);
    proto_tree_add_item(adp_tree, hf_adp_entity_guid, tvb, ADP_ENTITY_GUID_OFFSET, 8, FALSE);
    proto_tree_add_item(adp_tree, hf_adp_vendor_id, tvb, ADP_VENDOR_ID_OFFSET, 4, FALSE);
    proto_tree_add_item(adp_tree, hf_adp_model_id, tvb, ADP_MODEL_ID_OFFSET, 4, FALSE);
    
    /* Subtree for entity_capabilities field */
    if (tree)
    {
        ent_cap_ti = proto_tree_add_item(adp_tree, hf_adp_entity_cap, tvb, ADP_ENTITY_CAP_OFFSET, 4, FALSE);
        
        ent_cap_flags_tree = proto_item_add_subtree(ent_cap_ti, ett_adp_ent_cap);
    
        proto_tree_add_item(ent_cap_flags_tree,
                hf_adp_entity_cap_avdecc_ip, tvb, ADP_ENTITY_CAP_OFFSET, 4, FALSE);
                
        proto_tree_add_item(ent_cap_flags_tree,
                hf_adp_entity_cap_zero_conf, tvb, ADP_ENTITY_CAP_OFFSET, 4, FALSE);
        
        proto_tree_add_item(ent_cap_flags_tree,
                hf_adp_entity_cap_gateway_entity, tvb, ADP_ENTITY_CAP_OFFSET, 4, FALSE);  

        proto_tree_add_item(ent_cap_flags_tree,
                hf_adp_entity_cap_avdecc_control, tvb, ADP_ENTITY_CAP_OFFSET, 4, FALSE);         

        proto_tree_add_item(ent_cap_flags_tree,
                hf_adp_entity_cap_legacy_avc, tvb, ADP_ENTITY_CAP_OFFSET, 4, FALSE);
                
        proto_tree_add_item(ent_cap_flags_tree,
                hf_adp_entity_cap_assoc_id_support, tvb, ADP_ENTITY_CAP_OFFSET, 4, FALSE);
                
        proto_tree_add_item(ent_cap_flags_tree,
                hf_adp_entity_cap_assoc_id_valid, tvb, ADP_ENTITY_CAP_OFFSET, 4, FALSE);                 
    }
    
    
    proto_tree_add_item(adp_tree, hf_adp_talker_stream_srcs, tvb, ADP_TALKER_STREAM_SRCS_OFFSET, 2, FALSE);
    
    if (tree)
    {
        talk_cap_ti = proto_tree_add_item(adp_tree, hf_adp_talker_cap, tvb, ADP_TALKER_CAP_OFFSET, 2, FALSE);
        
        talk_cap_flags_tree = proto_item_add_subtree(talk_cap_ti, ett_adp_talk_cap);
        
        proto_tree_add_item(talk_cap_flags_tree, 
                hf_adp_talk_cap_implement, tvb, ADP_TALKER_CAP_OFFSET, 2, FALSE);
        proto_tree_add_item(talk_cap_flags_tree, 
                hf_adp_talk_cap_other_src, tvb, ADP_TALKER_CAP_OFFSET, 2, FALSE);
        proto_tree_add_item(talk_cap_flags_tree, 
                hf_adp_talk_cap_control_src, tvb, ADP_TALKER_CAP_OFFSET, 2, FALSE);
        proto_tree_add_item(talk_cap_flags_tree, 
                hf_adp_talk_cap_media_clk_src, tvb, ADP_TALKER_CAP_OFFSET, 2, FALSE);
        proto_tree_add_item(talk_cap_flags_tree, 
                hf_adp_talk_cap_smpte_src, tvb, ADP_TALKER_CAP_OFFSET, 2, FALSE);
        proto_tree_add_item(talk_cap_flags_tree, 
                hf_adp_talk_cap_midi_src, tvb, ADP_TALKER_CAP_OFFSET, 2, FALSE);
        proto_tree_add_item(talk_cap_flags_tree, 
                hf_adp_talk_cap_audio_src, tvb, ADP_TALKER_CAP_OFFSET, 2, FALSE);
        proto_tree_add_item(talk_cap_flags_tree, 
                hf_adp_talk_cap_video_src, tvb, ADP_TALKER_CAP_OFFSET, 2, FALSE);
                
    }
    
    proto_tree_add_item(adp_tree, hf_adp_listener_stream_sinks, 
            tvb, ADP_LISTENER_STREAM_SINKS_OFFSET, 2, FALSE);
            
    if (tree)
    {
        list_cap_ti = proto_tree_add_item(adp_tree, hf_adp_listener_cap, tvb, ADP_LISTENER_CAP_OFFSET, 2, FALSE);
        
        list_cap_flags_tree = proto_item_add_subtree(list_cap_ti, ett_adp_list_cap);
        
        proto_tree_add_item(list_cap_flags_tree, 
                hf_adp_list_cap_implement, tvb, ADP_LISTENER_CAP_OFFSET, 2, FALSE);
        proto_tree_add_item(list_cap_flags_tree, 
                hf_adp_list_cap_other_sink, tvb, ADP_LISTENER_CAP_OFFSET, 2, FALSE);
        proto_tree_add_item(list_cap_flags_tree, 
                hf_adp_list_cap_control_sink, tvb, ADP_LISTENER_CAP_OFFSET, 2, FALSE);
        proto_tree_add_item(list_cap_flags_tree, 
                hf_adp_list_cap_media_clk_sink, tvb, ADP_LISTENER_CAP_OFFSET, 2, FALSE);
        proto_tree_add_item(list_cap_flags_tree, 
                hf_adp_list_cap_smpte_sink, tvb, ADP_LISTENER_CAP_OFFSET, 2, FALSE);
        proto_tree_add_item(list_cap_flags_tree, 
                hf_adp_list_cap_midi_sink, tvb, ADP_LISTENER_CAP_OFFSET, 2, FALSE);
        proto_tree_add_item(list_cap_flags_tree, 
                hf_adp_list_cap_audio_sink, tvb, ADP_LISTENER_CAP_OFFSET, 2, FALSE);
        proto_tree_add_item(list_cap_flags_tree, 
                hf_adp_list_cap_video_sink, tvb, ADP_LISTENER_CAP_OFFSET, 2, FALSE);
                
    }
    
    if (tree)
    {
        cont_cap_ti = proto_tree_add_item(adp_tree, hf_adp_controller_cap, tvb, ADP_CONTROLLER_CAP_OFFSET, 4, FALSE);
        
        cont_cap_flags_tree = proto_item_add_subtree(cont_cap_ti, ett_adp_cont_cap);
        
        proto_tree_add_item(cont_cap_flags_tree, 
                hf_adp_cont_cap_implement, tvb, ADP_CONTROLLER_CAP_OFFSET, 4, FALSE);
        proto_tree_add_item(cont_cap_flags_tree, 
                hf_adp_cont_cap_layer3_proxy, tvb, ADP_CONTROLLER_CAP_OFFSET, 4, FALSE);
    }
        
    proto_tree_add_item(adp_tree, hf_adp_avail_index, tvb, ADP_AVAIL_INDEX_OFFSET, 4, FALSE);
    proto_tree_add_item(adp_tree, hf_adp_as_gm_id, tvb, ADP_AS_GM_ID_OFFSET, 8, FALSE);
    
    if (tree)
    {
    
        aud_format_ti = proto_tree_add_item(adp_tree, hf_adp_def_aud_format, tvb, ADP_DEF_AUDIO_FORMAT_OFFSET, 4, FALSE);
        
        aud_format_tree = proto_item_add_subtree(aud_format_ti, ett_adp_aud_format);
        
        if (aud_format_tree)
        {
            samp_rates_ti = proto_tree_add_item(aud_format_tree, 
                                hf_adp_def_aud_sample_rates, tvb, ADP_DEF_AUDIO_FORMAT_OFFSET, 1, FALSE);
         
            samp_rates_tree = proto_item_add_subtree(samp_rates_ti, ett_adp_samp_rates);
            
            proto_tree_add_item(samp_rates_tree, 
                hf_adp_samp_rate_44k1, tvb, ADP_DEF_AUDIO_FORMAT_OFFSET, 1, FALSE);
            proto_tree_add_item(samp_rates_tree, 
                hf_adp_samp_rate_48k, tvb, ADP_DEF_AUDIO_FORMAT_OFFSET, 1, FALSE);
            proto_tree_add_item(samp_rates_tree, 
                hf_adp_samp_rate_88k2, tvb, ADP_DEF_AUDIO_FORMAT_OFFSET, 1, FALSE);
            proto_tree_add_item(samp_rates_tree, 
                hf_adp_samp_rate_96k, tvb, ADP_DEF_AUDIO_FORMAT_OFFSET, 1, FALSE);
            proto_tree_add_item(samp_rates_tree, 
                hf_adp_samp_rate_176k4, tvb, ADP_DEF_AUDIO_FORMAT_OFFSET, 1, FALSE);
            proto_tree_add_item(samp_rates_tree, 
                hf_adp_samp_rate_192k, tvb, ADP_DEF_AUDIO_FORMAT_OFFSET, 1, FALSE);
            
        }
        proto_tree_add_item(aud_format_tree, 
                hf_adp_def_aud_max_chan, tvb, ADP_DEF_AUDIO_FORMAT_OFFSET, 2, FALSE);
        proto_tree_add_item(aud_format_tree, 
                hf_adp_def_aud_saf_flag, tvb, ADP_DEF_AUDIO_FORMAT_OFFSET, 2, FALSE);
        proto_tree_add_item(aud_format_tree, 
                hf_adp_def_aud_float_flag, tvb, ADP_DEF_AUDIO_FORMAT_OFFSET, 2, FALSE);
                
        if (aud_format_tree)
        {
            chan_format_ti = proto_tree_add_item(aud_format_tree, 
                    hf_adp_def_aud_chan_formats, tvb, ADP_CHAN_FORMAT_OFFSET, 2, FALSE);
                    
            chan_format_tree = proto_item_add_subtree(chan_format_ti, ett_adp_chan_format);
            
            proto_tree_add_item(chan_format_tree, 
               hf_adp_chan_format_mono, tvb, ADP_CHAN_FORMAT_OFFSET, 2, FALSE);
            proto_tree_add_item(chan_format_tree, 
               hf_adp_chan_format_2ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, FALSE);
            proto_tree_add_item(chan_format_tree, 
               hf_adp_chan_format_3ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, FALSE);
            proto_tree_add_item(chan_format_tree, 
               hf_adp_chan_format_4ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, FALSE);
            proto_tree_add_item(chan_format_tree, 
               hf_adp_chan_format_5ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, FALSE);
            proto_tree_add_item(chan_format_tree, 
               hf_adp_chan_format_6ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, FALSE);
            proto_tree_add_item(chan_format_tree, 
               hf_adp_chan_format_7ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, FALSE);
            proto_tree_add_item(chan_format_tree, 
               hf_adp_chan_format_8ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, FALSE);
            proto_tree_add_item(chan_format_tree, 
               hf_adp_chan_format_10ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, FALSE);
            proto_tree_add_item(chan_format_tree, 
               hf_adp_chan_format_12ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, FALSE);
            proto_tree_add_item(chan_format_tree, 
               hf_adp_chan_format_14ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, FALSE);
            proto_tree_add_item(chan_format_tree, 
               hf_adp_chan_format_16ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, FALSE);
            proto_tree_add_item(chan_format_tree, 
               hf_adp_chan_format_18ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, FALSE);
            proto_tree_add_item(chan_format_tree, 
               hf_adp_chan_format_20ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, FALSE);
            proto_tree_add_item(chan_format_tree, 
               hf_adp_chan_format_22ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, FALSE);
            proto_tree_add_item(chan_format_tree, 
               hf_adp_chan_format_24ch, tvb, ADP_CHAN_FORMAT_OFFSET, 2, FALSE);
        }
    }
    proto_tree_add_item(adp_tree, hf_adp_def_vid_format, tvb, ADP_DEF_VIDEO_FORMAT_OFFSET, 4, FALSE);
    proto_tree_add_item(adp_tree, hf_adp_assoc_id, tvb, ADP_ASSOC_ID_OFFSET, 8, FALSE);
    proto_tree_add_item(adp_tree, hf_adp_entity_type, tvb, ADP_ENTITY_TYPE_OFFSET, 4, FALSE);

}

static void dissect_17221_acmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *acmp_tree = NULL;
    proto_item *flags_ti = NULL;
    
    proto_tree *flags_tree = NULL;
    
    acmp_tree = proto_item_add_subtree(tree, proto_17221);
    
    proto_tree_add_item(acmp_tree, hf_acmp_message_type, tvb, ACMP_VERSION_OFFSET, 1, FALSE);
    proto_tree_add_item(acmp_tree, hf_acmp_status_field, tvb, ACMP_STATUS_FIELD_OFFSET, 1, FALSE);
    proto_tree_add_item(acmp_tree, hf_acmp_cd_length, tvb, ACMP_CD_LENGTH_OFFSET, 1, FALSE);
    proto_tree_add_item(acmp_tree, hf_acmp_stream_id, tvb, ACMP_STREAM_ID_OFFSET, 8, FALSE);
    proto_tree_add_item(acmp_tree, hf_acmp_controller_guid, tvb, ACMP_CONTROLLER_GUID_OFFSET, 8, FALSE);
    proto_tree_add_item(acmp_tree, hf_acmp_talker_guid, tvb, ACMP_TALKER_GUID_OFFSET, 8, FALSE);
    proto_tree_add_item(acmp_tree, hf_acmp_listener_guid, tvb, ACMP_LISTENER_GUID_OFFSET, 8, FALSE);
    proto_tree_add_item(acmp_tree, hf_acmp_talker_unique_id, tvb, ACMP_TALKER_UNIQUE_ID_OFFSET, 2, FALSE);
    proto_tree_add_item(acmp_tree, hf_acmp_listener_unique_id, tvb, ACMP_LISTENER_UNIQUE_ID_OFFSET, 2, FALSE);
    proto_tree_add_item(acmp_tree, hf_acmp_stream_dest_mac, tvb, ACMP_DEST_MAC_OFFSET, 6, FALSE);
    proto_tree_add_item(acmp_tree, hf_acmp_connection_count, tvb, ACMP_CONNECTION_COUNT_OFFSET, 2, FALSE);
    proto_tree_add_item(acmp_tree, hf_acmp_sequence_id, tvb, ACMP_SEQUENCE_ID_OFFSET, 2, FALSE);
    
    if (tree)
    {
        flags_ti = proto_tree_add_item(acmp_tree, hf_acmp_flags, tvb, ACMP_FLAGS_OFFSET, 2, FALSE);
        
        flags_tree = proto_item_add_subtree(flags_ti, ett_acmp_flags);
        
        proto_tree_add_item(flags_tree,
                hf_acmp_flags_class_b, tvb, ACMP_FLAGS_OFFSET, 2, FALSE);
        proto_tree_add_item(flags_tree,
                hf_acmp_flags_fast_connect, tvb, ACMP_FLAGS_OFFSET, 2, FALSE);
        proto_tree_add_item(flags_tree,
                hf_acmp_flags_saved_state, tvb, ACMP_FLAGS_OFFSET, 2, FALSE);
        proto_tree_add_item(flags_tree,
                hf_acmp_flags_streaming_wait, tvb, ACMP_FLAGS_OFFSET, 2, FALSE);
        
    }    
        
    proto_tree_add_item(acmp_tree, hf_acmp_default_format, tvb, ACMP_DEFAULT_FORMAT_OFFSET, 4, FALSE);
}

static void dissect_17221(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    
    guint8 subtype = 0;
    subtype = tvb_get_guint8(tvb, 0);
    subtype &= 0x7F;
    
    // fprintf(stderr, "subtype: %d\n", subtype);
    
    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IEEE1722-1");
    
    switch (subtype)
    {
        case 0x7A: 
        {
            col_set_str(pinfo->cinfo, COL_INFO, "AVDECC Discovery Protocol");
            dissect_17221_adp(tvb, pinfo, tree);
            break;
        }
        case 0x7B:
        {
            col_set_str(pinfo->cinfo, COL_INFO, "AVDECC Enumeration and Control Protocol");
            break;
        }
        case 0x7C:
        {
            col_set_str(pinfo->cinfo, COL_INFO, "AVDECC Connection Management Protocol");
            dissect_17221_acmp(tvb, pinfo, tree);
            break;
        }
        default:
        {
            /* Shouldn't get here */
            col_set_str(pinfo->cinfo, COL_INFO, "1722.1 Unknown");
            return;
        }
    }
 
}

/* Register the protocol with Wireshark */
void proto_register_17221(void) 
{
    static hf_register_info hf[] = {
        { &hf_adp_message_type,
            { "Message Type", "ieee17221.message_type", 
              FT_UINT8, BASE_DEC, VALS(adp_message_type_vals), ADP_MSG_TYPE_MASK, NULL, HFILL } 
        },
        { &hf_adp_valid_time,
            { "Valid Time", "ieee17221.valid_time", 
              FT_UINT8, BASE_DEC, NULL, ADP_VALID_TIME_MASK, NULL, HFILL } 
        },
        { &hf_adp_cd_length,
            { "Control Data Length", "ieee17221.control_data_length", 
              FT_UINT16, BASE_DEC, NULL, ADP_CD_LENGTH_MASK, NULL, HFILL } 
        },
        { &hf_adp_entity_guid,
            { "Entity GUID", "ieee17221.entity_guid", 
              FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL } 
        },
        { &hf_adp_vendor_id,
            { "Vendor ID", "ieee17221.vendor_id", 
              FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL } 
        },
        { &hf_adp_model_id,
            { "Model ID", "ieee17221.model_id", 
              FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL } 
        },
        { &hf_adp_entity_cap,
            { "Entity Capabilities", "ieee17221.entity_capabilities", 
              FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL } 
        },
        /* Entity Capability Flags Begin */
        { &hf_adp_entity_cap_avdecc_ip,
            { "AVDECC_IP", "ieee17221.entity_capabilities.avdecc_ip", 
              FT_UINT32, BASE_DEC, VALS(avb_bool_vals), ADP_AVDECC_IP_BITMASK, NULL, HFILL } 
        },        
        { &hf_adp_entity_cap_zero_conf,
            { "ZERO_CONF", "ieee17221.entity_capabilities.zero_conf", 
              FT_UINT32, BASE_DEC, VALS(avb_bool_vals), ADP_ZERO_CONF_BITMASK, NULL, HFILL } 
        },   
        { &hf_adp_entity_cap_gateway_entity,
            { "GATEWAY_ENTITY", "ieee17221.entity_capabilities.gateway_entity", 
              FT_UINT32, BASE_DEC, VALS(avb_bool_vals), ADP_GATEWAY_ENTITY_BITMASK, NULL, HFILL } 
        },
        { &hf_adp_entity_cap_avdecc_control,
            { "AVDECC_CONTROL", "ieee17221.entity_capabilities.avdecc_control", 
              FT_UINT32, BASE_DEC, VALS(avb_bool_vals), ADP_AVDECC_CONTROL_BITMASK, NULL, HFILL } 
        },
        { &hf_adp_entity_cap_legacy_avc,
            { "LEGACY_AVC", "ieee17221.entity_capabilities.legacy_avc", 
              FT_UINT32, BASE_DEC, VALS(avb_bool_vals), ADP_LEGACY_AVC_BITMASK, NULL, HFILL } 
        },
        { &hf_adp_entity_cap_assoc_id_support,
            { "ASSOCIATION_ID_SUPPORTED", "ieee17221.entity_capabilities.association_id_supported", 
              FT_UINT32, BASE_DEC, VALS(avb_bool_vals), ADP_ASSOC_ID_SUPPORT_BITMASK, NULL, HFILL } 
        },
        { &hf_adp_entity_cap_assoc_id_valid,
            { "ASSOCIATION_ID_VALID", "ieee17221.entity_capabilities.association_id_valid", 
              FT_UINT32, BASE_DEC, VALS(avb_bool_vals), ADP_ASSOC_ID_VALID_BITMASK, NULL, HFILL } 
        },
        /* Entity Capability Flags End */
        { &hf_adp_talker_stream_srcs,
            { "Talker Stream Sources", "ieee17221.talker_stream_sources", 
              FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL } 
        },
        { &hf_adp_talker_cap,
            { "Talker Capabilities", "ieee17221.talker_capabilities", 
              FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL } 
        },
        /* Talker Capability Flags Begin */
        { &hf_adp_talk_cap_implement,
            { "IMPLEMENTED", "ieee17221.talker_capabilities.implemented",
                FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_TALK_IMPLEMENTED_BITMASK, NULL, HFILL }
        },
        { &hf_adp_talk_cap_other_src,
            { "OTHER_SOURCE", "ieee17221.talker_capabilities.other_source",
                FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_TALK_OTHER_SRC_BITMASK, NULL, HFILL }
        },
        { &hf_adp_talk_cap_control_src,
            { "CONTROL_SOURCE", "ieee17221.talker_capabilities.control_source",
                FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_TALK_CONTROL_SRC_BITMASK, NULL, HFILL }
        },
        { &hf_adp_talk_cap_media_clk_src,
            { "MEDIA_CLOCK_SOURCE", "ieee17221.talker_capabilities.media_clock_source",
                FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_TALK_MEDIA_CLK_SRC_BITMASK, NULL, HFILL }
        },
        { &hf_adp_talk_cap_smpte_src,
            { "SMPTE_SOURCE", "ieee17221.talker_capabilities.smpte_source",
                FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_TALK_SMPTE_SRC_BITMASK, NULL, HFILL }
        },
        { &hf_adp_talk_cap_midi_src,
            { "MIDI_SOURCE", "ieee17221.talker_capabilities.midi_source",
                FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_TALK_MIDI_SRC_BITMASK, NULL, HFILL }
        },
        { &hf_adp_talk_cap_audio_src,
            { "AUDIO_SOURCE", "ieee17221.talker_capabilities.audio_source",
                FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_TALK_AUDIO_SRC_BITMASK, NULL, HFILL }
        },
        { &hf_adp_talk_cap_video_src,
            { "VIDEO_SOURCE", "ieee17221.talker_capabilities.video_source",
                FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_TALK_VIDEO_SRC_BITMASK, NULL, HFILL }
        },
        /* Talker Capability Flags End */
        { &hf_adp_listener_stream_sinks,
            { "Listener Stream Sinks", "ieee17221.listener_stream_sinks", 
              FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL } 
        },
        { &hf_adp_listener_cap,
            { "Listener Capabilities", "ieee17221.listener_capabilities", 
              FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL } 
        },
        /* Listener Capability Flags Begin */
        { &hf_adp_list_cap_implement,
            { "IMPLEMENTED", "ieee17221.listener_capabilities.implemented",
                FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_LIST_IMPLEMENTED_BITMASK, NULL, HFILL }
        },
        { &hf_adp_list_cap_other_sink,
            { "OTHER_SINK", "ieee17221.listener_capabilities.other_source",
                FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_LIST_OTHER_SINK_BITMASK, NULL, HFILL }
        },
        { &hf_adp_list_cap_control_sink,
            { "CONTROL_SINK", "ieee17221.listener_capabilities.control_source",
                FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_LIST_CONTROL_SINK_BITMASK, NULL, HFILL }
        },
        { &hf_adp_list_cap_media_clk_sink,
            { "MEDIA_CLOCK_SINK", "ieee17221.listener_capabilities.media_clock_source",
                FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_LIST_MEDIA_CLK_SINK_BITMASK, NULL, HFILL }
        },
        { &hf_adp_list_cap_smpte_sink,
            { "SMPTE_SINK", "ieee17221.listener_capabilities.smpte_source",
                FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_LIST_SMPTE_SINK_BITMASK, NULL, HFILL }
        },
        { &hf_adp_list_cap_midi_sink,
            { "MIDI_SINK", "ieee17221.listener_capabilities.midi_source",
                FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_LIST_MIDI_SINK_BITMASK, NULL, HFILL }
        },
        { &hf_adp_list_cap_audio_sink,
            { "AUDIO_SINK", "ieee17221.listener_capabilities.audio_source",
                FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_LIST_AUDIO_SINK_BITMASK, NULL, HFILL }
        },
        { &hf_adp_list_cap_video_sink,
            { "VIDEO_SINK", "ieee17221.listener_capabilities.video_source",
                FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_LIST_VIDEO_SINK_BITMASK, NULL, HFILL }
        },
        /* Listener Capability Flags End */
        { &hf_adp_controller_cap,
            { "Controller Capabilities", "ieee17221.controller_capabilities", 
              FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL } 
        },
        /* Controller Capability Flags Begin */
        { &hf_adp_cont_cap_implement,
            { "IMPLEMENTED", "ieee17221.controller_capabilities.implemented",
                FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_CONT_IMPLEMENTED_BITMASK, NULL, HFILL }
        },
        { &hf_adp_cont_cap_layer3_proxy,
            { "LAYER3_PROXY", "ieee17221.controller_capabilities.layer3_proxy",
                FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_CONT_LAYER3_PROXY_BITMASK, NULL, HFILL }
        },
        { &hf_adp_avail_index,
            { "Available Index", "ieee17221.available_index", 
              FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL } 
        },
        { &hf_adp_as_gm_id,
            { "AS Grandmaster ID", "ieee17221.as_grandmaster_id", 
              FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL } 
        },
        { &hf_adp_def_aud_format,
        { "Default Audio Format", "ieee17221.default_audio_format", 
              FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL } 
        },
        /* Default Audio Formats Fields Begin */
        { &hf_adp_def_aud_sample_rates,
        { "Sample Rates", "ieee17221.default_audio_format.sample_rates", 
              FT_UINT8, BASE_HEX, NULL, ADP_DEF_AUDIO_SAMPLE_RATES_MASK, NULL, HFILL } 
        },
        /* Sample rates Begin */
        { &hf_adp_samp_rate_44k1,
        { "44.1kHz", "ieee17221.default_audio_format.sample_rates.44k1", 
              FT_UINT8, BASE_DEC, VALS(avb_bool_vals), ADP_SAMP_RATE_44K1_BITMASK, NULL, HFILL } 
        },
        { &hf_adp_samp_rate_48k,
        { "48kHz", "ieee17221.default_audio_format.sample_rates.48k", 
              FT_UINT8, BASE_DEC, VALS(avb_bool_vals), ADP_SAMP_RATE_48K_BITMASK, NULL, HFILL } 
        },
        { &hf_adp_samp_rate_88k2,
        { "88.2kHz", "ieee17221.default_audio_format.sample_rates.88k2", 
              FT_UINT8, BASE_DEC, VALS(avb_bool_vals), ADP_SAMP_RATE_88K2_BITMASK, NULL, HFILL } 
        },
        { &hf_adp_samp_rate_96k,
        { "96kHz", "ieee17221.default_audio_format.sample_rates.96k", 
              FT_UINT8, BASE_DEC, VALS(avb_bool_vals), ADP_SAMP_RATE_96K_BITMASK, NULL, HFILL } 
        },
        { &hf_adp_samp_rate_176k4,
        { "176.4kHz", "ieee17221.default_audio_format.sample_rates.176k4", 
              FT_UINT8, BASE_DEC, VALS(avb_bool_vals), ADP_SAMP_RATE_176K4_BITMASK, NULL, HFILL } 
        },
        { &hf_adp_samp_rate_192k,
        { "192kHz", "ieee17221.default_audio_format.sample_rates.192k", 
              FT_UINT8, BASE_DEC, VALS(avb_bool_vals), ADP_SAMP_RATE_192K_BITMASK, NULL, HFILL } 
        },
        /* Sample rates End */
        { &hf_adp_def_aud_max_chan,
        { "Max Channels", "ieee17221.default_audio_format.max_channels", 
              FT_UINT16, BASE_DEC, NULL, ADP_DEF_AUDIO_MAX_CHANS_MASK, NULL, HFILL } 
        },
        { &hf_adp_def_aud_saf_flag,
        { "saf", "ieee17221.default_audio_format.saf", 
              FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_DEF_AUDIO_SAF_MASK, NULL, HFILL } 
        },
        { &hf_adp_def_aud_float_flag,
        { "float", "ieee17221.default_audio_format.float", 
              FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_DEF_AUDIO_FLOAT_MASK, NULL, HFILL } 
        },
        { &hf_adp_def_aud_chan_formats,
        { "Channel Formats", "ieee17221.default_audio_format.channel_formats", 
              FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL } 
        },
        /* Channel Formats Fields Start */
        { &hf_adp_chan_format_mono,
        { "MONO", "ieee17221.default_audio_format.channel_formats.mono", 
              FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_CHAN_FORMAT_MONO, NULL, HFILL } 
        },
        { &hf_adp_chan_format_2ch,
        { "2_CH", "ieee17221.default_audio_format.channel_formats.2_ch", 
              FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_CHAN_FORMAT_2CH, NULL, HFILL } 
        },
        { &hf_adp_chan_format_3ch,
        { "3_CH", "ieee17221.default_audio_format.channel_formats.3_ch", 
              FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_CHAN_FORMAT_3CH, NULL, HFILL } 
        },
        { &hf_adp_chan_format_4ch,
        { "4_CH", "ieee17221.default_audio_format.channel_formats.4_ch", 
              FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_CHAN_FORMAT_4CH, NULL, HFILL } 
        },
        { &hf_adp_chan_format_5ch,
        { "5_CH", "ieee17221.default_audio_format.channel_formats.5_ch", 
              FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_CHAN_FORMAT_5CH, NULL, HFILL } 
        },
        { &hf_adp_chan_format_6ch,
        { "6_CH", "ieee17221.default_audio_format.channel_formats.6_ch", 
              FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_CHAN_FORMAT_6CH, NULL, HFILL } 
        },
        { &hf_adp_chan_format_7ch,
        { "7_CH", "ieee17221.default_audio_format.channel_formats.7_ch", 
              FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_CHAN_FORMAT_7CH, NULL, HFILL } 
        },
        { &hf_adp_chan_format_8ch,
        { "8_CH", "ieee17221.default_audio_format.channel_formats.8_ch", 
              FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_CHAN_FORMAT_8CH, NULL, HFILL } 
        },
        { &hf_adp_chan_format_10ch,
        { "10_CH", "ieee17221.default_audio_format.channel_formats.10_ch", 
              FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_CHAN_FORMAT_10CH, NULL, HFILL } 
        },
        { &hf_adp_chan_format_12ch,
        { "12_CH", "ieee17221.default_audio_format.channel_formats.12_ch", 
              FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_CHAN_FORMAT_12CH, NULL, HFILL } 
        },
        { &hf_adp_chan_format_14ch,
        { "14_CH", "ieee17221.default_audio_format.channel_formats.14_ch", 
              FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_CHAN_FORMAT_14CH, NULL, HFILL } 
        },
        { &hf_adp_chan_format_16ch,
        { "16_CH", "ieee17221.default_audio_format.channel_formats.16_ch", 
              FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_CHAN_FORMAT_16CH, NULL, HFILL } 
        },
        { &hf_adp_chan_format_18ch,
        { "18_CH", "ieee17221.default_audio_format.channel_formats.18_ch", 
              FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_CHAN_FORMAT_18CH, NULL, HFILL } 
        },
        { &hf_adp_chan_format_20ch,
        { "20_CH", "ieee17221.default_audio_format.channel_formats.20_ch", 
              FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_CHAN_FORMAT_20CH, NULL, HFILL } 
        },
        { &hf_adp_chan_format_22ch,
        { "22_CH", "ieee17221.default_audio_format.channel_formats.22_ch", 
              FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_CHAN_FORMAT_22CH, NULL, HFILL } 
        },
        { &hf_adp_chan_format_24ch,
        { "24_CH", "ieee17221.default_audio_format.channel_formats.24_ch", 
              FT_UINT16, BASE_DEC, VALS(avb_bool_vals), ADP_CHAN_FORMAT_24CH, NULL, HFILL } 
        },
        /* Channel Formats Fields End */
        /* Default Audio Formats Fields End */
        { &hf_adp_def_vid_format,
        { "Default Video Format", "ieee17221.default_video_format", 
              FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL } 
        },
        { &hf_adp_assoc_id,
        { "Assocation ID", "ieee17221.assocation_id", 
              FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL } 
        },
        { &hf_adp_entity_type,
        { "Entity Type", "ieee17221.entity_type", 
              FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL } 
        },
        /*******************************************************************/
        { &hf_acmp_message_type,
            { "Message Type", "ieee17221.message_type", 
              FT_UINT8, BASE_DEC, VALS(acmp_message_type_vals), ACMP_MSG_TYPE_MASK, NULL, HFILL } 
        },
        { &hf_acmp_status_field,
            { "Status Field", "ieee17221.status_field", 
              FT_UINT8, BASE_DEC, VALS(acmp_status_field_vals), ACMP_STATUS_FIELD_MASK, NULL, HFILL } 
        },
        { &hf_acmp_cd_length,
            { "Control Data Length", "ieee17221.control_data_length", 
              FT_UINT16, BASE_DEC, NULL, ACMP_CD_LENGTH_MASK, NULL, HFILL } 
        },
        { &hf_acmp_stream_id,
            { "Stream ID", "ieee17221.stream_id", 
              FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL } 
        },
        { &hf_acmp_controller_guid,
            { "Controller GUID", "ieee17221.controller_guid", 
              FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL } 
        },
        { &hf_acmp_talker_guid,
            { "Talker GUID", "ieee17221.talker_guid", 
              FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL } 
        },
        { &hf_acmp_listener_guid,
            { "Listener GUID", "ieee17221.listener_guid", 
              FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL } 
        },
        { &hf_acmp_talker_unique_id,
            { "Talker Unique ID", "ieee17221.talker_unique_id", 
              FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL } 
        },
        { &hf_acmp_listener_unique_id,
            { "Listener Unique ID", "ieee17221.listener_unique_id", 
              FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL } 
        },
        { &hf_acmp_stream_dest_mac,
            { "Destination MAC address", "ieee17221.dest_mac", 
              FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL } 
        },
        { &hf_acmp_connection_count,
            { "Connection Count", "ieee17221.connection_count", 
              FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL } 
        },
        { &hf_acmp_sequence_id,
            { "Sequence ID", "ieee17221.sequence_id", 
              FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL } 
        },
        { &hf_acmp_flags,
            { "Flags", "ieee17221.flags", 
              FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL } 
        },
        /* ACMP Flags Begin */
        { &hf_acmp_flags_class_b,
        { "CLASS_B", "ieee17221.flags.class_b", 
              FT_UINT8, BASE_DEC, VALS(avb_bool_vals), ACMP_FLAG_CLASS_B_BITMASK, NULL, HFILL } 
        },
        { &hf_acmp_flags_fast_connect,
        { "FAST_CONNECT", "ieee17221.flags.fast_connect", 
              FT_UINT8, BASE_DEC, VALS(avb_bool_vals), ACMP_FLAG_FAST_CONNECT_BITMASK, NULL, HFILL } 
        },
        { &hf_acmp_flags_saved_state,
        { "SAVED_STATE", "ieee17221.flags.saved_state", 
              FT_UINT8, BASE_DEC, VALS(avb_bool_vals), ACMP_FLAG_SAVED_STATE_BITMASK, NULL, HFILL } 
        },
        { &hf_acmp_flags_streaming_wait,
        { "STREAMING_WAIT", "ieee17221.flags.streaming_wait", 
              FT_UINT8, BASE_DEC, VALS(avb_bool_vals), ACMP_FLAG_STREAMING_WAIT_BITMASK, NULL, HFILL } 
        },
        /* ACMP Flags End */
        { &hf_acmp_default_format,
            { "Default Format", "ieee17221.default_format", 
              FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL } 
        }
    };
    
    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_adp_ent_cap,
        &ett_adp_talk_cap,
        &ett_adp_list_cap,
        &ett_adp_cont_cap,
        &ett_adp_aud_format,
        &ett_adp_samp_rates,
        &ett_adp_chan_format,
        &ett_acmp_flags
    };

    /* Register the protocol name and description */
    proto_17221 = proto_register_protocol("IEEE 1722.1 Protocol", "IEEE1722.1", "ieee17221");
    
    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_17221, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_17221(void) 
{

    dissector_handle_t avb17221_handle;
    
    // avb17221_handle = find_dissector("ieee1722");

    avb17221_handle = create_dissector_handle(dissect_17221, proto_17221);
    dissector_add_uint("ieee1722.subtype", 0x7A, avb17221_handle);
    dissector_add_uint("ieee1722.subtype", 0x7B, avb17221_handle);
    dissector_add_uint("ieee1722.subtype", 0x7C, avb17221_handle);
}
