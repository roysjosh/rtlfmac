/******************************************************************************
 *
 * Portions Copyright(c) 2013 Joshua Roys
 * Portions Copyright(c) 2009-2012  Realtek Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110, USA
 *
 * The full GNU General Public License is included in this distribution in the
 * file called LICENSE.
 *
 *****************************************************************************/

#ifndef RTLFMAC_H
#define RTLFMAC_H

#include <linux/completion.h>
#include <linux/firmware.h>

#define REALTEK_USB_VENQT_READ		0xC0
#define REALTEK_USB_VENQT_WRITE		0x40
#define REALTEK_USB_VENQT_CMD_REQ	0x05
#define   REALTEK_USB_VENQT_CMD_IDX	0x00
#define MAX_USBCTRL_VENDORREQ_TIMES	10

#define RTL_NUM_RX_URBS			8
#define RTL_MAX_RX_SIZE			9100

#define RTL_RX_HEADER_SIZE		24
#define RTL_TX_HEADER_SIZE		32

enum rtlfmac_txq {
#if 0
	RTL_TXQ_BK,
	RTL_TXQ_BE,
	RTL_TXQ_VI,
	RTL_TXQ_VO,
#endif
	RTL_TXQ_VO,
	RTL_TXQ_VI,
	RTL_TXQ_BE,
	RTL_TXQ_BK,

	RTL_TXQ_BCN,
	RTL_TXQ_HI,
	RTL_TXQ_MGT,
	RTL_TXQ_H2CCMD,

	__RTL_TXQ_NUM,
};

struct rtlfmac_rx_desc {
	/* dword0 */
	u16 pkt_len:14;
	u8 crc32:1;
	u8 icv:1;
	u8 drvinfo_size:4;
	u8 security:3;
	u8 qos:1;
	u8 shift:2;
	u8 phy_status:1;
	u8 swdec:1;
	u8 last_seg:1;
	u8 first_seg:1;
	u8 eor:1;
	u8 own:1;

	/* dword1 */
	u8 macid:5;
	u8 tid:4;
	u8 reserved01_09:5;
	u8 paggr:1;
	u8 faggr:1;
	u8 a1_fit:4;
	u8 a2_fit:4;
	u8 pam:1;
	u8 pwr:1;
	u8 more_data:1;
	u8 more_frag:1;
	u8 type:2;
	u8 mc:1;
	u8 bc:1;

	/* dword2 */
	u16 seq:12;
	u8 frag:4;
	u8 next_pktlen;
	u8 reserved02_24:6;
	u8 next_ind:1;
	u8 reserved02_31:1;

	/* dword3 */
	u8 rx_mcs:6;
	u8 rx_ht:1;
	u8 amsdu:1;
	u8 splcp:1;
	u8 bw:1;
	u8 htc:1;
	u8 tcp_chk_rpt:1;
	u8 ip_chk_rpt:1;
	u8 tcp_chk_valid:1;
	u8 hwpc_err:1;
	u8 hwpc_ind:1;
	u16 iv0;

	/* dword4 */
	u32 iv1;

	/* dword5 */
	u32 tsfl;
} __packed;

struct rtlfmac_rx_c2h_desc {
	/* dword0 */
	u16 len;
	u8 evnum;
	u8 seqno:7;
	u8 frag:1;
} __packed;

struct rtlfmac_tx_desc {
	/* dword0 */
	u16 pkt_size;
	u8 offset;
	u8 type:2;
	u8 last_seg:1;
	u8 first_seg:1;
	u8 linip:1;
	u8 amsdu:1;
	u8 reserved00_30:1;
	u8 own:1;

	/* dword1 */
	u8 macid:5;
	u8 more_data:1;
	u8 more_frag:1;
	u8 pifs:1;
	u8 queue_sel:5;
	u8 ack_policy:2;
	u8 no_acm:1;
	u8 non_qos:1;
	u8 key_id:2;
	u8 oui:1;
	u8 pkt_type:1;
	u8 en_desc_id:1;
	u8 sec_type:2;
	u8 wds:1;
	u8 htc:1;
	u8 pkt_offset:5;
	u8 hwpc:1;

	/* dword2 */
	u8 data_retry_limit:6;
	u8 retry_limit_enable:1;
	u8 bmc:1;
	u8 reserved02_08:4;
	u8 rts_retry_count:6;
	u8 data_retry_count:6;
	u8 rsvd_macid:5;
	u8 agg_enable:1;
	u8 agg_break:1;
	u8 own_mac:1;

	/* dword3 */
	u8 next_heap_page;
	u8 tail_page;
	u16 seq:12;
	u8 frag:4;

	/* dword4 */
	u8 rts_rate:6;
	u8 disable_rts_fb:1;
	u8 rts_rate_fb_limit:4;
	u8 cts_enable:1;
	u8 rts_enable:1;
	u8 ra_brsr_id:3;
	u8 tx_ht:1;
	u8 tx_short:1;
	u8 tx_bandwidth:1;
	u8 tx_subcarrier:2;
	u8 tx_stbc:2;
	u8 tx_reverse_direction:1;
	u8 rts_ht:1;
	u8 rts_short:1;
	u8 rts_bandwidth:1;
	u8 rts_subcarrier:2;
	u8 rts_stbc:2;
	u8 user_rate:1;

	/* dword5 */
	u16 packet_id:9;
	u8 tx_rate:6;
	u8 disable_fb:1;
	u8 data_rate_fb_limit:5;
	u16 tx_agc:11;

	/* dword6 */
	u16 ip_check_sum;
	u16 tcp_check_sum;

	/* dword7 */
	u16 tx_buffer_size;
	u8 cmd_seq;
	u8 reserved07_24;
} __packed;

struct rtlfmac_tx_h2c_desc {
	/* dword0 */
	u16 len;
	u8 cmdid;
	u8 seqno:7;
	u8 more_cmds:1;
} __packed;

enum fw_c2h_event {
	C2H_READ_MACREG_EVENT,				/* 0 */
	C2H_READBB_EVENT,
	C2H_READRF_EVENT,
	C2H_READ_EEPROM_EVENT,
	C2H_READ_EFUSE_EVENT,
	C2H_READ_CAM_EVENT,				/* 5 */
	C2H_GET_BASIC_RATE_EVENT,
	C2H_GET_DATA_RATE_EVENT,
	C2H_SURVEY_EVENT,
	C2H_SURVEY_DONE_EVENT,
	C2H_JOIN_BSS_EVENT,				/* 10 */
	C2H_ADD_STA_EVENT,
	C2H_DEL_STA_EVENT,
	C2H_ATIM_DONE_EVENT,
	C2H_TX_REPORT_EVENT,
	C2H_CCX_REPORT_EVENT,				/* 15 */
	C2H_DTM_REPORT_EVENT,
	C2H_TX_RATE_STATS_EVENT,
	C2H_C2H_LBK_EVENT,
	C2H_FWDBG_EVENT,
	C2H_C2HFEEDBACK_EVENT,				/* 20 */
	C2H_ADDBA_EVENT,
	C2H_HBCN_EVENT,
	C2H_REPORT_PWR_STATE_EVENT,
	C2H_WPS_PBC_EVENT,
	C2H_ADDBA_REPORT_EVENT,				/* 25 */
};

enum fw_h2c_cmd {
	H2C_READ_MACREG_CMD,				/* 0 */
	H2C_WRITE_MACREG_CMD,
	H2C_READBB_CMD,
	H2C_WRITEBB_CMD,
	H2C_READRF_CMD,
	H2C_WRITERF_CMD,				/* 5 */
	H2C_READ_EEPROM_CMD,
	H2C_WRITE_EEPROM_CMD,
	H2C_READ_EFUSE_CMD,
	H2C_WRITE_EFUSE_CMD,
	H2C_READ_CAM_CMD,				/* 10 */
	H2C_WRITE_CAM_CMD,
	H2C_SETBCNITV_CMD,
	H2C_SETMBIDCFG_CMD,
	H2C_JOINBSS_CMD,
	H2C_DISCONNECT_CMD,				/* 15 */
	H2C_CREATEBSS_CMD,
	H2C_SETOPMODE_CMD,
	H2C_SITESURVEY_CMD,
	H2C_SETAUTH_CMD,
	H2C_SETKEY_CMD,					/* 20 */
	H2C_SETSTAKEY_CMD,
	H2C_SETASSOCSTA_CMD,
	H2C_DELASSOCSTA_CMD,
	H2C_SETSTAPWRSTATE_CMD,
	H2C_SETBASICRATE_CMD,				/* 25 */
	H2C_GETBASICRATE_CMD,
	H2C_SETDATARATE_CMD,
	H2C_GETDATARATE_CMD,
	H2C_SETPHYINFO_CMD,
	H2C_GETPHYINFO_CMD,				/* 30 */
	H2C_SETPHY_CMD,
	H2C_GETPHY_CMD,
	H2C_READRSSI_CMD,
	H2C_READGAIN_CMD,
	H2C_SETATIM_CMD,				/* 35 */
	H2C_SETPWRMODE_CMD,
	H2C_JOINBSSRPT_CMD,
	H2C_SETRATABLE_CMD,
	H2C_GETRATABLE_CMD,
	H2C_GETCCXREPORT_CMD,				/* 40 */
	H2C_GETDTMREPORT_CMD,
	H2C_GETTXRATESTATICS_CMD,
	H2C_SETUSBSUSPEND_CMD,
	H2C_SETH2CLBK_CMD,
	H2C_ADDBA_REQ_CMD,				/* 45 */
	H2C_SETCHANNEL_CMD,
	H2C_SET_TXPOWER_CMD,
	H2C_SWITCH_ANTENNA_CMD,
	H2C_SET_XTAL_CAP_CMD,
	H2C_SET_SINGLE_CARRIER_TX_CMD,			/* 50 */
	H2C_SET_SINGLE_TONE_CMD,
	H2C_SET_CARRIER_SUPPRESION_TX_CMD,
	H2C_SET_CONTINOUS_TX_CMD,
	H2C_SWITCH_BW_CMD,
	H2C_TX_BEACON_CMD,				/* 55 */
	H2C_SET_POWER_TRACKING_CMD,
	H2C_AMSDU_TO_AMPDU_CMD,
	H2C_SET_MAC_ADDRESS_CMD,
	H2C_DISCONNECT_CTRL_CMD,
	H2C_SET_CHANNELPLAN_CMD,			/* 60 */
	H2C_DISCONNECT_CTRL_EX_CMD,
	H2C_GET_H2C_LBK_CMD,
	H2C_SET_PROBE_REQ_EXTRA_IE_CMD,
	H2C_SET_ASSOC_REQ_EXTRA_IE_CMD,
	H2C_SET_PROBE_RSP_EXTRA_IE_CMD,			/* 65 */
	H2C_SET_ASSOC_RSP_EXTRA_IE_CMD,
	H2C_GET_CURRENT_DATA_RATE_CMD,
	H2C_GET_TX_RETRY_CNT_CMD,
	H2C_GET_RX_RETRY_CNT_CMD,
	H2C_GET_BCN_OK_CNT_CMD,				/* 70 */
	H2C_GET_BCN_ERR_CNT_CMD,
	H2C_GET_CURRENT_TXPOWER_CMD,
	H2C_SET_DIG_CMD,
	H2C_SET_RA_CMD,
	H2C_SET_PT_CMD,					/* 75 */
	H2C_READ_RSSI_CMD,
	MAX_H2CCMD,					/* 77 */
};

struct rtlfmac_sitesurvey_cmd {
	u32 active;
	u32 bsslimit;
	u32 ssidlen;
	u8 ssid[IEEE80211_MAX_SSID_LEN + 1];
} __packed;

enum {
	IW_AUTHMODE_OPEN,
	IW_AUTHMODE_SHARED,
	IW_AUTHMODE_WPA,
};

struct rtlfmac_setauth_cmd {
	u8 mode;
	u8 _1x;
	u8 reserved2;
	u8 reserved3;
} __packed;

struct ndis_802_11_ssid {
	u32 ssidlen;
	u8 ssid[IEEE80211_MAX_SSID_LEN];
};

struct ndis_802_11_configuration_fh {
	u32 len;
	u32 hoppattern;
	u32 hopset;
	u32 dwelltime;
};

struct ndis_802_11_configuration {
	u32 len;
	u32 beaconperiod;
	u32 atimwindow;
	u32 dsconfig;
	struct ndis_802_11_configuration_fh fhconfig;
};

struct ndis_wlan_bssid_ex {
	u32 len;
	u8 macaddr[ETH_ALEN];
	u8 reserved10[2];
	struct ndis_802_11_ssid ssid;
	u32 privacy;
	s32 rssi;
	u32 networktype;
	struct ndis_802_11_configuration config;
	u32 inframode;
	u8 supportedrates[16];
	u32 ielen;
	u8 ies[0];
};

struct ndis_802_11_fixed_ies {
	u8 timestamp[8];
	u16 beaconint;
	u16 caps;
};

struct rtlfmac_joinbss_cmd {
	struct ndis_wlan_bssid_ex network;
};

/* event structures */

struct wlan_network {
#if 0
	/* we don't use this, so avoid 32/64-bit issues */
	struct list_head list;
#else
	u32 next, prev;
#endif
	int network_type;
	int fixed;
	unsigned int last_scanned;
	int aid;
	int join_res; /* -1: auth fail, -2: assoc fail, >0: TID */
	struct ndis_wlan_bssid_ex network;
} __packed;

/* firmware structures */

struct rtlfmac_fw_hdr {
	u16 signature;
	u16 version;

	u32 dmem_size;
	u32 img_imem_size;
	u32 img_sram_size;
	u32 fw_priv_size;

	u32 reserved20;
	u32 reserved24;
	u32 reserved28;
} __packed;

struct rtlfmac_fw_priv {
	u16 signature;
	u8 hci_sel;
	u8 chip_version;
	u16 customer_id;
	u8 rf_config;
	u8 usb_ep_num;

	u32 regulatory_class;
	u8 rfintfs;
	u8 def_nettype;
	u8 turbo_mode;
	u8 low_power_mode;

	u8 lbk_mode;
	u8 mp_mode;
	u8 vcs_type;
	u8 vcs_mode;
	u8 reserved20;
	u8 reserved21;
	u8 reserved22;
	u8 reserved23;

	u8 qos_en;
	u8 bw_40mhz_en;
	u8 amsdu2ampdu_en;
	u8 ampdu_en;
	u8 rate_control_offload;
	u8 aggregation_offload;
	u8 reserved30;
	u8 reserved31;

	u8 beacon_offload;
	u8 mlme_offload;
	u8 hwpc_offload;
	u8 tcp_checksum_offload;
	u8 tcp_offload;
	u8 ps_control_offload;
	u8 wwlan_offload;
	u8 reserved39;

	u16 tcp_tx_frame_len;
	u16 tcp_rx_frame_len;
	u8 reserved44;
	u8 reserved45;
	u8 reserved46;
	u8 reserved47;
} __packed;

/* driver private structures */

struct rtlfmac_cfg80211_priv {
	struct usb_device *usbdev;
	struct device *dev;

	struct net_device *ndev;
	struct wiphy *wiphy;
	struct wireless_dev *wdev;

	/* cfg80211 */
	struct cfg80211_scan_request *scan_request;

	u8 num_endpoints;
	u32 in_ep_num;
	u32 ep_mapping[__RTL_TXQ_NUM];
	u8 hwrev;

	u8 h2c_cmd_seqno:7;

	struct usb_anchor rx_cleanup;
	struct usb_anchor rx_submitted;

	struct completion fw_ready;

	struct tasklet_struct rx_work_tasklet;
	struct sk_buff_head rx_queue;
};

static inline struct rtlfmac_cfg80211_priv *wiphy_to_cfg(struct wiphy *w)
{
	return (struct rtlfmac_cfg80211_priv *)(wiphy_priv(w));
}

/* System Configuration Registers */
#define REG_SYS_ISO_CTRL			0x0000
#define   ISO_MD2PP				BIT(0)
#define   ISO_PLL2MD				BIT(4)
#define   ISO_PWC_DV2RP				BIT(11)
#define REG_SYS_FUNC_EN				0x0002
#define   FEN_CPUEN				BIT(10)
#define   FEN_DCORE				BIT(11)
#define   PWC_DV2LDR				BIT(13)
#define   FEN_MREGEN				BIT(15)
#define REG_PMC_FSM				0x0004
#define REG_SYS_CLKR				0x0008
#define   SYS_CLKSEL_80M			BIT(0)
#define   SYS_CPU_CLKSEL			BIT(2)
#define   SYS_MAC_CLK_EN			BIT(11)
#define   SYS_SYS_CLK_EN			BIT(12)
#define   SWHW_SEL				BIT(14)
#define   FWHW_SEL				BIT(15)
#define REG_EPROM_CMD				0x000A
#define   EPROM_SEL				BIT(4)
#define   EPROM_EN				BIT(5)
#define REG_AFE_MISC				0x0010
#define   AFE_MISC_BGEN				BIT(0)
#define   AFE_MISC_MBEN				BIT(1)
#define   AFE_MISC_I32_EN			BIT(3)
#define REG_SPS0_CTRL				0x0011
#define REG_SPS1_CTRL				0x0018
#define REG_LDOA15_CTRL				0x0020
#define   LDA15_EN				BIT(0)
#define REG_LDOV12D_CTRL			0x0021
#define   LDV12_EN				BIT(0)
#define REG_AFE_XTAL_CTRL			0x0026
#define   XTAL_GATE_AFE				BIT(10)
#define REG_AFE_PLL_CTRL			0x0028
#define   APLL_EN				BIT(0)
#define REG_EFUSE_CTRL				0x0030
#define REG_EFUSE_TEST				0x0034
#define   LDOE25_EN				BIT(31)

/* Command Control Registers */
#define REG_CR					0x0040
#define   HCI_TXDMA_EN				BIT(2)
#define   HCI_RXDMA_EN				BIT(3)
#define   TXDMA_EN				BIT(4)
#define   RXDMA_EN				BIT(5)
#define   FW2HW_EN				BIT(6)
#define   DDMA_EN				BIT(7)
#define   MACTXEN				BIT(8)
#define   MACRXEN				BIT(9)
#define   SCHEDULE_EN				BIT(10)
#define   BB_GLB_RSTn				BIT(12)
#define   BBRSTn				BIT(13)
#define REG_TXPAUSE				0x0042
#define REG_LBKMD_SEL				0x0043
#define REG_TCR					0x0044
#define   IMEM_CODE_DONE			BIT(0)
#define   IMEM_CHK_RPT				BIT(1)
#define   EMEM_CODE_DONE			BIT(2)
#define   EMEM_CHK_RPT				BIT(3)
#define   DMEM_CODE_DONE			BIT(4)
#define   IMEM_RDY				BIT(5)
#define   BASECHG				BIT(6)
#define   FWRDY					BIT(7)
#define REG_RCR					0x0048
#define   APP_PHYST_RXFF			BIT(25)
#define   RX_TCPOFDL_EN				BIT(26)

#define LBK_NORMAL				0x00
#define TXDMA_INIT_VALUE			(IMEM_CHK_RPT | EMEM_CHK_RPT)

/* MACID Setting Registers */
#define REG_MACIDR0				0x0050
#define REG_MACIDR4				0x0054

/* FIFO Control Registers */
#define REG_PBP					0x00B5
#define   PBP_PAGE_128B				BIT(0)
#define   PBP_PAGE_256B				BIT(1)
#define   PBP_PAGE_512B				BIT(2)
#define   PBP_PAGE_1024B			BIT(3)
#define   PBP_PAGE_2048B			BIT(4)
#define REG_RXDMA_RXCTRL			0x00BD
#define   RXDMA_AGG_EN				BIT(7)
#define REG_RXDMA_AGG_PG_TH			0x00D9

/* USB Configuration Registers */
#define REG_USB_HRPWM				0xFE58
#define REG_USB_DMA_AGG_TO			0xFE5B
#define REG_USB_AGG_TO				0xFE5C
#define REG_USB_MAC_ADDR			0xFE70

#endif
