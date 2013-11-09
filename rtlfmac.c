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

#include <linux/etherdevice.h>
#include <linux/ieee80211.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/usb.h>
#include <net/cfg80211.h>

#include "rtlfmac.h"

/* USB communication functions */
static int _usbctrl_vendorreq_sync_read(struct usb_device *udev, u8 request,
					u16 value, u16 index, void *pdata,
					u16 len)
{
	unsigned int pipe;
	int status;
	u8 reqtype;
	int vendorreq_times = 0;
	static int count;

	pipe = usb_rcvctrlpipe(udev, 0); /* read_in */
	reqtype = REALTEK_USB_VENQT_READ;

	do {
		status = usb_control_msg(udev, pipe, request, reqtype, value,
					 index, pdata, len, 0); /*max. timeout*/
	} while (status < 0 && ++vendorreq_times < MAX_USBCTRL_VENDORREQ_TIMES);

	if (status < 0 && count++ < 4)
		pr_err("reg 0x%x, usbctrl_vendorreq TimeOut! status:0x%x value=0x%x\n",
		       value, status, le32_to_cpu(*(u32 *)pdata));
	return status;
}

static int _usbctrl_vendorreq_sync_write(struct usb_device *udev, u8 request,
					u16 value, u16 index, void *pdata,
					u16 len)
{
	unsigned int pipe;
	int status;
	u8 reqtype;
	int vendorreq_times = 0;
	static int count;

	pipe = usb_sndctrlpipe(udev, 0); /* write_out */
	reqtype = REALTEK_USB_VENQT_WRITE;

	do {
		status = usb_control_msg(udev, pipe, request, reqtype, value,
					 index, pdata, len, 0); /*max. timeout*/
	} while (status < 0 && ++vendorreq_times < MAX_USBCTRL_VENDORREQ_TIMES);

	if (status < 0 && count++ < 4)
		pr_err("reg 0x%x, usbctrl_vendorreq TimeOut! status:0x%x value=0x%x\n",
		       value, status, le32_to_cpu(*(u32 *)pdata));
	return status;
}

static u32 _usb_read_sync(struct usb_device *udev, u32 addr, u16 len)
{
	u8 request;
	u16 wvalue;
	u16 index;
	u32 *data;
	u32 ret;

	data = kmalloc(sizeof(u32), GFP_KERNEL);
	if (!data)
		return -ENOMEM;
	request = REALTEK_USB_VENQT_CMD_REQ;
	index = REALTEK_USB_VENQT_CMD_IDX;

	wvalue = (u16)addr;
	_usbctrl_vendorreq_sync_read(udev, request, wvalue, index, data, len);
	ret = le32_to_cpu(*data);
	kfree(data);
	return ret;
}

static int _usb_write_sync(struct usb_device *udev, u32 addr, u32 val, u16 len)
{
	u8 request;
	u16 wvalue;
	u16 index;
	u32 *data;
	int ret;

	data = kmalloc(sizeof(u32), GFP_KERNEL);
	if (!data)
		return -ENOMEM;
	request = REALTEK_USB_VENQT_CMD_REQ;
	index = REALTEK_USB_VENQT_CMD_IDX;

	wvalue = (u16)addr;
	*data = val;
	ret = _usbctrl_vendorreq_sync_write(udev, request, wvalue, index, data, len);
	kfree(data);
	return ret;
}

static void _usb_write_bulk_complete(struct urb *_urb)
{
	struct sk_buff *skb = (struct sk_buff *)_urb->context;
	dev_kfree_skb_irq(skb);
}

static int _usb_write_bulk(struct usb_device *udev, struct sk_buff *skb, u32 ep_num)
{
	int ret;
	struct urb *_urb;

	_urb = usb_alloc_urb(0, GFP_ATOMIC);
	if (!_urb) {
		pr_err("%s: failed to allocate URB\n", __func__);
		dev_kfree_skb(skb);
		return -ENOMEM;
	}

	usb_fill_bulk_urb(_urb, udev, usb_sndbulkpipe(udev, ep_num), skb->data, skb->len,
			_usb_write_bulk_complete, skb);
	_urb->transfer_flags |= URB_ZERO_PACKET;

	//usb_anchor_urb(_urb, ...); FIXME

	ret = usb_submit_urb(_urb, GFP_ATOMIC);
	if (ret < 0) {
		//usb_unanchor_urb(_urb);
		dev_kfree_skb(skb);
	}
	usb_free_urb(_urb);

	return ret;
}

static u8 rtlfmac_read_byte(struct rtlfmac_cfg80211_priv *priv, u32 addr)
{
	return _usb_read_sync(priv->usbdev, addr, 1);
}

static u16 rtlfmac_read_word(struct rtlfmac_cfg80211_priv *priv, u32 addr)
{
	return _usb_read_sync(priv->usbdev, addr, 2);
}

static u32 rtlfmac_read_dword(struct rtlfmac_cfg80211_priv *priv, u32 addr)
{
	return _usb_read_sync(priv->usbdev, addr, 4);
}

static int rtlfmac_write_byte(struct rtlfmac_cfg80211_priv *priv, u32 addr, u8 val)
{
	return _usb_write_sync(priv->usbdev, addr, (u32)val, 1);
}

static int rtlfmac_write_word(struct rtlfmac_cfg80211_priv *priv, u32 addr, u16 val)
{
	val = cpu_to_le16(val);
	return _usb_write_sync(priv->usbdev, addr, (u32)val, 2);
}

static int rtlfmac_write_dword(struct rtlfmac_cfg80211_priv *priv, u32 addr, u32 val)
{
	val = cpu_to_le32(val);
	return _usb_write_sync(priv->usbdev, addr, val, 4);
}

static int rtlfmac_write_skb(struct rtlfmac_cfg80211_priv *priv, struct sk_buff *skb)
{
	u32 ep_num = priv->ep_mapping[skb_get_queue_mapping(skb)];
	return _usb_write_bulk(priv->usbdev, skb, ep_num);
}

/* USB RX functions */
static void rtlfmac_rx_cleanup(struct rtlfmac_cfg80211_priv *priv)
{
	struct urb *urb;

	usb_kill_anchored_urbs(&priv->rx_submitted);

	tasklet_kill(&priv->rx_work_tasklet);
	skb_queue_purge(&priv->rx_queue);

	while ((urb = usb_get_from_anchor(&priv->rx_cleanup))) {
		usb_free_coherent(priv->usbdev, urb->transfer_buffer_length,
				urb->transfer_buffer, urb->transfer_dma);
		usb_free_urb(urb);
	}
}

static void rtlfmac_rx_survey_resp(struct rtlfmac_cfg80211_priv *priv, u8 *data)
{
	int freq;
	size_t ie_len;
	struct cfg80211_bss *bss;
	struct ieee80211_channel *chan;
	struct ndis_802_11_fixed_ies *fixed;
	struct ndis_wlan_bssid_ex *survey = (struct ndis_wlan_bssid_ex *)data;
	s32 signal;
	u8 *ie;
	u16 caps, beaconint;
	u32 bssid_len;
	u64 tsf;

	netdev_dbg(priv->ndev, "%s: found BSS %s/%pM, channel %i\n", __func__, survey->ssid.ssid,
			survey->macaddr, survey->config.dsconfig);

	bssid_len = le32_to_cpu(survey->len);
	if (bssid_len < sizeof(struct ndis_wlan_bssid_ex) +
			sizeof(struct ndis_802_11_fixed_ies))
		return;

	fixed = (struct ndis_802_11_fixed_ies *)survey->ies;

	if (sizeof(struct ndis_802_11_fixed_ies) > survey->ielen) {
		ie = NULL;
		ie_len = 0;
	} else {
		ie = survey->ies + sizeof(struct ndis_802_11_fixed_ies);
		ie_len = survey->ielen - sizeof(struct ndis_802_11_fixed_ies);
	}

	freq = ieee80211_channel_to_frequency(survey->config.dsconfig,
			IEEE80211_BAND_2GHZ);
	chan = ieee80211_get_channel(priv->wiphy, freq);

	//signal = DBM_TO_MBM(rtl92s_signal_scale_mapping(le32_to_cpu(survey->rssi)));
	signal = 0;
	tsf = le64_to_cpu(*(__le64 *)fixed->timestamp);
	caps = le16_to_cpu(fixed->caps);
	beaconint = le16_to_cpu(fixed->beaconint);

	bss = cfg80211_inform_bss(priv->wiphy, chan, survey->macaddr, tsf, caps,
			beaconint, ie, ie_len, signal, GFP_ATOMIC);
	cfg80211_put_bss(priv->wiphy, bss);
}

static void rtlfmac_rx_join_resp(struct rtlfmac_cfg80211_priv *priv, u8 *data)
{
	struct wlan_network *res = (struct wlan_network *)data;
	u16 status;

	if (!priv->connecting) {
		return;
	}
	priv->connecting = false;

	netdev_dbg(priv->ndev, "%s: aid(%d) join_res(%i)\n", __func__, res->aid, res->join_res);

	switch(res->join_res) {
	case -2:
		status = WLAN_STATUS_ASSOC_DENIED_UNSPEC;
		break;
	case -1:
		status = WLAN_STATUS_UNKNOWN_AUTH_TRANSACTION;
		break;
	default:
		status = WLAN_STATUS_SUCCESS;
		break;
	}

	cfg80211_connect_result(priv->ndev, res->network.macaddr, NULL, 0,
			res->network.ies, res->network.ielen, status, GFP_ATOMIC);

	if (WLAN_STATUS_SUCCESS == status) {
		memcpy(priv->bssid, res->network.macaddr, ETH_ALEN);
		netif_carrier_on(priv->ndev);
	}
}

/* Unfortunately, ieee80211_data_to_8023 doesn't handle the IV junk bytes
 * between the 802.11 header and the SNAP header.  Thus, our own function.
 */
static int rtlfmac_data_to_8023(struct sk_buff *skb, const uint8_t *addr, enum nl80211_iftype iftype, int iv_len)
{
	int hdrlen;
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;

	hdrlen = ieee80211_hdrlen(hdr->frame_control);

	if (ieee80211_has_protected(hdr->frame_control)) {
		memmove(skb->data + iv_len, skb->data, hdrlen);
		skb_pull(skb, iv_len);
	}

	return ieee80211_data_to_8023(skb, addr, iftype);
}

static void rtlfmac_rx_process(struct rtlfmac_cfg80211_priv *priv, struct sk_buff *skb)
{
	struct rtlfmac_rx_desc *pdesc;

	pdesc = (struct rtlfmac_rx_desc *)skb->data;
	skb_pull(skb, RTL_RX_HEADER_SIZE);

	if (pdesc->macid == 0x1f && pdesc->tid == 0x0f) {
		/* C2H event */
		u8 evnum;
		u16 evlen;
		struct rtlfmac_rx_c2h_desc *c2h;

		c2h = (struct rtlfmac_rx_c2h_desc *)skb->data;
		skb_pull(skb, 8); /* 8 byte alignment */

		evnum = c2h->evnum;
		evlen = le16_to_cpu(c2h->len);

		switch(evnum) {
		case C2H_SURVEY_EVENT:
			rtlfmac_rx_survey_resp(priv, skb->data);
			break;
		case C2H_SURVEY_DONE_EVENT:
			cfg80211_scan_done(priv->scan_request, false);
			priv->scan_request = NULL;
			break;
		case C2H_JOIN_BSS_EVENT:
			rtlfmac_rx_join_resp(priv, skb->data);
			break;
		case C2H_DEL_STA_EVENT:
			cfg80211_disconnected(priv->ndev, 0, NULL, 0, GFP_ATOMIC);
			break;
		case C2H_FWDBG_EVENT:
			netdev_dbg(priv->ndev, "%s: fwdbg: %s%s", __func__, skb->data,
					(skb->data[evlen - 2] == '\n' ? "" : "\n"));
			break;
		default:
			netdev_warn(priv->ndev, "%s: unhandled C2H %i\n", __func__, evnum);
			break;
		}

		dev_kfree_skb_any(skb);

		return;
	}

	// remove PHY status
	skb_pull(skb, pdesc->drvinfo_size * 8);

	// convert 802.11 frame to 802.3 frame
	if (rtlfmac_data_to_8023(skb, priv->ndev->perm_addr, priv->wdev->iftype, priv->iv_len)) {
		netdev_err(priv->ndev, "%s: failed to convert 802.11 to 802.3\n", __func__);
		dev_kfree_skb_any(skb);
		return;
	}

	skb->dev = priv->ndev;
	skb->protocol = eth_type_trans(skb, skb->dev);
	netif_rx(skb);
}

static void rtlfmac_rx_tasklet(unsigned long param)
{
	struct rtlfmac_cfg80211_priv *priv = (struct rtlfmac_cfg80211_priv *)param;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&priv->rx_queue))) {
		rtlfmac_rx_process(priv, skb);
	}
}

static void rtlfmac_rx_complete(struct urb *urb)
{
	int err;
	struct rtlfmac_cfg80211_priv *priv = (struct rtlfmac_cfg80211_priv *)urb->context;

	if (likely(0 == urb->status)) {
		struct sk_buff *skb;
		unsigned int size = urb->actual_length;

		/* FIXME check size */

		skb = dev_alloc_skb(size + 32); /* for radiotap */
		if (!skb) {
			pr_err("%s: failed to allocate skb\n", __func__);
			goto resubmit;
		}
		skb_reserve(skb, 32); /* for radiotap */
		memcpy(skb_put(skb, size), urb->transfer_buffer, size);

		skb_queue_tail(&priv->rx_queue, skb);
		tasklet_schedule(&priv->rx_work_tasklet);

		goto resubmit;
	}

	switch(urb->status) {
	/* disconnect */
	case -ENOENT:
	case -ECONNRESET:
	case -ENODEV:
	case -ESHUTDOWN:
		goto free;
	default:
		break;
	}

resubmit:
	usb_anchor_urb(urb, &priv->rx_submitted);
	err = usb_submit_urb(urb, GFP_ATOMIC);
	if (unlikely(err)) {
		pr_err("%s: failed to submit URB\n", __func__);
		usb_unanchor_urb(urb);
		goto free;
	}

	return;

free:
	/* On some architectures, usb_free_coherent must not be called from
	 * hardirq context. Queue urb to cleanup list.
	 */
	usb_anchor_urb(urb, &priv->rx_cleanup);
}

static int rtlfmac_rx_start(struct rtlfmac_cfg80211_priv *priv)
{
	int i, ret = 0;
	struct urb *urb;
	void *buf;

	priv->connecting = false;
	priv->ieee8021x_blocked = false;

	init_usb_anchor(&priv->rx_cleanup);
	init_usb_anchor(&priv->rx_submitted);

	skb_queue_head_init(&priv->rx_queue);
	priv->rx_work_tasklet.func = rtlfmac_rx_tasklet;
	priv->rx_work_tasklet.data = (unsigned long)priv;

	for(i = 0; i < RTL_NUM_RX_URBS; i++) {
		urb = usb_alloc_urb(0, GFP_KERNEL);
		if (!urb) {
			pr_err("%s: failed to allocate URB\n", __func__);
			ret = -ENOMEM;
			break;
		}

		buf = usb_alloc_coherent(priv->usbdev, RTL_MAX_RX_SIZE, GFP_KERNEL,
				&urb->transfer_dma);
		if (!buf) {
			pr_err("%s: failed to allocate USB coherent buffer\n", __func__);
			usb_free_urb(urb);
			ret = -ENOMEM;
			break;
		}

		usb_fill_bulk_urb(urb, priv->usbdev, usb_rcvbulkpipe(priv->usbdev, priv->in_ep_num),
				buf, RTL_MAX_RX_SIZE, rtlfmac_rx_complete, priv);
		urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;

		usb_anchor_urb(urb, &priv->rx_submitted);
		ret = usb_submit_urb(urb, GFP_KERNEL);
		if (unlikely(ret)) {
			pr_err("%s: failed to submit URB\n", __func__);
			usb_unanchor_urb(urb);
			usb_free_coherent(priv->usbdev, RTL_MAX_RX_SIZE, buf,
					urb->transfer_dma);
			usb_free_urb(urb);
			break;
		}
		usb_free_urb(urb);
	}

	if (unlikely(ret)) {
		rtlfmac_rx_cleanup(priv);
	}

	return ret;
}

/* rtlfmac functions */
int rtlfmac_fw_cmd(struct rtlfmac_cfg80211_priv *priv, uint8_t code, void *buf, int len)
{
	u8 *ptr;
	struct rtlfmac_tx_desc *pdesc;
	struct rtlfmac_tx_h2c_desc *h2c;
	struct sk_buff *skb;

	skb = dev_alloc_skb(len + RTL_TX_HEADER_SIZE + 8);
	if (!skb) {
		return -ENOMEM;
	}
	skb_reserve(skb, RTL_TX_HEADER_SIZE + 8);
	ptr = skb_put(skb, len);
	memcpy(ptr, buf, len);

	h2c = (struct rtlfmac_tx_h2c_desc *)skb_push(skb, 8);
	memset(h2c, 0, 8);
	h2c->len = cpu_to_le16(len);
	h2c->cmdid = code;
	h2c->seqno = priv->h2c_cmd_seqno++;

	pdesc = (struct rtlfmac_tx_desc *)skb_push(skb, RTL_TX_HEADER_SIZE);
	memset(pdesc, 0, RTL_TX_HEADER_SIZE);
	pdesc->first_seg = pdesc->last_seg = 1;
	pdesc->offset = RTL_TX_HEADER_SIZE;
	pdesc->pkt_size = cpu_to_le32(len + 8);
	pdesc->queue_sel = 0x13;
	pdesc->own = 1;

	skb->queue_mapping = RTL_TXQ_H2CCMD;
	return rtlfmac_write_skb(priv, skb);
}

int rtlfmac_sitesurvey(struct rtlfmac_cfg80211_priv *priv, struct cfg80211_scan_request *req)
{
	struct rtlfmac_sitesurvey_cmd cmd;

	priv->scan_request = req;

	memset(&cmd, 0, sizeof(cmd));
	cmd.bsslimit = cpu_to_le32(48);
	if (req->n_ssids) {
		cmd.active = cpu_to_le32(1);
		cmd.ssidlen = cpu_to_le32(req->ssids[0].ssid_len);
		memcpy(cmd.ssid, req->ssids[0].ssid, req->ssids[0].ssid_len);
	}

	return rtlfmac_fw_cmd(priv, H2C_SITESURVEY_CMD, &cmd, sizeof(cmd));
}

int rtlfmac_connect(struct rtlfmac_cfg80211_priv *priv, struct net_device *ndev,
		struct cfg80211_connect_params *sme)
{
	int chan = -1, ret;
	size_t ie_len;
	u8 *ie_ptr;
	struct cfg80211_bss *bss;
	struct ieee80211_channel *channel = sme->channel;
	struct ieee80211_ht_cap *ht_cap;
	struct ndis_802_11_fixed_ies *fixed;
	struct rtlfmac_joinbss_cmd *cmd;
	struct rtlfmac_setauth_cmd *authcmd;
	struct rtlfmac_setopmode_cmd *modecmd;

	bss = cfg80211_get_bss(priv->wiphy, channel, sme->bssid, sme->ssid,
			sme->ssid_len, WLAN_CAPABILITY_ESS, WLAN_CAPABILITY_ESS);
	if (!bss) {
		netdev_err(ndev, "%s: Unable to find BSS\n", __func__);
		return -ENOENT;
	}

	if (!channel) {
		channel = bss->channel;
	}
	if (channel) {
		chan = ieee80211_frequency_to_channel(channel->center_freq);
	}

	netdev_dbg(ndev, "%s: '%.*s':[%pM]:%d:[%d,0x%x:0x%x]\n", __func__,
			(int)sme->ssid_len, sme->ssid, bss->bssid, chan, sme->privacy,
			sme->crypto.wpa_versions, sme->auth_type);

	// set_opmode
	modecmd = kzalloc(sizeof(struct rtlfmac_setopmode_cmd), GFP_KERNEL);
	if (!modecmd) {
		ret = -ENOMEM;
		goto done;
	}

	modecmd->opmode = IW_MODE_INFRA;

	ret = rtlfmac_fw_cmd(priv, H2C_SETOPMODE_CMD, modecmd, sizeof(*modecmd));
	kfree(modecmd);
	if (ret) {
		goto done;
	}

	// set_auth
	authcmd = kzalloc(sizeof(struct rtlfmac_setauth_cmd), GFP_KERNEL);
	if (!authcmd) {
		ret = -ENOMEM;
		goto done;
	}

	if (sme->crypto.wpa_versions) {
		authcmd->mode = IW_AUTHMODE_WPA;
		priv->ieee8021x_blocked = true;
	} else if (sme->auth_type == NL80211_AUTHTYPE_SHARED_KEY) {
		authcmd->mode = IW_AUTHMODE_SHARED;
	} else if (sme->auth_type == NL80211_AUTHTYPE_OPEN_SYSTEM) {
		authcmd->mode = IW_AUTHMODE_OPEN;
	} else { // default to open
		authcmd->mode = IW_AUTHMODE_OPEN;
	}

	priv->cipher_pairwise = sme->crypto.ciphers_pairwise[0];
	switch (sme->crypto.ciphers_pairwise[0]) {
	case 0:
		priv->iv_len = 0;
		break;
	case WLAN_CIPHER_SUITE_CCMP:
		priv->iv_len = 8;
		break;
	}

	priv->cipher_group = sme->crypto.cipher_group;

	ret = rtlfmac_fw_cmd(priv, H2C_SETAUTH_CMD, authcmd, sizeof(*authcmd));
	kfree(authcmd);
	if (ret) {
		goto done;
	}

	// joinbss
	ie_len = sizeof(struct ndis_802_11_fixed_ies) + sme->ie_len;
	if (1) {
		ie_len += (2 + sizeof(struct ieee80211_ht_cap));
	}

	cmd = kzalloc(sizeof(struct rtlfmac_joinbss_cmd) + ie_len, GFP_KERNEL);
	if (!cmd) {
		ret = -ENOMEM;
		goto done;
	}

	cmd->network.len = cpu_to_le32(sizeof(struct ndis_wlan_bssid_ex) + ie_len);
	memcpy(cmd->network.macaddr, bss->bssid, ETH_ALEN);
	cmd->network.ssid.ssidlen = cpu_to_le32(sme->ssid_len);
	memcpy(cmd->network.ssid.ssid, sme->ssid, sme->ssid_len);
	cmd->network.privacy = cpu_to_le32(sme->privacy);
	cmd->network.networktype = cpu_to_le32(3); // Ndis802_11OFDM24
	cmd->network.config.len = sizeof(cmd->network.config);
	cmd->network.config.beaconperiod = cpu_to_le32(bss->beacon_interval);
	cmd->network.config.dsconfig = cpu_to_le32(chan);
	cmd->network.inframode = cpu_to_le32(1); // ???
	cmd->network.ielen = cpu_to_le32(ie_len);
	cmd->network.supportedrates[0] = 0x82;
	cmd->network.supportedrates[1] = 0x84;
	cmd->network.supportedrates[2] = 0x8b;
	cmd->network.supportedrates[3] = 0x96;
	cmd->network.supportedrates[4] = 0x0c;
	cmd->network.supportedrates[5] = 0x12;
	cmd->network.supportedrates[6] = 0x18;
	cmd->network.supportedrates[7] = 0x24;
	cmd->network.supportedrates[8] = 0x30;
	cmd->network.supportedrates[9] = 0x48;
	cmd->network.supportedrates[10] = 0x60;
	cmd->network.supportedrates[11] = 0x6c;
	// construct fixed IE
	fixed = (struct ndis_802_11_fixed_ies *)cmd->network.ies;
	fixed->beaconint = cpu_to_le16(bss->beacon_interval);
	fixed->caps = cpu_to_le16(bss->capability);
	// append provided IEs
	ie_ptr = (u8 *)&fixed[1];
	memcpy(ie_ptr, sme->ie, sme->ie_len);
	ie_ptr += sme->ie_len;
	// append constructed IEs
	if (1) {
		*(ie_ptr++) = WLAN_EID_HT_CAPABILITY;
		*(ie_ptr++) = (u8)sizeof(struct ieee80211_ht_cap);
		ht_cap = (struct ieee80211_ht_cap *)ie_ptr;
		ht_cap->cap_info = RTLFMAC_HT_CAP;
		ie_ptr += sizeof(struct ieee80211_ht_cap);
	}

	ret = rtlfmac_fw_cmd(priv, H2C_JOINBSS_CMD, cmd, sizeof(*cmd) + ie_len);
	kfree(cmd);
	if (!ret) {
		priv->connecting = true;
	}

done:
	cfg80211_put_bss(priv->wiphy, bss);

	return ret;
}

/* rtlfmac cfg80211 functions */
static int rtlfmac_cfg80211_scan(struct wiphy *wiphy,
		struct cfg80211_scan_request *request)
{
	struct rtlfmac_cfg80211_priv *priv = wiphy_to_cfg(wiphy);

	netdev_dbg(priv->ndev, "%s: enter\n", __func__);

	return rtlfmac_sitesurvey(priv, request);
}

static int rtlfmac_cfg80211_connect(struct wiphy *wiphy, struct net_device *ndev,
		struct cfg80211_connect_params *sme)
{
	struct rtlfmac_cfg80211_priv *priv = wiphy_to_cfg(wiphy);

	netdev_dbg(ndev, "%s: enter\n", __func__);

	return rtlfmac_connect(priv, ndev, sme);
}

static int rtlfmac_cfg80211_disconnect(struct wiphy *wiphy, struct net_device *ndev,
		u16 reason_code)
{
	struct rtlfmac_cfg80211_priv *priv = wiphy_to_cfg(wiphy);
	struct rtlfmac_disconnect_cmd cmd;

	netdev_dbg(ndev, "%s: enter\n", __func__);

	memset(&cmd, 0, sizeof(cmd));

	return rtlfmac_fw_cmd(priv, H2C_DISCONNECT_CMD, &cmd, sizeof(cmd));
}

static int rtlfmac_cfg80211_add_key(struct wiphy *wiphy, struct net_device *ndev,
		u8 key_index, bool pairwise, const u8 *mac_addr, struct key_params *params)
{
	u8 algo;
	struct rtlfmac_cfg80211_priv *priv = wiphy_to_cfg(wiphy);
	struct rtlfmac_setkey_cmd keycmd;
	struct rtlfmac_setstakey_cmd stakeycmd;

	netdev_dbg(ndev, "%s: enter idx=%hhu pair=%u mac=%pM\n", __func__, key_index, pairwise, mac_addr);

	switch(params->cipher) {
	case WLAN_CIPHER_SUITE_CCMP:
		algo = IW_KEYALGO_AES;
		break;
	default:
		netdev_err(ndev, "%s: unknown cipher: 0x%08X\n", __func__, params->cipher);
		return -ENOTSUPP;
	}

	if (pairwise && mac_addr) {
		memcpy(&stakeycmd.addr, mac_addr, ETH_ALEN);
		stakeycmd.algo = algo;
		memcpy(&stakeycmd.key, params->key, params->key_len);

		return rtlfmac_fw_cmd(priv, H2C_SETSTAKEY_CMD, &stakeycmd, sizeof(stakeycmd));
	} else {
		// assume 802.1x was successful
		priv->ieee8021x_blocked = false;

		keycmd.algo = algo;
		keycmd.keyid = key_index;
		keycmd.grpkey = (mac_addr == NULL ? 1 : 0);
		memcpy(&keycmd.key, params->key, params->key_len);

		return rtlfmac_fw_cmd(priv, H2C_SETKEY_CMD, &keycmd, sizeof(keycmd));
	}
}

static int rtlfmac_cfg80211_del_key(struct wiphy *wiphy, struct net_device *ndev,
		u8 key_index, bool pairwise, const u8 *mac_addr)
{
	netdev_dbg(ndev, "%s: enter idx=%hhu\n", __func__, key_index);

	return 0;
}

static int rtlfmac_cfg80211_set_default_key(struct wiphy *wiphy, struct net_device *ndev,
		u8 key_index, bool unicast, bool multicast)
{
	struct rtlfmac_cfg80211_priv *priv = wiphy_to_cfg(wiphy);

	netdev_dbg(ndev, "%s: enter idx=%hhu ucast=%u mcast=%u\n", __func__, key_index, unicast, multicast);

	priv->key_id = key_index;

	return 0;
}

/* cfg80211 data */
static struct cfg80211_ops rtlfmac_cfg80211_ops = {
	.scan			= rtlfmac_cfg80211_scan,
	.connect		= rtlfmac_cfg80211_connect,
	.disconnect		= rtlfmac_cfg80211_disconnect,
	.add_key		= rtlfmac_cfg80211_add_key,
	.del_key		= rtlfmac_cfg80211_del_key,
	.set_default_key	= rtlfmac_cfg80211_set_default_key,
};

static struct ieee80211_channel rtl_channeltable_2g[] = {
	{.center_freq = 2412, .hw_value = 1,},
	{.center_freq = 2417, .hw_value = 2,},
	{.center_freq = 2422, .hw_value = 3,},
	{.center_freq = 2427, .hw_value = 4,},
	{.center_freq = 2432, .hw_value = 5,},
	{.center_freq = 2437, .hw_value = 6,},
	{.center_freq = 2442, .hw_value = 7,},
	{.center_freq = 2447, .hw_value = 8,},
	{.center_freq = 2452, .hw_value = 9,},
	{.center_freq = 2457, .hw_value = 10,},
	{.center_freq = 2462, .hw_value = 11,},
	{.center_freq = 2467, .hw_value = 12,},
	{.center_freq = 2472, .hw_value = 13,},
	{.center_freq = 2484, .hw_value = 14,},
};

static struct ieee80211_rate rtl_ratetable_2g[] = {
	{.bitrate = 10, .hw_value = 0x00,},
	{.bitrate = 20, .hw_value = 0x01,},
	{.bitrate = 55, .hw_value = 0x02,},
	{.bitrate = 110, .hw_value = 0x03,},
	{.bitrate = 60, .hw_value = 0x04,},
	{.bitrate = 90, .hw_value = 0x05,},
	{.bitrate = 120, .hw_value = 0x06,},
	{.bitrate = 180, .hw_value = 0x07,},
	{.bitrate = 240, .hw_value = 0x08,},
	{.bitrate = 360, .hw_value = 0x09,},
	{.bitrate = 480, .hw_value = 0x0a,},
	{.bitrate = 540, .hw_value = 0x0b,},
};

static struct ieee80211_supported_band rtl_band_2ghz = {
	.band = IEEE80211_BAND_2GHZ,

	.channels = rtl_channeltable_2g,
	.n_channels = ARRAY_SIZE(rtl_channeltable_2g),

	.bitrates = rtl_ratetable_2g,
	.n_bitrates = ARRAY_SIZE(rtl_ratetable_2g),

	.ht_cap.cap = RTLFMAC_HT_CAP,
	.ht_cap.ht_supported = true,
	.ht_cap.ampdu_factor = IEEE80211_HT_MAX_AMPDU_64K,
	.ht_cap.ampdu_density = IEEE80211_HT_MPDU_DENSITY_16,
	.ht_cap.mcs.rx_mask[0] = 0xff,
	.ht_cap.mcs.tx_params = IEEE80211_HT_MCS_TX_DEFINED,
};

static const u32 rtlfmac_cipher_suites[] = {
	WLAN_CIPHER_SUITE_WEP40,
	WLAN_CIPHER_SUITE_WEP104,
	WLAN_CIPHER_SUITE_TKIP,
	WLAN_CIPHER_SUITE_CCMP,
	WLAN_CIPHER_SUITE_AES_CMAC,
};

/* rtlfmac netdev functions */
static int rtlfmac_ndo_open(struct net_device *ndev)
{
	netdev_dbg(ndev, "%s: enter\n", __func__);

	netif_tx_start_all_queues(ndev);

	return 0;
}

static int rtlfmac_ndo_stop(struct net_device *ndev)
{
	netdev_dbg(ndev, "%s: enter\n", __func__);

	if (ndev->ieee80211_ptr->current_bss) {
		cfg80211_disconnected(ndev, 0, NULL, 0, GFP_KERNEL);
	}
	netif_tx_stop_all_queues(ndev);
	netif_carrier_off(ndev);

	return 0;
}

netdev_tx_t rtlfmac_ndo_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	int hdrlen;
	struct ethhdr *eth = (struct ethhdr *)skb->data;
	struct ieee80211_qos_hdr *hdr;
	struct rtlfmac_cfg80211_priv *priv = wiphy_priv(ndev->ieee80211_ptr->wiphy);
	struct rtlfmac_tx_desc *pdesc;

	netdev_dbg(ndev, "%s: enter %pM->%pM proto=%04x\n", __func__, eth->h_source, eth->h_dest, be16_to_cpu(eth->h_proto));

	if (priv->ieee8021x_blocked && be16_to_cpu(eth->h_proto) != ETH_P_PAE) {
		netdev_dbg(ndev, "%s: drop non 802.1x packet\n", __func__);
		return NETDEV_TX_OK;
	}

	if (ieee80211_data_from_8023(skb, ndev->perm_addr, priv->wdev->iftype, priv->bssid, 1)) {
		netdev_err(ndev, "%s: failed to convert 802.3 to 802.11\n", __func__);
		return -1;
	}

	hdr = (struct ieee80211_qos_hdr *)skb->data;
	hdr->qos_ctrl = 0;

	priv->seqno[RTL_TXQ_BE] = ieee80211_sn_inc(priv->seqno[RTL_TXQ_BE]);
	hdr->seq_ctrl = cpu_to_le16(IEEE80211_SN_TO_SEQ(priv->seqno[RTL_TXQ_BE]));

	// or in PROT if WEP/WPA is enabled
	if (priv->cipher_pairwise && !priv->ieee8021x_blocked) {
		// 802.1x is complete
		hdr->frame_control |= cpu_to_le16(IEEE80211_FCTL_PROTECTED);
	}

	// need to emulate IEEE80211_KEY_FLAG_PUT_IV_SPACE
	if (ieee80211_has_protected(hdr->frame_control)) {
		hdrlen = ieee80211_hdrlen(hdr->frame_control);
		skb_push(skb, priv->iv_len);
		memmove(skb->data, skb->data + priv->iv_len, hdrlen);

		skb->data[hdrlen + 0] = (priv->txiv >>  0) & 0xff;
		skb->data[hdrlen + 1] = (priv->txiv >>  8) & 0xff;
		skb->data[hdrlen + 2] = 0;
		skb->data[hdrlen + 3] = 0x20 ; // | (key_id << 6) if b/m-cast
		skb->data[hdrlen + 4] = (priv->txiv >> 16) & 0xff;
		skb->data[hdrlen + 5] = (priv->txiv >> 24) & 0xff;
		skb->data[hdrlen + 6] = (priv->txiv >> 32) & 0xff;
		skb->data[hdrlen + 7] = (priv->txiv >> 40) & 0xff;
		priv->txiv++;
		priv->txiv &= 0xffffffffffffULL;
	}

	if (skb_headroom(skb) < RTL_TX_HEADER_SIZE) {
		netdev_err(ndev, "%s: not enough headroom\n", __func__);
		return -1;
	}

	pdesc = (struct rtlfmac_tx_desc *)skb_push(skb, RTL_TX_HEADER_SIZE);
	memset(pdesc, 0, RTL_TX_HEADER_SIZE);
	pdesc->first_seg = pdesc->last_seg = 1;
	pdesc->offset = RTL_TX_HEADER_SIZE;
	pdesc->pkt_size = cpu_to_le16(skb->len - RTL_TX_HEADER_SIZE);
	pdesc->macid = 5;
	pdesc->queue_sel = 0x03; // BE
	// FIXME if (wpa)
	pdesc->sec_type = 0x03; // AES/CCMP
	pdesc->key_id = priv->key_id;
	// XXX
	pdesc->own = 1;

	skb->queue_mapping = RTL_TXQ_BE;
	rtlfmac_write_skb(priv, skb);

	return NETDEV_TX_OK;
}

/* net_device data */
static const struct net_device_ops rtlfmac_netdev_ops = {
	.ndo_open		= rtlfmac_ndo_open,
	.ndo_stop		= rtlfmac_ndo_stop,
	.ndo_start_xmit		= rtlfmac_ndo_start_xmit,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
};

/* chip init functions */
int rtlfmac_chip_init(struct rtlfmac_cfg80211_priv *priv)
{
	int loop;
	u8 val8;
	u16 val16;

	/* Switch to HW control */
	val16 = rtlfmac_read_word(priv, REG_SYS_CLKR);
	if (val16 & FWHW_SEL) {
		val16 &= ~(FWHW_SEL | SWHW_SEL);
		rtlfmac_write_word(priv, REG_SYS_CLKR, val16);
	}

	/* Reset CPU Core, Digital Core and MAC I/O */
	val16 = rtlfmac_read_word(priv, REG_SYS_FUNC_EN);
	val16 &= ~(FEN_MREGEN | FEN_DCORE | FEN_CPUEN);
	rtlfmac_write_word(priv, REG_SYS_FUNC_EN, val16);
	msleep(20);

	rtlfmac_write_byte(priv, REG_SPS0_CTRL + 1, 0x53);
	rtlfmac_write_byte(priv, REG_SPS0_CTRL + 0, 0x57);

	/* Enable AFE Macro Block's Bandgap & Mbias */
	val8 = rtlfmac_read_byte(priv, REG_AFE_MISC);
	val8 |= AFE_MISC_BGEN;
	rtlfmac_write_byte(priv, REG_AFE_MISC, val8);
	val8 |= (AFE_MISC_MBEN | AFE_MISC_I32_EN);
	rtlfmac_write_byte(priv, REG_AFE_MISC, val8);

	/* Enable PLL Power (LDOA15V) */
	val8 = rtlfmac_read_byte(priv, REG_LDOA15_CTRL);
	rtlfmac_write_byte(priv, REG_LDOA15_CTRL, val8 | LDA15_EN);

	/* Enable LDOV12D block */
	val8 = rtlfmac_read_byte(priv, REG_LDOV12D_CTRL);
	rtlfmac_write_byte(priv, REG_LDOV12D_CTRL, val8 | LDV12_EN);

	/* Set Digital Vdd to retention isolation path */
	val16 = rtlfmac_read_word(priv, REG_SYS_ISO_CTRL);
	rtlfmac_write_word(priv, REG_SYS_ISO_CTRL, val16 | ISO_PWC_DV2RP);

	/* Warm reboot issue / Engineer Packet CP Test Enable */
	val16 = rtlfmac_read_word(priv, REG_SYS_FUNC_EN);
	rtlfmac_write_word(priv, REG_SYS_FUNC_EN, val16 | PWC_DV2LDR);

	/* Support 64k IMEM */
	val8 = rtlfmac_read_byte(priv, REG_SYS_ISO_CTRL + 1);
	rtlfmac_write_byte(priv, REG_SYS_ISO_CTRL + 1, val8 & ~0x97);

	/* Enable AFE clock */
	val16 = rtlfmac_read_word(priv, REG_AFE_XTAL_CTRL);
	rtlfmac_write_word(priv, REG_AFE_XTAL_CTRL, val16 & ~XTAL_GATE_AFE);

	/* Enable AFE PLL Macro Block */
	val8 = rtlfmac_read_byte(priv, REG_AFE_PLL_CTRL);
	rtlfmac_write_byte(priv, REG_AFE_PLL_CTRL, val8 | 0x10 | APLL_EN);
	udelay(500); /* Allow clock to stabilize */
	rtlfmac_write_byte(priv, REG_AFE_PLL_CTRL, val8 | 0x50 | APLL_EN);
	udelay(500);
	rtlfmac_write_byte(priv, REG_AFE_PLL_CTRL, val8 | 0x10 | APLL_EN);
	udelay(500);

	/* Attach AFE PLL to MACTOP/BB/... */
	val8 = rtlfmac_read_byte(priv, REG_SYS_ISO_CTRL);
	rtlfmac_write_byte(priv, REG_SYS_ISO_CTRL, val8 & ~(ISO_PLL2MD | ISO_MD2PP));

	/* Switch to 40MHz clock */
	rtlfmac_write_byte(priv, REG_SYS_CLKR, 0x00);

	/* Disable CPU clock and 80MHz clock SSC */
	val8 = rtlfmac_read_byte(priv, REG_SYS_CLKR);
	rtlfmac_write_byte(priv, REG_SYS_CLKR, val8 | 0xa0);

	/* Enable MAC clock */
	val16 = rtlfmac_read_word(priv, REG_SYS_CLKR);
	rtlfmac_write_word(priv, REG_SYS_CLKR, val16 | SYS_SYS_CLK_EN | SYS_MAC_CLK_EN);

	rtlfmac_write_byte(priv, REG_PMC_FSM, 0x02);

	/* Enable Digital Core */
	val16 = rtlfmac_read_word(priv, REG_SYS_FUNC_EN);
	rtlfmac_write_word(priv, REG_SYS_FUNC_EN, val16 | FEN_DCORE);

	/* Enable IOREG R/W (MAC I/O) */
	val16 = rtlfmac_read_word(priv, REG_SYS_FUNC_EN);
	rtlfmac_write_word(priv, REG_SYS_FUNC_EN, val16 | FEN_MREGEN);

	/* Switch the control path to FW */
	val16 = rtlfmac_read_word(priv, REG_SYS_CLKR);
	rtlfmac_write_word(priv, REG_SYS_CLKR, (val16 | FWHW_SEL) & ~SWHW_SEL);

	rtlfmac_write_word(priv, REG_CR, BBRSTn | BB_GLB_RSTn | SCHEDULE_EN |
			MACRXEN | MACTXEN | DDMA_EN | FW2HW_EN |
			RXDMA_EN | TXDMA_EN | HCI_RXDMA_EN | HCI_TXDMA_EN);

	/* Fix USB RX FIFO error */
	val8 = rtlfmac_read_byte(priv, REG_USB_AGG_TO);
	rtlfmac_write_byte(priv, REG_USB_AGG_TO, val8 | BIT(7));

	/* Save power */
	val8 = rtlfmac_read_byte(priv, REG_SYS_CLKR);
	rtlfmac_write_byte(priv, REG_SYS_CLKR, val8 & ~SYS_CPU_CLKSEL);

	/* Prevent incorrect operation of 8051 ROM code */
	rtlfmac_write_byte(priv, 0xFE1C, 0x80);

	/* Ensure TxDMA is ready for firmware download */
	for(loop = 0; loop < 20; loop++) {
		val8 = rtlfmac_read_byte(priv, REG_TCR);
		if ((val8 & TXDMA_INIT_VALUE) == TXDMA_INIT_VALUE)
			break;
		udelay(5);
	}
	if (loop >= 20) {
		/* Reset TxDMA */
		val8 = rtlfmac_read_byte(priv, REG_CR);
		rtlfmac_write_byte(priv, REG_CR, val8 & ~TXDMA_EN);
		udelay(2);
		rtlfmac_write_byte(priv, REG_CR, val8 | TXDMA_EN);
	}

	return 0;
}

static int rtlfmac_chip_init_complete(struct rtlfmac_cfg80211_priv *priv)
{
	u8 val8;
	u32 val32;

	/* Append PHY status, Enable RX TCP checksum offload */
	val32 = rtlfmac_read_dword(priv, REG_RCR);
	rtlfmac_write_dword(priv, REG_RCR, val32 | APP_PHYST_RXFF | RX_TCPOFDL_EN);
	pr_info("%s: RCR=0x%08x\n", __func__, rtlfmac_read_dword(priv, REG_RCR));
	/* Set MAC lookback to normal mode */
	rtlfmac_write_byte(priv, REG_LBKMD_SEL, LBK_NORMAL);
	/* Set TX/RX page size */
	val8 = rtlfmac_read_byte(priv, REG_PBP);
	rtlfmac_write_byte(priv, REG_PBP, val8 | PBP_PAGE_128B);
	/* Enable USB RX aggregation */
	val8 = rtlfmac_read_byte(priv, REG_RXDMA_RXCTRL);
	rtlfmac_write_byte(priv, REG_RXDMA_RXCTRL, val8 | RXDMA_AGG_EN);
	/* Set USB aggregation threshold (1 means no USB aggregation) */
	rtlfmac_write_byte(priv, REG_RXDMA_AGG_PG_TH, 1);
	/* Set USB aggregation timeout to 1.7ms/4 */
	rtlfmac_write_byte(priv, REG_USB_DMA_AGG_TO, 0x04);
	/* Fix USB RX FIFO error - done in chip init */
	/* Set MAC address */
	for(val8 = 0; val8 < 6; val8++) {
		rtlfmac_write_byte(priv, REG_MACIDR0 + val8, priv->wiphy->perm_addr[val8]);
	}

	return 0;
}

/* firmware loading functions */
static const char firmware_file[] = "rtlwifi/rtl8712u.bin";

static void rtlfmac_upload_fw(struct rtlfmac_cfg80211_priv *priv, const struct firmware *firmware)
{
	int i, state;
	struct rtlfmac_fw_hdr *fw_hdr;
	struct rtlfmac_fw_priv *fw_priv;
	struct rtlfmac_tx_desc *pdesc;
	struct sk_buff *skb;
	u8 *imem, *emem, *data, *ptr;
	u16 sig, val16, mask16;
	u32 fw_size, dmem_size, img_imem_size, img_sram_size, fw_priv_size, len, frag_len;

	fw_hdr = (struct rtlfmac_fw_hdr *)firmware->data;
	fw_size = firmware->size;

	sig = le16_to_cpu(fw_hdr->signature);
	if (sig != 0x8712 && sig != 0x8192) {
		pr_err("%s: invalid firmware signature\n", __func__);
		return;
	}
	dmem_size = le32_to_cpu(fw_hdr->dmem_size);
	img_imem_size = le32_to_cpu(fw_hdr->img_imem_size);
	img_sram_size = le32_to_cpu(fw_hdr->img_sram_size);
	fw_priv_size = le32_to_cpu(fw_hdr->fw_priv_size);

#if 0
	if (dmem_size + img_imem_size + img_sram_size + fw_priv_size > fw_size) {
		pr_err("%s: \n");
	}
#endif

	/* setup fw_priv */
	fw_priv = (struct rtlfmac_fw_priv *)(firmware->data + sizeof(struct rtlfmac_fw_hdr));
	memset(fw_priv, 0, sizeof(struct rtlfmac_fw_priv));

	fw_priv->hci_sel = 0x12;
	fw_priv->rf_config = 0x11;
	fw_priv->usb_ep_num = priv->num_endpoints;
#if 0
	fw_priv->turbo_mode = 1;
	fw_priv->low_power_mode = 0;
	fw_priv->mp_mode = 0;
	fw_priv->bw_40mhz_en = 0;
	fw_priv->vcs_type = 2;
	fw_priv->vcs_mode = 1;
#endif

	imem = (u8 *)firmware->data + sizeof(struct rtlfmac_fw_hdr) + sizeof(struct rtlfmac_fw_priv);
	emem = imem + img_imem_size;

	for(state = 0; state < 5; state++) {
		switch(state) {
		case 0: /* IMEM */
			data = imem;
			len = img_imem_size;
			break;
		case 1: /* EMEM */
			data = emem;
			len = img_sram_size;
			break;
		case 2: /* Enable CPU */
			val16 = rtlfmac_read_word(priv, REG_SYS_CLKR);
			rtlfmac_write_word(priv, REG_SYS_CLKR, val16 | SYS_CPU_CLKSEL);
			val16 = rtlfmac_read_word(priv, REG_SYS_FUNC_EN);
			rtlfmac_write_word(priv, REG_SYS_FUNC_EN, val16 | FEN_CPUEN);
			len = 0;
			break;
		case 3: /* DMEM */
			data = (u8 *)fw_priv;
			len = sizeof(struct rtlfmac_fw_priv);
			break;
		case 4: /* Final check */
			len = 0;
			break;
		}

		while (len > 0) {
			if (len > 0xC000) {
				frag_len = 0xC000;
			} else {
				frag_len = len;
			}

			skb = dev_alloc_skb(frag_len);
			if (!skb) {
				pr_err("%s: failed to allocate skb\n", __func__);
				return;
			}
			ptr = skb_put(skb, frag_len);
			memcpy(ptr, data, frag_len);
			pdesc = (struct rtlfmac_tx_desc *)skb_push(skb, RTL_TX_HEADER_SIZE);
			memset(pdesc, 0, RTL_TX_HEADER_SIZE);
			pdesc->pkt_size = cpu_to_le32(frag_len);
			pdesc->linip = (frag_len == len ? 1 : 0);

			skb->queue_mapping = RTL_TXQ_VO;
			rtlfmac_write_skb(priv, skb);

			len -= frag_len;
			data += frag_len;
		}

		switch(state) {
		case 0:
			mask16 = IMEM_CODE_DONE | IMEM_CHK_RPT;
			i = 20;
			break;
		case 1:
			mask16 = EMEM_CODE_DONE | EMEM_CHK_RPT;
			i = 20;
			break;
		case 2:
			mask16 = IMEM_RDY;
			i = 200;
			break;
		case 3:
			mask16 = DMEM_CODE_DONE;
			i = 200;
			break;
		case 4:
			mask16 = FWRDY;
			i = 10000;
			break;
		}

		do {
			val16 = rtlfmac_read_word(priv, REG_TCR);
			if (val16 & mask16)
				break;
			udelay(10);
			i--;
		} while (i > 0);
		if (i == 0) {
			pr_err("%s: firmware upload failed\n", __func__);
			return;
		}
	}
}

static void rtlfmac_fw_cb(const struct firmware *firmware, void *context)
{
	int err;
	struct rtlfmac_cfg80211_priv *priv = context;

	complete(&priv->fw_ready);
	if (!firmware) {
		pr_err("%s: firmware request failed\n", __func__);
		return;
	}

	rtlfmac_chip_init(priv);
	rtlfmac_upload_fw(priv, firmware);
	release_firmware(firmware);
	rtlfmac_chip_init_complete(priv);

	rtlfmac_rx_start(priv);

	err = wiphy_register(priv->wiphy);
	if (err < 0) {
		pr_err("%s: failed wiphy_register: %i\n", __func__, err);
		return;
	}

	err = register_netdev(priv->ndev);
	if (err < 0) {
		pr_err("%s: failed register_netdev: %i\n", __func__, err);
		return;
	}

	netif_tx_stop_all_queues(priv->ndev);
	netif_carrier_off(priv->ndev);
}

int rtlfmac_load_fw(struct rtlfmac_cfg80211_priv *priv)
{
	int rc;

	init_completion(&priv->fw_ready);

	pr_info("%s: loading firmware from \"%s\"\n", __func__, firmware_file);
	rc = request_firmware_nowait(THIS_MODULE, 1, firmware_file, priv->dev,
			GFP_KERNEL, priv, rtlfmac_fw_cb);
	if (rc) {
		pr_err("%s: failed to request firmware\n", __func__);
	}

	return rc;
}

/* probe helper functions */
static struct rtlfmac_cfg80211_priv *rtlfmac_alloc(void)
{
	struct net_device *ndev;
	struct rtlfmac_cfg80211_priv *priv;
	struct wiphy *wiphy;
	struct wireless_dev *wdev;

	/* allocate wireless_dev */
	wdev = kzalloc(sizeof(struct wireless_dev), GFP_KERNEL);
	if (!wdev) {
		return NULL;
	}

	/* fill out wireless_dev */
	wdev->iftype = NL80211_IFTYPE_STATION;

	/* allocate wiphy */
	wiphy = wiphy_new(&rtlfmac_cfg80211_ops,
			sizeof(struct rtlfmac_cfg80211_priv));
	if (!wiphy) {
		pr_err("%s: wiphy_new failed\n", __func__);
		kfree(wdev);
		return NULL;
	}
	priv = wiphy_priv(wiphy);
	priv->wdev = wdev;
	priv->wiphy = wiphy;
	wdev->wiphy = wiphy;

	/* fill out wiphy */
	//wiphy->privid
	wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION);
	wiphy->max_scan_ssids = 1;
	wiphy->max_num_pmkids = 16;

	wiphy->bands[IEEE80211_BAND_2GHZ] = &rtl_band_2ghz;
	//wiphy->bands[IEEE80211_BAND_5GHZ]
	wiphy->cipher_suites = rtlfmac_cipher_suites;
	wiphy->n_cipher_suites = ARRAY_SIZE(rtlfmac_cipher_suites);

	wiphy->rts_threshold = 2347;

	wiphy->signal_type = CFG80211_SIGNAL_TYPE_MBM;
	//wiphy->flags = ;

	/* allocate net_device */
	ndev = alloc_netdev(0, "wlan%d", ether_setup);
	if (!ndev) {
		pr_err("%s: alloc_netdev failed\n", __func__);
		wiphy_free(wiphy);
		kfree(wdev);
		return NULL;
	}
	priv->ndev = ndev;
	wdev->netdev = ndev;

	/* fill out net_device */
	ndev->netdev_ops = &rtlfmac_netdev_ops;
	ndev->needed_headroom = RTL_TX_HEADER_SIZE + sizeof(struct ieee80211_qos_hdr) +
			8 + 8 - 14; // IV junk + SNAP - sizeof(Ethernet header)
	ndev->ieee80211_ptr = wdev;

	return priv;
}

/* driver init/de-init functions */
int rtlfmac_probe(struct usb_interface *intf,
		const struct usb_device_id *id)
{
	int i;
	struct rtlfmac_cfg80211_priv *priv;
	struct usb_device *usb = interface_to_usbdev(intf);
	u8 tmpb;

	/* check the interface */
	tmpb = intf->cur_altsetting->desc.bNumEndpoints;
	switch(tmpb) {
	case 4:
	case 6:
	case 11:
		pr_info("%s: %i endpoints\n", __func__, tmpb);
		break;
	default:
		pr_err("%s: unknown number of endpoints!\n", __func__);
		return -1;
	}

	/* cfg80211 */
	priv = rtlfmac_alloc();
	if (!priv) {
		return -1;
	}
	priv->usbdev = usb;
	priv->dev = &usb->dev;

	/* usb endpoint mapping */
	priv->num_endpoints = intf->cur_altsetting->desc.bNumEndpoints;

	priv->in_ep_num = 0x3;
	priv->ep_mapping[RTL_TXQ_BE] = 0x6;
	priv->ep_mapping[RTL_TXQ_VO] = 0x4;
	priv->ep_mapping[RTL_TXQ_H2CCMD] = 0xd;
	switch(priv->num_endpoints) {
	case 4:
		priv->ep_mapping[RTL_TXQ_BK] = 0x6;
		priv->ep_mapping[RTL_TXQ_VI] = 0x4;
		priv->ep_mapping[RTL_TXQ_BCN] = 0xd;
		priv->ep_mapping[RTL_TXQ_HI] = 0xd;
		priv->ep_mapping[RTL_TXQ_MGT] = 0xd;
		break;
	case 6:
		priv->ep_mapping[RTL_TXQ_BK] = 0x7;
		priv->ep_mapping[RTL_TXQ_VI] = 0x5;
		priv->ep_mapping[RTL_TXQ_BCN] = 0xd;
		priv->ep_mapping[RTL_TXQ_HI] = 0xd;
		priv->ep_mapping[RTL_TXQ_MGT] = 0xd;
		break;
	case 11:
		priv->ep_mapping[RTL_TXQ_BK] = 0x7;
		priv->ep_mapping[RTL_TXQ_VI] = 0x5;
		priv->ep_mapping[RTL_TXQ_BCN] = 0xa;
		priv->ep_mapping[RTL_TXQ_HI] = 0xb;
		priv->ep_mapping[RTL_TXQ_MGT] = 0xc;
		break;
	}

	/* driver state */
	dev_set_drvdata(priv->dev, priv);
	set_wiphy_dev(priv->wiphy, priv->dev);
	SET_NETDEV_DEV(priv->ndev, priv->dev);

	/* ensure chip is in initial state */
	rtlfmac_write_byte(priv, REG_USB_HRPWM, 0x00);

	/* read chip version */
	tmpb = (rtlfmac_read_dword(priv, REG_PMC_FSM) >> 15) & 0x1f;
	if (tmpb != 0x3) {
		tmpb = (tmpb >> 1) + 1;
		if (tmpb > 0x3)
			tmpb = 0x2; /* default to BCUT */
	}
	priv->hwrev = tmpb;
	pr_info("%s: hwrev %u\n", __func__, priv->hwrev);

	/* read eeprom info */
	tmpb = rtlfmac_read_byte(priv, REG_EPROM_CMD);
	pr_info("%s: Boot from %s: Autoload %s\n",
			__func__,
			(tmpb & EPROM_SEL) ? "EEPROM" : "EFUSE",
			(tmpb & EPROM_EN) ? "OK" : "Failed");
	if (tmpb & EPROM_EN) {
		/* Prevent EFUSE leakage by turning on 2.5V */
		tmpb = rtlfmac_read_byte(priv, REG_EFUSE_TEST + 3);
		rtlfmac_write_byte(priv, REG_EFUSE_TEST + 3, tmpb | 0x80);
		msleep(20);
		rtlfmac_write_byte(priv, REG_EFUSE_TEST + 3, tmpb & ~0x80);
	}

	/* read MAC address from registers */
	for(i = 0; i < ETH_ALEN; i++) {
		tmpb = rtlfmac_read_byte(priv, REG_USB_MAC_ADDR + i);
		priv->ndev->dev_addr[i] = tmpb;
		priv->ndev->perm_addr[i] = tmpb;
		priv->wiphy->perm_addr[i] = tmpb;
	}
	pr_info("%s: MAC address from registers: %pM\n", __func__, priv->wiphy->perm_addr);

	rtlfmac_load_fw(priv);

	return 0;
}

static void rtlfmac_disconnect(struct usb_interface *intf)
{
	struct rtlfmac_cfg80211_priv *priv;
	struct usb_device *usb = interface_to_usbdev(intf);

	priv = dev_get_drvdata(&usb->dev);

	wait_for_completion(&priv->fw_ready);

	rtlfmac_rx_cleanup(priv);

	if (priv->scan_request) {
		cfg80211_scan_done(priv->scan_request, true);
	}

	unregister_netdev(priv->ndev);
	free_netdev(priv->ndev);

	wiphy_unregister(priv->wiphy);
	wiphy_free(priv->wiphy);

	kfree(priv->wdev);
}

static const struct usb_device_id products[] = {
/* RTL8188SU */
	/* Realtek */
	{USB_DEVICE(0x0BDA, 0x8171)},
	{USB_DEVICE(0x0bda, 0x8173)},
	{USB_DEVICE(0x0bda, 0x8712)},
	{USB_DEVICE(0x0bda, 0x8713)},
	{USB_DEVICE(0x0bda, 0xC512)},
	/* Abocom */
	{USB_DEVICE(0x07B8, 0x8188)},
	/* ASUS */
	{USB_DEVICE(0x0B05, 0x1786)},
	{USB_DEVICE(0x0B05, 0x1791)}, /* 11n mode disable */
	/* Belkin */
	{USB_DEVICE(0x050D, 0x945A)},
	/* ISY IWL - Belkin clone */
	{USB_DEVICE(0x050D, 0x11F1)},
	/* Corega */
	{USB_DEVICE(0x07AA, 0x0047)},
	/* D-Link */
	{USB_DEVICE(0x2001, 0x3306)},
	{USB_DEVICE(0x07D1, 0x3306)}, /* 11n mode disable */
	/* Edimax */
	{USB_DEVICE(0x7392, 0x7611)},
	/* EnGenius */
	{USB_DEVICE(0x1740, 0x9603)},
	/* Hawking */
	{USB_DEVICE(0x0E66, 0x0016)},
	/* Hercules */
	{USB_DEVICE(0x06F8, 0xE034)},
	{USB_DEVICE(0x06F8, 0xE032)},
	/* Logitec */
	{USB_DEVICE(0x0789, 0x0167)},
	/* PCI */
	{USB_DEVICE(0x2019, 0xAB28)},
	{USB_DEVICE(0x2019, 0xED16)},
	/* Sitecom */
	{USB_DEVICE(0x0DF6, 0x0057)},
	{USB_DEVICE(0x0DF6, 0x0045)},
	{USB_DEVICE(0x0DF6, 0x0059)}, /* 11n mode disable */
	{USB_DEVICE(0x0DF6, 0x004B)},
	{USB_DEVICE(0x0DF6, 0x005B)},
	{USB_DEVICE(0x0DF6, 0x005D)},
	{USB_DEVICE(0x0DF6, 0x0063)},
	/* Sweex */
	{USB_DEVICE(0x177F, 0x0154)},
	/* Thinkware */
	{USB_DEVICE(0x0BDA, 0x5077)},
	/* Toshiba */
	{USB_DEVICE(0x1690, 0x0752)},
	/* - */
	{USB_DEVICE(0x20F4, 0x646B)},
	{USB_DEVICE(0x083A, 0xC512)},
	{USB_DEVICE(0x25D4, 0x4CA1)},
	{USB_DEVICE(0x25D4, 0x4CAB)},

/* RTL8191SU */
	/* Realtek */
	{USB_DEVICE(0x0BDA, 0x8172)},
	{USB_DEVICE(0x0BDA, 0x8192)},
	/* Amigo */
	{USB_DEVICE(0x0EB0, 0x9061)},
	/* ASUS/EKB */
	{USB_DEVICE(0x13D3, 0x3323)},
	{USB_DEVICE(0x13D3, 0x3311)}, /* 11n mode disable */
	{USB_DEVICE(0x13D3, 0x3342)},
	/* ASUS/EKBLenovo */
	{USB_DEVICE(0x13D3, 0x3333)},
	{USB_DEVICE(0x13D3, 0x3334)},
	{USB_DEVICE(0x13D3, 0x3335)}, /* 11n mode disable */
	{USB_DEVICE(0x13D3, 0x3336)}, /* 11n mode disable */
	/* ASUS/Media BOX */
	{USB_DEVICE(0x13D3, 0x3309)},
	/* Belkin */
	{USB_DEVICE(0x050D, 0x815F)},
	/* D-Link */
	{USB_DEVICE(0x07D1, 0x3302)},
	{USB_DEVICE(0x07D1, 0x3300)},
	{USB_DEVICE(0x07D1, 0x3303)},
	/* Edimax */
	{USB_DEVICE(0x7392, 0x7612)},
	/* EnGenius */
	{USB_DEVICE(0x1740, 0x9605)},
	/* Guillemot */
	{USB_DEVICE(0x06F8, 0xE031)},
	/* Hawking */
	{USB_DEVICE(0x0E66, 0x0015)},
	/* Mediao */
	{USB_DEVICE(0x13D3, 0x3306)},
	/* PCI */
	{USB_DEVICE(0x2019, 0xED18)},
	{USB_DEVICE(0x2019, 0x4901)},
	/* Sitecom */
	{USB_DEVICE(0x0DF6, 0x0058)},
	{USB_DEVICE(0x0DF6, 0x0049)},
	{USB_DEVICE(0x0DF6, 0x004C)},
	{USB_DEVICE(0x0DF6, 0x0064)},
	/* Skyworth */
	{USB_DEVICE(0x14b2, 0x3300)},
	{USB_DEVICE(0x14b2, 0x3301)},
	{USB_DEVICE(0x14B2, 0x3302)},
	/* - */
	{USB_DEVICE(0x04F2, 0xAFF2)},
	{USB_DEVICE(0x04F2, 0xAFF5)},
	{USB_DEVICE(0x04F2, 0xAFF6)},
	{USB_DEVICE(0x13D3, 0x3339)},
	{USB_DEVICE(0x13D3, 0x3340)}, /* 11n mode disable */
	{USB_DEVICE(0x13D3, 0x3341)}, /* 11n mode disable */
	{USB_DEVICE(0x13D3, 0x3310)},
	{USB_DEVICE(0x13D3, 0x3325)},

/* RTL8192SU */
	/* Realtek */
	{USB_DEVICE(0x0BDA, 0x8174)},
	/* Belkin */
	{USB_DEVICE(0x050D, 0x845A)},
	/* Corega */
	{USB_DEVICE(0x07AA, 0x0051)},
	/* Edimax */
	{USB_DEVICE(0x7392, 0x7622)},
	/* NEC */
	{USB_DEVICE(0x0409, 0x02B6)},
	{}
};

MODULE_DEVICE_TABLE(usb, products);

static struct usb_driver rtlfmac_driver = {
	.name		= "rtlfmac",
	.id_table	= products,
	.probe		= rtlfmac_probe,
	.disconnect	= rtlfmac_disconnect,
#if 0
	.suspend	= rtlfmac_suspend,
	.resume		= rtlfmac_resume,
#endif
};

module_usb_driver(rtlfmac_driver);

MODULE_AUTHOR("Joshua Roys");
MODULE_DESCRIPTION("FullMAC driver for Realtek USB devices");
MODULE_LICENSE("GPL");
MODULE_FIRMWARE("rtlwifi/rtl8712u.bin");
