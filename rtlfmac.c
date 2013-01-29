
#include <linux/ieee80211.h>
#include <linux/module.h>
#include <linux/usb.h>
#include <net/cfg80211.h>

#include "rtlfmac.h"

/* usb communication functions */
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

static u8 rtlfmac_read_byte(struct rtlfmac_cfg80211_priv *priv, u32 addr)
{
	//struct device *dev = priv->dev;

	//return (u8)_usb_read_sync(to_usb_device(dev), addr, 1);
	return _usb_read_sync(priv->usbdev, addr, 1);
}

static u16 rtlfmac_read_word(struct rtlfmac_cfg80211_priv *priv, u32 addr)
{
	//struct device *dev = priv->dev;

	//return (u16)_usb_read_sync(to_usb_device(dev), addr, 2);
	return _usb_read_sync(priv->usbdev, addr, 2);
}

static u32 rtlfmac_read_dword(struct rtlfmac_cfg80211_priv *priv, u32 addr)
{
	//struct device *dev = priv->dev;

	//return _usb_read_sync(to_usb_device(dev), addr, 4);
	return _usb_read_sync(priv->usbdev, addr, 4);
}

/* rtlfmac functions */
int rtlfmac_fw_cmd(struct rtlfmac_cfg80211_priv *priv, uint8_t code, void *buf, int len)
{
	return 0;
}

int rtlfmac_sitesurvey(struct rtlfmac_cfg80211_priv *priv, struct cfg80211_scan_request *req)
{
	struct rtlfmac_sitesurvey_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.bsslimit = cpu_to_le32(48);
	if (req->n_ssids) {
		cmd.active = cpu_to_le32(1);
		cmd.ssidlen = cpu_to_le32(req->ssids[0].ssid_len);
		memcpy(cmd.ssid, req->ssids[0].ssid, req->ssids[0].ssid_len);
	}

	return rtlfmac_fw_cmd(priv, H2C_SITESURVEY_CMD, &cmd, sizeof(cmd));
}

/* rtlfmac cfg80211 functions */
static int rtlfmac_cfg80211_scan(struct wiphy *wiphy,
		struct cfg80211_scan_request *request)
{
	struct rtlfmac_cfg80211_priv *priv = wiphy_to_cfg(wiphy);

	return rtlfmac_sitesurvey(priv, request);
}

static int rtlfmac_cfg80211_connect(struct wiphy *wiphy, struct net_device *ndev,
		struct cfg80211_connect_params *sme)
{
	return 0;
}

static int rtlfmac_cfg80211_disconnect(struct wiphy *wiphy, struct net_device *ndev,
		u16 reason_code)
{
	return 0;
}

/* cfg80211 data */
static struct cfg80211_ops rtlfmac_cfg80211_ops = {
	.scan		= rtlfmac_cfg80211_scan,
	.connect	= rtlfmac_cfg80211_connect,
	.disconnect	= rtlfmac_cfg80211_disconnect,
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

	.ht_cap = {0},
};

static const u32 rtlfmac_cipher_suites[] = {
	WLAN_CIPHER_SUITE_WEP40,
	WLAN_CIPHER_SUITE_WEP104,
	WLAN_CIPHER_SUITE_TKIP,
	WLAN_CIPHER_SUITE_CCMP,
	WLAN_CIPHER_SUITE_AES_CMAC,
};

/* cfg80211 functions */
static struct rtlfmac_cfg80211_priv *rtlfmac_alloc_wiphy()
{
	struct rtlfmac_cfg80211_priv *priv;
	struct wiphy *wiphy;
	s32 err = 0;

	wiphy = wiphy_new(&rtlfmac_cfg80211_ops,
			sizeof(struct rtlfmac_cfg80211_priv));
	if (!wiphy) {
		pr_err("%s: wiphy_new failed\n", __func__);
		return NULL;
	}
	priv = wiphy_priv(wiphy);
	priv->wiphy = wiphy;

	/* fill out wiphy */
	//wiphy->perm_addr
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

	err = wiphy_register(wiphy);
	if (err < 0) {
		pr_err("%s: failed wiphy_register: %i\n", __func__, err);
		wiphy_free(wiphy);
		return NULL;
	}

	return priv;
}

int rtlfmac_probe(struct usb_interface *intf,
		const struct usb_device_id *id)
{
	struct rtlfmac_cfg80211_priv *priv;
	struct usb_device *usb = interface_to_usbdev(intf);
	u8 tmpb;

	pr_info("%s: enter\n", __func__);

	/* cfg80211 */
	priv = rtlfmac_alloc_wiphy();
	if (!priv) {
		return -1;
	}
	priv->usbdev = usb;
	priv->dev = &usb->dev;

	/* driver state */
	dev_set_drvdata(priv->dev, priv);
	set_wiphy_dev(priv->wiphy, priv->dev);

	/* read chip version */
	tmpb = (rtlfmac_read_dword(priv, REG_PMC_FSM) >> 15) & 0x1f;
	if (tmpb != 0x3) {
		tmpb = (tmpb >> 1) + 1;
		if (tmpb > 0x3)
			tmpb = 0x2; /* default to BCUT */
	}
	priv->hwrev = tmpb;

	pr_info("%s: hw rev: %u, leaving\n", __func__, priv->hwrev);

	return 0;
}

static void rtlfmac_disconnect(struct usb_interface *intf)
{
	struct rtlfmac_cfg80211_priv *priv;
	struct usb_device *usb = interface_to_usbdev(intf);

	pr_info("%s: enter\n", __func__);

	priv = dev_get_drvdata(&usb->dev);
	wiphy_unregister(priv->wiphy);
	wiphy_free(priv->wiphy);
}

static const struct usb_device_id products[] = {
	{
		.idVendor = 0x0b05,
		.idProduct = 0x1786,
	},
	{ }
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
