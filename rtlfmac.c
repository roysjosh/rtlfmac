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

/* rtlfmac functions */
int rtlfmac_fw_cmd(struct rtlfmac_cfg80211_priv *priv, uint8_t code, void *buf, int len)
{
#if 0
	struct sk_buff *skb;

	skb = dev_alloc_skb(len);
	if (!skb)
		return -ENOMEM;
#endif

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

/* firmware loading functions */
static const char firmware_file[] = "rtlwifi/rtl8712u.bin";

static void rtlfmac_fw_cb(const struct firmware *firmware, void *context)
{
	struct rtlfmac_cfg80211_priv *priv = context;

	complete(&priv->fw_ready);
	if (!firmware) {
		pr_err("%s: firmware request failed\n", __func__);
		return;
	}

	priv->fw = firmware;

	rtlfmac_chip_init(priv);
}

int rtlfmac_load_fw(struct rtlfmac_cfg80211_priv *priv)
{
	int rc;

	init_completion(&priv->fw_ready);
	priv->fw = NULL;

	pr_info("%s: loading firmware from \"%s\"\n", __func__, firmware_file);
	rc = request_firmware_nowait(THIS_MODULE, 1, firmware_file, priv->dev,
			GFP_KERNEL, priv, rtlfmac_fw_cb);
	if (rc) {
		pr_err("%s: failed to request firmware\n", __func__);
	}

	return rc;
}

/* probe helper functions */
static struct rtlfmac_cfg80211_priv *rtlfmac_alloc_wiphy(void)
{
	struct rtlfmac_cfg80211_priv *priv;
	struct wiphy *wiphy;
#if 0
	s32 err = 0;
#endif

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

#if 0
	err = wiphy_register(wiphy);
	if (err < 0) {
		pr_err("%s: failed wiphy_register: %i\n", __func__, err);
		wiphy_free(wiphy);
		return NULL;
	}
#endif

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
		priv->wiphy->perm_addr[i] = rtlfmac_read_byte(priv, REG_USB_MAC_ADDR + i);
	}
	pr_info("%s: MAC address from registers: %pM\n", __func__, priv->wiphy->perm_addr);

	rtlfmac_load_fw(priv);

	pr_info("%s: leaving\n", __func__);

	return 0;
}

static void rtlfmac_disconnect(struct usb_interface *intf)
{
	struct rtlfmac_cfg80211_priv *priv;
	struct usb_device *usb = interface_to_usbdev(intf);

	pr_info("%s: enter\n", __func__);

	priv = dev_get_drvdata(&usb->dev);

	wait_for_completion(&priv->fw_ready);
	if (priv->fw)
		release_firmware(priv->fw);
#if 0
	wiphy_unregister(priv->wiphy);
#endif
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
