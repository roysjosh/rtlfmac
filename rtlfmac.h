
#ifndef RTLFMAC_H
#define RTLFMAC_H

#include <linux/completion.h>
#include <linux/firmware.h>

#define REALTEK_USB_VENQT_READ		0xC0
#define REALTEK_USB_VENQT_WRITE		0x40
#define REALTEK_USB_VENQT_CMD_REQ	0x05
#define   REALTEK_USB_VENQT_CMD_IDX	0x00
#define MAX_USBCTRL_VENDORREQ_TIMES	10

enum fw_h2c_cmd {
	H2C_READ_MACREG_CMD,				/*0*/
	H2C_WRITE_MACREG_CMD,
	H2C_READBB_CMD,
	H2C_WRITEBB_CMD,
	H2C_READRF_CMD,
	H2C_WRITERF_CMD,				/*5*/
	H2C_READ_EEPROM_CMD,
	H2C_WRITE_EEPROM_CMD,
	H2C_READ_EFUSE_CMD,
	H2C_WRITE_EFUSE_CMD,
	H2C_READ_CAM_CMD,				/*10*/
	H2C_WRITE_CAM_CMD,
	H2C_SETBCNITV_CMD,
	H2C_SETMBIDCFG_CMD,
	H2C_JOINBSS_CMD,
	H2C_DISCONNECT_CMD,				/*15*/
	H2C_CREATEBSS_CMD,
	H2C_SETOPMode_CMD,
	H2C_SITESURVEY_CMD,
	H2C_SETAUTH_CMD,
	H2C_SETKEY_CMD,					/*20*/
	H2C_SETSTAKEY_CMD,
	H2C_SETASSOCSTA_CMD,
	H2C_DELASSOCSTA_CMD,
	H2C_SETSTAPWRSTATE_CMD,
	H2C_SETBASICRATE_CMD,				/*25*/
	H2C_GETBASICRATE_CMD,
	H2C_SETDATARATE_CMD,
	H2C_GETDATARATE_CMD,
	H2C_SETPHYINFO_CMD,
	H2C_GETPHYINFO_CMD,				/*30*/
	H2C_SETPHY_CMD,
	H2C_GETPHY_CMD,
	H2C_READRSSI_CMD,
	H2C_READGAIN_CMD,
	H2C_SETATIM_CMD,				/*35*/
	H2C_SETPWRMODE_CMD,
	H2C_JOINBSSRPT_CMD,
	H2C_SETRATABLE_CMD,
	H2C_GETRATABLE_CMD,
	H2C_GETCCXREPORT_CMD,				/*40*/
	H2C_GETDTMREPORT_CMD,
	H2C_GETTXRATESTATICS_CMD,
	H2C_SETUSBSUSPEND_CMD,
	H2C_SETH2CLBK_CMD,
	H2C_TMP1,					/*45*/
	H2C_WOWLAN_UPDATE_GTK_CMD,
	H2C_WOWLAN_FW_OFFLOAD,
	H2C_TMP2,
	H2C_TMP3,
	H2C_WOWLAN_UPDATE_IV_CMD,			/*50*/
	H2C_TMP4,
	MAX_H2CCMD					/*52*/
};

struct rtlfmac_sitesurvey_cmd {
	u32 active;
	u32 bsslimit;
	u32 ssidlen;
	u8 ssid[IEEE80211_MAX_SSID_LEN + 1];
};

struct rtlfmac_cfg80211_priv {
	struct usb_device *usbdev;
	struct device *dev;

	struct wiphy *wiphy;

	u8 hwrev;

	struct completion fw_ready;
	const struct firmware *fw;
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
#define REG_TCR					0x0044
#define   IMEM_CHK_RPT				BIT(1)
#define   EMEM_CHK_RPT				BIT(3)
#define REG_RCR					0x0048

#define TXDMA_INIT_VALUE			(IMEM_CHK_RPT | EMEM_CHK_RPT)

/* MACID Setting Registers */
#define REG_MACIDR0				0x0050
#define REG_MACIDR4				0x0054

/* USB Configuration Registers */
#define REG_USB_AGG_TO				0xFE5C
#define REG_USB_MAC_ADDR			0xFE70

#endif
