#include <zebra.h>
#include "zthread_support.h"
#include "if_support.h"
#include "fs_support.h"
#include "io_support.h"
#include "getopt.h"
#include "daemon.h"
#include "mac.h"
#include "zclient.h"
#include "vty.h"
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/wireless.h>
#include "ieee80211.h"
#include "wipsd_wnode.h"

wips_event wips_event_table[] = {
	{0,NULL},
	{WIPS_EID_ALL, 			"all"},
	{WIPS_EID_ERR_CFG_GRP, 	"policy_category"},
	{WIPS_EID_NO_CRYPT_AP, 	"no_encryption"},
	{WIPS_EID_CRYPT_WEP_AP, 	"web_encryption"},
	{WIPS_EID_WPS_AP,		"wps_enabled"},
	{WIPS_EID_WDS_AP,		"wds_ap"},
	{WIPS_EID_WDS_STA,		"wds_sta"},
	{WIPS_EID_AD_HOC,		"adhoc"},
	{WIPS_EID_AD_PKG,		"adhoc_communication"},
	{WIPS_EID_UNAUTH_AP,	"rogue_ap"},
//	WIPS_EID_INVALID_FREQ_AP,
	{WIPS_EID_STA_PROXY_AP,	"proxy_ap"},
	{WIPS_EID_CLOSE_PSPE,		"pspf_disabled"},
//	WIPS_EID_UNAUTH_MAC_FACT,
	{WIPS_EID_WPA_REFUSED,	"wpa_refused"},
	{WIPS_EID_FORBID_CHANNEL,"illegal_channel"},
	{WIPS_EID_UNAUTH_ESSID,	"illegal_essid"},
	{WIPS_EID_AP_BRAODCAST_SSID,	"broadcast_essid"},
	{WIPS_EID_AP_DEFAULTSSID,	"default_essid"},
	{WIPS_EID_UNAUTH_STA,		"unauthed_station"},
	{WIPS_EID_AUTHSTA_UNAUTHAP,"authed_station_associated_unauthed_ap"},
//	WIPS_EID_UNAUTH_DHCP,
	{WIPS_EID_AUTHSTA_EXTAP,		"authed_station_associated_external_ap"},
	{WIPS_EID_UNAUTHSTA_INTERAP,"unauthed_station_associated_internal_ap"},
//	WIPS_EID_AP_FORBIDRATE,
//	WIPS_EID_STA_FORBIDRATE,

	{WIPS_EID_PROBE_GRP,			"probe_category"},
//	WIPS_EID_NULLPROBE_RESP,
	{WIPS_EID_UNAUTHSTA_PROBE_TOOMANY,	"unanthed_station_scan"},

	{WIPS_EID_SPOOFING_GRP,		"spoof_category"},
	{WIPS_EID_FISHING_AP,			"fishing_ap"},	/* == WIPS_EID_FAKESSID_AP, */
	{WIPS_EID_HOTSPOTTER_AP,		"hotspotter_ap"},
	{WIPS_EID_AIRBASE_NG_FAKE_AP,	"fake_ap"},
	{WIPS_EID_MDK3_BEACON_FLOOD_AP,	"mdk3_fake_ap"},
	{WIPS_EID_MITM_ATTACK,				"MITM_attack"},
	{WIPS_EID_ARP_SPOOFING_ATTACK,		"arp_spoof_attack"},
	{WIPS_EID_SEND2_ITSELF,				"send_to_itself"},
	{WIPS_EID_AP_SIGNAL_TOOHIGH,		"signal_toohigh"},
	{WIPS_EID_TOOMANY_AP_INACHANNEL,	"too_many_ap_inchannel"},
	{WIPS_EID_ADHOC_SSID_AP_SSID_SAME,	"adhoc_essid_same_with_ap"},
//	WIPS_EID_STA_FAKE_AS_AP,
	{WIPS_EID_STA_SIGNAL_TOOHIGH,		"station_signal_toohigh"},

	{WIPS_EID_DOS_GRP,					"Dos_attack"},
	{WIPS_EID_DEAUTH_STA,				"deauth_dos_attack"},
	{WIPS_EID_MDK3_DEAUTH_STA,			"MDK3_deauth_dos_attack"},
	{WIPS_EID_AIREPLAY_NG_DEAUTH_STA,	"airreplay-ng_deauth_attack"},
	{WIPS_EID_DEASSO_STA,				"deassociate_attack"},
	{WIPS_EID_MDK3_DEASSO_STA,			"MDK3_deassociate_attack"},
	{WIPS_EID_AUTH_FLOOD_STA,			"auth_flood_attack"},
	{WIPS_EID_ASSO_FLOOD_STA,			"associate_flood_attack"},
	{WIPS_EID_PROBE_FLOOD_STA,			"probe_flood_attack"},
	{WIPS_EID_ASSO_FLOOD_ACK_STA,		"ACK_flood_attack"},
	{WIPS_EID_ASSO_FLOOD_RTS_STA,		"RST_flood_attack"},
	{WIPS_EID_ASSO_FLOOD_CTS_STA,		"CTS_flood_attack"},
	{WIPS_EID_DURATION_ATTACK,			"time-slice_attack"},
	{WIPS_EID_TOOMANY_AP,				"too_many_ap"},
	{WIPS_EID_BRAODCAST_STORM,			"broadcast_storm"},
	{WIPS_EID_BRAODCAST_SMAC,			"broadcast_source_mac"},
	{WIPS_EID_GROUP_SMAC,				"multicast_source_mac"},
	{WIPS_EID_AP_TOOMANY_QBSSSTA,		"too_many_QBSS_station"},
	
	{WIPS_EID_CRACK_GRP,					"crack_category"},
	{WIPS_EID_VIOLENT_CRACK_STA,			"violent_crack"},
	{WIPS_EID_AIREPLAY_NG_FRAMG_STA,	"aireplay-ng_FRAMG_crack"},
	{WIPS_EID_AIREPLAY_NG_CHOP_STA,		"aireplay-ng_CHOP_crack"},
	{WIPS_EID_AIREPLAY_NG_ARP_STA,		"aireplay-ng_arp_crack"},
	{WIPS_EID_WESSID_NG_STA,				"wessid-ng_crack"},
//	WIPS_EID_ASLEAP_ATTACK,
	{WIPS_EID_8021XAUTH_ATTACK,			"802.1x_violent_attack"},

	{WIPS_EID_INFO_GRP,					"configure_category"},
	{WIPS_EID_ASSO_DENIED_STA,			"ap_refuse_station"},
	{WIPS_EID_AUTH_REFUSED,				"ap_refuse_auth"},
	{WIPS_EID_AP_SMALL_FRAG_PKG,		"ap_frag_pkg_too_small"},
//	WIPS_EID_SMALL_INTERVAL_RETRY_PKG,
	{WIPS_EID_TOOMANY_BEACON,			"too_many_beacon"},
	{WIPS_EID_REASSO_REFUSED,			"reassociate_refuse"},
//	WIPS_EID_SMALL_INTERVAL_RTS_CTS,		
	{WIPS_EID_AP_ESSID_DIFF,				"different_ap_configuration"},
	{WIPS_EID_AP_BG_MODE,				"BG_mode_ap"},
	{WIPS_EID_11N_DEVICE,					"802.11n_enabled"},
	{WIPS_EID_AP_SUPPORT40MHZ,			"dual_channel_enabled"},
	{WIPS_EID_NO_QOS,					"no_QOS"},
	{WIPS_EID_AP_SIGNAL_TOOLOW,			"ap_signal_too_low"},
	{WIPS_EID_PROBE_NOAUTH,				"probe_noauth"},
	{WIPS_EID_PROBE_REFUSED,				"probe_refused"},
//	WIPS_EID_ROAMING_BIG_INTERVAL,
	{WIPS_EID_STA_SMALL_FRAG_PKG,		"station_too_many_frag_pkg"},
//	WIPS_EID_STA_SLEEPING_BIG_INTERVAL,
	{WIPS_EID_STA_LISTENINTERVAL_TOOBIG,	"station_listenning_interval_too_long"},
//	WIPS_EID_STA_SLEEPING_LOSE_PKG,		
	{WIPS_EID_STA_SIGNAL_TOOLOW,		"station_signal_too_low"},
//	WIPS_EID_WINDOWS_AUTO_WIRELESS_CONFIG,
	{WIPS_EID_AP_GN_MODE,				"GN_mode_enabled"},
	
	{WIPS_EID_AUDIT_GRP,					"audit_category"},
	{WIPS_EID_NEW_DEVICE_AP,				"audit_new_ap"},
	{WIPS_EID_NEW_DEVICE_STA,			"audit_new_station"},
	{WIPS_EID_DEVICE_DOWN_AP,			"audit_ap_down"},
	{WIPS_EID_DEVICE_DOWN_STA,			"audit_station_down"},
	{WIPS_EID_STA_ON_NETWORK,			"audit_station_online"},
	{WIPS_EID_STA_OFF_NETWORK,			"audit_station_offline"},
	{WIPS_EID_NOASSO_DATA,				"audit_noassociate_data"},
	{WIPS_EID_AP_REBOOTED,				"audit_ap_reboot"},
	{WIPS_EID_WIRELESS_MOOCH,			"wireless_mooch"},
	{WIPS_EID_SWITCH_ESSID,				"station_switch_essid"},
	{WIPS_EID_SWITCH_BSSID,				"station_switch_bssid"},

	{WIPS_EID_INTERFERENCE_GRP,			"interference_category"},
	{WIPS_EID_FREQ_HARDWARE_ERR,		"hardware_layer_error"},
	{WIPS_EID_FREQ_HARDWARE_ERR2OK,	"hardware_layer_recover"},
	{WIPS_EID_FREQ_OVERLAPPING,			"overlapping_channel"},
//	WIPS_EID_SNR_TOOLOW,/* SNR : Signal to Noise Ratio*/
	{WIPS_EID_INTERFERENCE,				"radio_interference"},
	{WIPS_EID_INTERFERENCE_2OK,			"radio_interference_recover"},
	{WIPS_EID_SUPPRESSION,				"radio_suppression"},
	{WIPS_EID_SUPPRESSION_2OK,			"radio_suppression_recover"},
	{WIPS_EID_BITRATE_CHANGED,			"radio_bitrate_changed"},
	{WIPS_EID_RATESWITCH_TOOFAST,		"radio_bitrate_switch_toofast"},
	{WIPS_EID_AP_TOOMANY_RETRY,		"ap_too_many_retry"},
	{WIPS_EID_STA_TOOMANY_RETRY,		"station_too_many_retry"},	
	{WIPS_EID_MAX, NULL}
};

