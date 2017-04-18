#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>   /* The L2 protocols */
#include <linux/if_arp.h>
#include <netinet/in.h>

#include "ieee80211.h"
#include "wipsd_wnode.h"

#include "wipsd.h"

extern wipsd_hdr_t wipsd_hdr;
const char *mac2str(unsigned char *addr); /* wlansniff.c */


static int show_timestamp(unsigned char *pos, int len)
{
//	int i;

	if (len < 8) {
		  	printf("  Timestamp: ");
		printf(" underflow!\n");
		return 0;
	}

	/*
	for (i = 7; i > 0; i--)
		printf("%02x", pos[i]);
	printf("\n");

	*/
	return 8;
}

static int show_beacon_interval(unsigned char *pos, int len)
{
	u16 *ival;
	u16 beacon_interval;

	if (len < 2) {
			printf("  Beacon interval: ");
		printf(" underflow!\n");
		return 0;
	}

	ival = (u16 *) pos;
	beacon_interval = le_to_host16(*ival);

	return 2;
}

static int show_listen_interval(unsigned char *pos, int len)
{
	u16 *ival;

	if (len < 2) {
	printf("  Listen interval: ");
		printf(" underflow!\n");
		return 0;
	}

	ival = (u16 *) pos;
	/* not needed */

	return 2;
}

static int show_status_code(unsigned char *pos, int len)
{
	u16 *ival;

	if (len < 2) {
	printf("  Status code: ");
		printf(" underflow!\n");
		return 0;
	}

	ival = (u16 *) pos;

	wipsd_hdr.status_code= le_to_host16(*ival);
	switch (le_to_host16(*ival)) {
	case WLAN_STATUS_SUCCESS:
		sprintf(wipsd_hdr.status_code_str,
		"Successful");
		break;
	case WLAN_STATUS_UNSPECIFIED_FAILURE:
		sprintf(wipsd_hdr.status_code_str,
		"Unspecified failure");
		break;
	case WLAN_STATUS_CAPS_UNSUPPORTED:
		sprintf(wipsd_hdr.status_code_str,
		"Cannot support all requested capabilities");
		break;
	case WLAN_STATUS_REASSOC_NO_ASSOC:
		sprintf(wipsd_hdr.status_code_str,
		"Reassociation denied due to inablity to confirm that "
			   "association exists");
		break;
	case WLAN_STATUS_ASSOC_DENIED_UNSPEC:
		sprintf(wipsd_hdr.status_code_str,
		"Association denied due to reason outside the scope of "
			   "802.11 standard");
		break;
	case WLAN_STATUS_NOT_SUPPORTED_AUTH_ALG:
		sprintf(wipsd_hdr.status_code_str,
		"Responding station does not support the specified "
			   "authentication algorithm");
		break;
	case WLAN_STATUS_UNKNOWN_AUTH_TRANSACTION:
		sprintf(wipsd_hdr.status_code_str,
		"Received an Authentication frame with authentication "
			   "transaction seq# out of expected sequence");
		break;
	case WLAN_STATUS_CHALLENGE_FAIL:
		sprintf(wipsd_hdr.status_code_str,
		"Authentication rejected because of challenge failure");
		break;
	case WLAN_STATUS_AUTH_TIMEOUT:
		sprintf(wipsd_hdr.status_code_str,
		"Authentication rejected due to timeout waiting for "
			   "next frame in sequence");
		break;
	case WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA:
		sprintf(wipsd_hdr.status_code_str,
		"Association denied because AP is unable to handle "
			   "additional associated stations");
		break;
	case WLAN_STATUS_ASSOC_DENIED_RATES:
		sprintf(wipsd_hdr.status_code_str,
		"Association denied due to requesting station not "
			   "supporting all of the data rates in the "
			   "BSSBasicRateSet parameter");
		break;
	case WLAN_STATUS_ASSOC_DENIED_NOSHORT:
		sprintf(wipsd_hdr.status_code_str,
		"Association denied due to requesting station not "
			   "supporting the Short Preample option[802.11b]");
		break;
	case WLAN_STATUS_ASSOC_DENIED_NOPBCC:
		sprintf(wipsd_hdr.status_code_str,
		"Association denied due to requesting station not "
			   "supporting the PBCC Modulation option[802.11b]");
		break;
	case WLAN_STATUS_ASSOC_DENIED_NOAGILITY:
		sprintf(wipsd_hdr.status_code_str,
		"Association denied due to requesting station not "
			   "supporting the Channel Agility option[802.11b]");
		break;
	default:
		sprintf(wipsd_hdr.status_code_str,
		"Reserved");
		break;
	}

	return 2;
}

static int show_reason_code(unsigned char *pos, int len)
{
	u16 *ival;

	if (len < 2) {
	printf("  Status code: ");
		printf(" underflow!\n");
		return 0;
	}

	ival = (u16 *) pos;
	wipsd_hdr.status_code= le_to_host16(*ival);
	switch (le_to_host16(*ival)) {
	case WLAN_REASON_UNSPECIFIED:
		sprintf(wipsd_hdr.status_code_str,
				"Unspecified reason");
		break;
	case WLAN_REASON_PREV_AUTH_NOT_VALID:
		sprintf(wipsd_hdr.status_code_str,
			 "Previous authentication no longer valid");
		break;
	case WLAN_REASON_DEAUTH_LEAVING:
		sprintf(wipsd_hdr.status_code_str,
		"Deauthenticated because sending station is leaving "
			   "(or has left) IBSS or ESS");
		break;
	case WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY:
		sprintf(wipsd_hdr.status_code_str,
		"Disassociated due to inactivity");
		break;
	case WLAN_REASON_DISASSOC_AP_BUSY:
		sprintf(wipsd_hdr.status_code_str,
		"Disassociated because AP is unable to handle all "
			   "currently associated stations");
		break;
	case WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA:
		sprintf(wipsd_hdr.status_code_str,
		"Class 2 frame received from nonauthenticated station");
		break;
	case WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA:
		sprintf(wipsd_hdr.status_code_str,
		"Class 3 frame received from nonassociated station");
		break;
	case WLAN_REASON_DISASSOC_STA_HAS_LEFT:
		sprintf(wipsd_hdr.status_code_str,
		"Disassociated because sending station is leaving "
			   "(or has left) BSS");
		break;
	case WLAN_REASON_STA_REQ_ASSOC_WITHOUT_AUTH:
		sprintf(wipsd_hdr.status_code_str,
		"Station requesting (re)association is not "
			   "authenticated with responding station");
		break;
	default:
		sprintf(wipsd_hdr.status_code_str,
		"Reserved/undocumented");
		break;
	}

	return 2;
}

static int show_aid(unsigned char *pos, int len)
{
	u16 *ival;

	if (len < 2) {
	printf("  Association ID (AID): ");
		printf(" underflow!\n");
		return 0;
	}

	ival = (u16 *) pos;
	wipsd_hdr.aid	 = le_to_host16(*ival);
	return 2;
}

static int show_auth_alg(unsigned char *pos, int len)
{
	u16 *ival;

	if (len < 2) {
	printf("  Authentication Algorithm Number: ");
		printf(" underflow!\n");
		return 0;
	}

	ival = (u16 *) pos;
	switch (le_to_host16(*ival)) {
	case 0:
		sprintf(wipsd_hdr.auth_str,
		"Open System");
		break;
	case 1:
		sprintf(wipsd_hdr.auth_str,
		"Shared Key");
		break;
	default:
		sprintf(wipsd_hdr.auth_str,
		"custom %u",
			 le_to_host16(*ival));
		break;
	}
	return 2;
}

static int show_auth_trans(unsigned char *pos, int len)
{
	u16 *ival;

	if (len < 2) {
	printf("  Authentication Transaction Number: ");
		printf(" underflow!\n");
		return 0;
	}

	ival = (u16 *) pos;
	/* printf("%u\n", le_to_host16(*ival)); */
	return 2;
}

static int show_current_ap(unsigned char *pos, int len)
{
	if (len < 6) {
	printf("  Current AP address): ");
		printf(" underflow!\n");
		return 0;
	printf("%s\n", mac2str(pos));
	}

	return 6;
}

static int show_capability_info(unsigned char *pos, int len)
{
	u16 *ptr, cap;

	if (len < 2) {
	printf("  Capability information: ");
		printf(" underflow!\n");
		return 0;
	}

	ptr = (u16 *) pos;
	cap = le_to_host16(*ptr);
	/*
	printf("0x%04x", cap);
	if (cap & BIT(0))
		printf(" ESS");
	if (cap & BIT(1))
		printf(" IBSS");
	if (cap & BIT(2))
		printf(" CF_Pollable");
	if (cap & BIT(3))
		printf(" CF_Poll_Request");
	if (cap & BIT(4))
		printf(" Privacy");
	if (cap & BIT(5))
		printf(" Short_Preample[802.11b]");
	if (cap & BIT(6))
		printf(" PBCC_Modulation[802.11b]");
	if (cap & BIT(7))
		printf(" Channel_Agility[802.11b]");
	if (cap & (BIT(8) | BIT(9) | BIT(10) | BIT(11) | BIT(12) | BIT(13) |
		   BIT(14)))
		printf(" Reserved!?");
	printf("\n");

	*/
	return 2;
}
#if 0
static const char *eid2str(unsigned char eid)
{
	switch (eid) {
	case WLAN_EID_SSID:
		return "Service Set Identify (SSID)";
	case WLAN_EID_SUPP_RATES:
		return "Supported rates";
	case WLAN_EID_FH_PARAMS:
		return "FH Parameter Set";
	case WLAN_EID_DS_PARAMS:
		return "DS Parameter Set";
	case WLAN_EID_CF_PARAMS:
		return "CF Parameter Set";
	case WLAN_EID_TIM:
		return "TIM";
	case WLAN_EID_IBSS_PARAMS:
		return "IBSS Parameter Set";
	case WLAN_EID_CHALLENGE:
		return "Challenge text";
	}

	if (eid >= 17 && eid <= 31)
		return "reserved EID for challenge text ext.";

	return "reserved EID";
}
#endif
static void show_elem_supp_rates(unsigned char *data, int len)
{
	int i;

	/*  dont care so just return */
	return ;
	printf("(Mbit/s) BSSBasicRateSet:");
	for (i = 0; i < len; i++) {
		if ((data[i] & BIT(7)) == 0)
			continue;
		printf(" %i", (data[i] & ~BIT(7)) / 2);
		if (data[i] & 1)
			printf(".5");
	}

	printf(" Others:");
	for (i = 0; i < len; i++) {
		if ((data[i] & BIT(7)) == BIT(7))
			continue;
		printf(" %i", (data[i] & ~BIT(7)) / 2);
		if (data[i] & 1)
			printf(".5");
	}
}

static void show_elem_fh_parms(unsigned char *data, int len)
{
	/*  dont care so just return */
	return ;
	printf("Dwell_Time=%u  Hop_Set=%u  Hop_Patterns=%u  Hop_Index=%u",
		   data[0] + 256 * data[1], data[2], data[3], data[4]);
}

static void show_elem_cf_parms(unsigned char *data, int len)
{
	/*  dont care so just return */
	return ;
	printf("CFP_Count=%u  CFP_Period=%u  CFP_MaxDuration=%u  "
		   "CFP_DurRemaining=%u", data[0], data[1],
		   data[2] + 256 * data[3], data[4] + 256 * data[5]);
}

static void show_elem_tim(unsigned char *data, int len)
{
	int i;

	/*  dont care so just return */
	return ;
	/*  dont care so just return */
	printf("DTIM_Count=%u  DTIM_Period=%u  Bitmap_Control=0x%02x  "
		   "Partial Virtual Bitmap: ", data[0], data[1],
		   data[2]);

	for (i = 3; i < len; i++)
		printf("%02x", data[i]);
}

static int show_element(unsigned char eid, unsigned char *pos, int len)
{
//	int i;
	unsigned int infolen;
	unsigned char *start;

	if (eid != pos[0])
		return 0; /* this element not present */

	infolen = pos[1];
	if (len < infolen + 2) {
	printf("\n	len=%u  ", infolen);
		printf("underflow!\n");
		return 0;
	}

	start = pos + 2;

	switch (eid) {
	case WLAN_EID_SUPP_RATES:
		show_elem_supp_rates(start, infolen);
		break;
	case WLAN_EID_FH_PARAMS:
		show_elem_fh_parms(start, infolen);
		break;
	case WLAN_EID_DS_PARAMS:
		/* printf("Current_Channel=%u", *start);*/
		break;
	case WLAN_EID_CF_PARAMS:
		show_elem_cf_parms(start, infolen);
		break;
	case WLAN_EID_TIM:
		show_elem_tim(start, infolen);
		break;
	case WLAN_EID_IBSS_PARAMS:
		printf("ATIM_Window=%u", start[0] + 256 * start[1]);
		break;
	case WLAN_EID_SSID:
		  wipsd_hdr.ssid_len=infolen+1;
		snprintf((char *)wipsd_hdr.SSID,infolen+2,"%s <<",start);
	case WLAN_EID_CHALLENGE:
	default:
		break;
	}


	return infolen + 2;
}

static int show_frame_assoc_req(unsigned char *pos, int len)
{
	int used = 0;
//		 "  Association request frame body:\n"
	used += show_capability_info(pos, len);	  //		   2
	used += show_listen_interval(pos + used, len - used);  // 2
	used += show_element(WLAN_EID_SSID, pos + used, len - used);  //reassoc_req total 4
	used += show_element(WLAN_EID_SUPP_RATES, pos + used, len - used);

	return used;
}

static int show_frame_assoc_resp(unsigned char *pos, int len)
{
	int used = 0;
	//  "  Association response frame body:\n"
	used += show_capability_info(pos, len);
	used += show_status_code(pos + used, len - used);
	used += show_aid(pos + used, len - used);
	used += show_element(WLAN_EID_SUPP_RATES, pos + used, len - used);

	return used;
}

static int show_frame_reassoc_req(unsigned char *pos, int len)
{
	int used = 0;
	// ("  Reassociation request frame body:\n");
	used += show_capability_info(pos, len);
	used += show_listen_interval(pos + used, len - used);
	used += show_current_ap(pos + used, len - used);
	used += show_element(WLAN_EID_SSID, pos + used, len - used);
	used += show_element(WLAN_EID_SUPP_RATES, pos + used, len - used);

	return used;
}

static int show_frame_reassoc_resp(unsigned char *pos, int len)
{
	int used = 0;
//	printf("  Reassociation response frame body:\n");
	used += show_capability_info(pos, len);
	used += show_status_code(pos + used, len - used);
	used += show_aid(pos + used, len - used);
	used += show_element(WLAN_EID_SUPP_RATES, pos + used, len - used);

	return used;
}

static int show_frame_probe_req(unsigned char *pos, int len)
{
	int used = 0;
//	printf("  Probe request frame body:\n");
	used += show_element(WLAN_EID_SSID, pos + used, len - used);  // probe req total 0
	used += show_element(WLAN_EID_SUPP_RATES, pos + used, len - used);

	return used;
}

static int show_frame_probe_resp(unsigned char *pos, int len)
{
	int used = 0;
//	printf("  Probe response frame body:\n");
	used += show_timestamp(pos, len);							//8
	used += show_beacon_interval(pos + used, len - used);		//2
	used += show_capability_info(pos + used, len - used);		//2
	used += show_element(WLAN_EID_SSID, pos + used, len - used);   //show probe resp total 12
	used += show_element(WLAN_EID_SUPP_RATES, pos + used, len - used);
	used += show_element(WLAN_EID_FH_PARAMS, pos + used, len - used);
	used += show_element(WLAN_EID_DS_PARAMS, pos + used, len - used);
	used += show_element(WLAN_EID_CF_PARAMS, pos + used, len - used);
	used += show_element(WLAN_EID_IBSS_PARAMS, pos + used, len - used);

	return used;
}

static int show_frame_beacon(unsigned char *pos, int len)
{
	int used = 0;
//	printf("  Beacon frame body:\n");
	used += show_timestamp(pos, len);
	used += show_beacon_interval(pos + used, len - used);
	used += show_capability_info(pos + used, len - used);
	used += show_element(WLAN_EID_SSID, pos + used, len - used);  //show beacon total 12
	used += show_element(WLAN_EID_SUPP_RATES, pos + used, len - used);
	used += show_element(WLAN_EID_FH_PARAMS, pos + used, len - used);
	used += show_element(WLAN_EID_DS_PARAMS, pos + used, len - used);
	used += show_element(WLAN_EID_CF_PARAMS, pos + used, len - used);
	used += show_element(WLAN_EID_IBSS_PARAMS, pos + used, len - used);
	used += show_element(WLAN_EID_TIM, pos + used, len - used);

	return used;
}

static int show_frame_atim(unsigned char *pos, int len)
{
//	("  IBSS Announcement Traffic Indication Message (ATIM)frame\n");
	/* frame body is null */

	return 0;
}

static int show_frame_disassoc(unsigned char *pos, int len)
{
	int used = 0;
//	printf("  Disassociation frame body:\n");
	used += show_reason_code(pos, len);

	return used;
}

static int show_frame_auth(unsigned char *pos, int len)
{
	int used = 0;
//	printf("  Authentication frame body:\n");
	used += show_auth_alg(pos, len);
	used += show_auth_trans(pos + used, len - used);
	used += show_status_code(pos + used, len - used);
	used += show_element(WLAN_EID_CHALLENGE, pos + used, len - used);
#if 0
	printf("  Auth. Alg.	Trans.  Status code  Challenge text\n");
	printf("  Open System   1	   Reserved	 Not present\n");
	printf("  Open System   2	   Status	   Not present\n");
	printf("  Shared Key	1	   Reserved	 Not present\n");
	printf("  Shared Key	2	   Status	   Present\n");
	printf("  Shared Key	3	   Reserved	 Present\n");
	printf("  Shared Key	4	   Status	   Not present\n");
#endif

	return used;
}

static int show_frame_deauth(unsigned char *pos, int len)
{
	int used = 0;
	//printf("  Deauthentication frame body:\n");
	used += show_reason_code(pos, len);

	return used;
}

int show_frame_management(unsigned int subtype, unsigned char *pos, int len)
{
	switch (subtype) {
	case WLAN_FC_STYPE_ASSOC_REQ:
		return show_frame_assoc_req(pos, len);
		break;
	case WLAN_FC_STYPE_ASSOC_RESP:
		return show_frame_assoc_resp(pos, len);
		break;
	case WLAN_FC_STYPE_REASSOC_REQ:
		return show_frame_reassoc_req(pos, len);
		break;
	case WLAN_FC_STYPE_REASSOC_RESP:
		return show_frame_reassoc_resp(pos, len);
		break;
	case WLAN_FC_STYPE_PROBE_REQ:
		return show_frame_probe_req(pos, len);
		break;
	case WLAN_FC_STYPE_PROBE_RESP:
		return show_frame_probe_resp(pos, len);
		break;
	case WLAN_FC_STYPE_BEACON:
		return show_frame_beacon(pos, len);
		break;
	case WLAN_FC_STYPE_ATIM:
		return show_frame_atim(pos, len);
		break;
	case WLAN_FC_STYPE_DISASSOC:
		return show_frame_disassoc(pos, len);
		break;
	case WLAN_FC_STYPE_AUTH:
		return show_frame_auth(pos, len);
		break;
	case WLAN_FC_STYPE_DEAUTH:
		return show_frame_deauth(pos, len);
		break;
	}

	return 0;
}
