// prismprint.c

#include <stdio.h>

#include <stdlib.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <netinet/in.h>


#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>   /* The L2 protocols */
#include <linux/if_arp.h>

#include <sqlite3.h>


#define MAX_BUFFER_SIZE 4000	/* Size of receive buffer */
#define WTAP_PKTHDR_SIZE (sizeof(struct wtap_pkthdr)-4)
#define ROWWIDTH	32

#define MAXASSOTIME	  600  // seconds
#define MAXASSO		  10  // max associations in Maxassotime cause an alert


#define MAXDEAUTHTIME	  600  // seconds
#define MAXDEAUTH		 10  // max associations in Maxassotime cause an alert

#include "ieee80211.h"
#include "wipsd_wnode.h"

#include "wipsd.h"






int use_ssid_blacklist=0;
int use_mac_blacklist=0;
int use_scripts=0;

int use_mac_whitelist=0;

char   badssids[500] ;
char   badmacs[500] ;
char   goodmacs[500] ;


int DEBUG;


#define BADSSIDFILE "./badsids"
#define BADMACFILE "./badmacs"
#define GOODMACFILE "./goodmacs"
#define wipsdSCRIPTS "./scripts/*.sh"
#define PROBEMONCONF "./probemon.conf"







struct wtap_pkthdr
{
  struct timeval ts;
  __u32 caplen;
  __u32 len;
  int pkt_encap;
};

  frame_control_t *fc;

wipsd_hdr_t wipsd_hdr;
char pritty[2];

/*
 *	for dumping the frame in hex
 */
char dummybuf[20];
char *
hexdump (__u8 * x, int y)
{
	int i = -1;
	while (++i < y)
		sprintf (&dummybuf[(i * 2)], "%02x", x[i]);
	return (dummybuf);
}


unsigned char msgbuf[MAX_BUFFER_SIZE];
int nullssid;
char  macaddress_1[13];
char  macaddress_2[13];
char  macaddress_3[13];
char  macaddress_4[13];
char  trackmac[13];
char  buffer[90];
char  packet_type[13];
char  packet_subtype[13];
//*********************************************************************************
//*********************************************************************************
  // clean subroutine a botch to remove shell escapes designed to remove
char * cleanit (  char * clean)
{
	char * temp_ptr;

	while ( (temp_ptr = strpbrk( clean, ";'&!|`)") ) )
	{
		*temp_ptr = '.';
	}
	return clean;
}
//*********************************************************************************
//*********************************************************************************
// call alert  scripts
void do_alert ( char * mess, char * wipsdssid , char *  macaddress_1,
		   char * dress_2, char * macaddress_3, char * macaddress_4)
{
	int ret;
	setenv ("wipsdSSID", cleanit( wipsdssid) ,1);
	setenv ("wipsdMSG", mess, 1);
	setenv ("wipsdPACKETTYPE", packet_subtype, 1);
	setenv ("wipsdMAC1", macaddress_1, 1);
	setenv ("wipsdMAC2", macaddress_2,1);
	setenv ("wipsdMAC3", macaddress_3,1);
	setenv ("wipsdMAC4", macaddress_4,1);

	ret = system ("Alert");
}

//*********************************************************************************
//*********************************************************************************

void get_packettype( int type,int subtype)
{

 	 char *typestring[4] = { "Management", "Control", "Data", "Reserved" };

	/*
 	* subtype lookup vectors
 	*/
 	 char *mgmtsubtypestring[16] = { "Association Request", "Association Response",
									"ReAssociation Request", "Reassociation Response", "Probe Request",
									"Probe Response", "Reserved", "Reserved", "Beacon", "ATIM",
									"Disassociation", "Authentication", "Deauthentication", "Reserved",
									"Reserved", "Reserved"
									};

  	char *ctrlsubtypestring[16] = { "Reserved", "Reserved", "Reserved", "Reserved",
									"Reserved", "Reserved", "Reserved", "Reserved", "Reserved", "Reserved",
									"PS-Poll", "RTS", "CTS", "ACK", "CF End", "CF End + CF Ack"
									};

  	char *datasubtypestring[16] = { "Data", "Data + CF Ack", "Data + CF Poll",
									"Data + CF Ack + CF Poll", "NULL Data", "CF Ack (no data)",
									"CF Poll (no data)", "Data + CF Ack + CF Poll ", "Qos Data",
									"Qos Data + CF Ack", "Qos Data + CF Poll",
									"Qos Data  + Qos Ack + Qos Poll", "Qos Null (no data)", "Qos CF Ack (no data)",
									"Qos CF Poll (no data)", "Qos CF Ack + Qos CF Poll(no data)"};

	sprintf (packet_type,"%s",typestring[type]);
	switch (type)
	{
		case 0:
			printf("subtype value is %d\n",subtype);
#if 0
			int j;
			for(j=0;j<16;j++)
			printf("mgtsubtype[%d] string is %s\n",j,mgmtsubtypestring[subtype]);
#endif
			sprintf (packet_subtype,"%s",mgmtsubtypestring[subtype]);
			break;
		case 1:
			sprintf (packet_subtype,"%s",ctrlsubtypestring[subtype]);
			break;
		case 2:
			sprintf (packet_subtype,"%s",datasubtypestring[subtype]);
			break;
		case 3:
			sprintf (packet_subtype,"Reserved%u",subtype);
			break;
		default:
			break;
	}
	/*xxx-stub1*/
	printf("packet type -> %s\npacket subtype ->%s\n",packet_type,packet_subtype);
	/*end*/

}
void		print_packet()
{


	//  print
	printf ("\n \n%i/%i %i:%i:%i.%i ", wipsd_hdr.timep->tm_mday
	,  wipsd_hdr.timep->tm_mon   + 1
	,  wipsd_hdr.timep->tm_hour
	,  wipsd_hdr.timep->tm_min
	,  wipsd_hdr.timep->tm_sec
	,0);
	strncpy (pritty, "  ", 2);
	printf("\n");
	printf (" control:type:%s ",packet_type);
	printf ("%s",pritty);
	printf("\n");
	printf (" subtype: %s ",packet_subtype);
	printf ("%s",pritty);
	printf("\n");
	printf (" mac-address-1:0x%s ",
			hexdump((unsigned char *)&wipsd_hdr.mac1,6));
	printf ("%s",pritty);
	printf("\n");
	printf (" mac-address-2:0x%s",
			hexdump((unsigned char *)&wipsd_hdr.mac2,6));
	printf ("%s",pritty);
	printf("\n");
	printf (" mac-address-3:0x%s ",
			hexdump((unsigned char *)&wipsd_hdr.mac3,6));
	printf ("%s",pritty);
	printf("\n");
	printf (" mac-address-4:0x%s ",
			hexdump((unsigned char *)&wipsd_hdr.mac4,6));
	printf ("%s",pritty);
	printf("\n");
	printf (" SSID %s ",
			wipsd_hdr.SSID  );
	printf ("\n");

	printf ("%s",pritty);
	printf("\n");
	printf (" duration-id:%u (0x%s) ",
			wipsd_hdr.duration_id,
		hexdump((unsigned char *) &wipsd_hdr.duration_id,2));
	printf ("%s",pritty);
	printf("\n");

}
//*********************************************************************************
//*********************************************************************************
void probe_mon ()
{
  	int   n = 0;
 	time_t  oassoc_time = 999999999;
  	time_t  odeauth_time = 999999999;
  	int naughty_packets=0;
	int   assoc_counter =  0;
	int   deauth_counter =  0;
	int ret;
	// after a null probe log the next 100 packets from that source
	n++;
	//(wipsd_hdr.frame_control[0] & 0x0c) |(wipsd_hdr.frame_control[0] & 0xf0)

	//fc = (frame_control_t *) &wipsd_hdr.frame_control;
	printf("wipsd_hdr.frame_control[0]*0x0c>>2 value is %d\n",(wipsd_hdr.frame_control[0] & 0x0c)>>2);
	printf("wipsd_hdr.frame_control[0]&0xf0>>4 value is %d\n",(wipsd_hdr.frame_control[0] & 0xf0)>>4);
	get_packettype((wipsd_hdr.frame_control[0] & 0x0c)>>2,(wipsd_hdr.frame_control[0] & 0xf0)>>4);

	if (oassoc_time == 999999999)
	{
	  		oassoc_time = wipsd_hdr.ts.tv_sec;
	}

	if (odeauth_time == 999999999)
	{
		odeauth_time = wipsd_hdr.ts.tv_sec;
	}

	//sprintf (macaddress_1,"%s", hexdump((unsigned char *)&wipsd_hdr.mac1,6));/*twice, wrong???*/
	sprintf (macaddress_1,"%s", hexdump((unsigned char *)&wipsd_hdr.mac1,6));
	sprintf (macaddress_2,"%s", hexdump((unsigned char *)&wipsd_hdr.mac2,6));
	sprintf (macaddress_3,"%s", hexdump((unsigned char *)&wipsd_hdr.mac3,6));
	//sprintf (macaddress_4,"%s", hexdump((unsigned char *)&wipsd_hdr.mac4,6));
//	get_packettype(fc->type,fc->subtype);
	  /*xxx-stub2*/
	printf("mac1 --> %s\nmac2 --> %s\nmac3 --> %s\n",macaddress_1,macaddress_2,macaddress_3);
	return;
	  /*end*/
	//  alert any bad macs

	if (  use_mac_blacklist == 1 )
   	{
   		if ( (  strstr(badmacs, macaddress_1) != NULL )  ||
		 	 	(  strstr(badmacs, macaddress_2) != NULL )  ||
		 	 	(  strstr(badmacs, macaddress_3) != NULL )  )
	 		{
		 		print_packet();
		 		printf ("\n BLACKLIST mac  ");

	  			sprintf (buffer," Alert Blacklist mac  %s %s %s %s %s'",
					wipsd_hdr.SSID,
					macaddress_1,
					macaddress_2,
					macaddress_3,
					macaddress_4);
	 			do_alert(" Alert Blacklist mac  ", (char *) wipsd_hdr.SSID,
					macaddress_1,
					macaddress_2,
					macaddress_3,
					macaddress_4);
			}
 	 }

//  alert any  non good  macs

	if (  use_mac_whitelist == 1 )
   	{
   		if ( (  strstr(goodmacs, macaddress_1) != NULL )  &&
		  		(  strstr(goodmacs, macaddress_2) != NULL )  )
	 		{
				// just do nada
			 }
		 else
	 		{
	 			print_packet();
	 			printf ("\n non white LIST mac  ");
	 			// sprintf (buffer," Alert 'NON whitelist mac  %s %s %s %s %s'", wipsd_hdr.SSID, macaddress_1, macaddress_2, macaddress_3, macaddress_4);
	 			do_alert (" Alert NON whitelist mac  ", (char *) wipsd_hdr.SSID,
	 				macaddress_1,
	 				macaddress_2,
	 				macaddress_3,
	 				macaddress_4);
			}
  	}
//  alert any bad SSIDS
	 if ( use_ssid_blacklist==1  &&  fc->type == 0  )  //  probe  packets
	{
		if (  strstr(badssids,(const char *)wipsd_hdr.SSID) != NULL )
	 		{
	 			print_packet();
				printf ("\n BLACKLIST ssid ");
	 			do_alert (" Alert Blacklist SSID ",
					(char *) wipsd_hdr.SSID,
					macaddress_1,
					macaddress_2,
					macaddress_3,
					macaddress_4);
			}

	}

//
//  alert
//  alert was going to open /proc/net/wireless
//  to look at link quality and alert but
//  while in monitor mod this does not get updated
//


// after a null probe log the next 100 packets from that source

	if ( (  strcmp(trackmac, macaddress_1) == 0 )  ||
		  	(  strcmp(trackmac, macaddress_2) == 0 )  ||
		  	(  strcmp(trackmac, macaddress_3) == 0 )  ||
		  	(  strcmp(trackmac, macaddress_4) == 0 )  )
	 	{
	 		print_packet();
	 		naughty_packets++;
	 		if ( naughty_packets  > 100 )
		 	{
		  		strcpy(trackmac, "xxxxxxxxxxxx");
		  		naughty_packets=0;
	 	}
	 	}
// alerts
	if (fc->type == 0)
	{
		// alert1
		//	   Alert if the essid is empty
		if ( fc->subtype == 4)  //  probe  packets
		{
  			if ( wipsd_hdr.ssid_len < 2 )
	   	{
	   		do_alert (" Alert Null Probe ", (char *) wipsd_hdr.SSID,
				macaddress_1,
				macaddress_2,
				macaddress_3,
				macaddress_4);
		  		print_packet();
		   		strcpy(trackmac, macaddress_1);
	   	}

		}

	}


// alerts
//			fata jack
	if (fc->type == 0)
	{
		// alert
		if ( fc->subtype == 11)  //  auth  packets
		{
  			if (strstr ( wipsd_hdr.auth_str,"custom") != NULL )
	   		{
	 				print_packet();
	 				printf ("\n Custom Auth method in use possible fatajack attack");
	 				do_alert (" Alert Poss FataJack '", (char *) wipsd_hdr.SSID,
						macaddress_1,
						macaddress_2,
						macaddress_3,
						macaddress_4);
				}
		}
	}

// alerts
	if (fc->type == 0)
   	{
   		if (	strstr (packet_subtype, "Response") > 0)
	  		{
	  			if ( wipsd_hdr.status_code > 0 )  //  error packets
			{
					print_packet();
					printf ("\n We failed to auth associate dissociate or something");
					do_alert ("Alert Command failled", (char *) wipsd_hdr.SSID,
						macaddress_1,
						macaddress_2,
						macaddress_3,
						macaddress_4);
		 		}
	  		}
   	}
//
// set up env
// so that scripts
// can process record

	if ( use_scripts == 1)
	{
	   setenv ("wipsdSSID", (const char *)wipsd_hdr.SSID,1);
	   setenv ("wipsdPACKETTYPE", packet_subtype, 1);
	   setenv ("wipsdMAC1", macaddress_1, 1);
	   setenv ("wipsdMAC2", macaddress_2,1);
	   setenv ("wipsdMAC3", macaddress_3,1);
	   setenv ("wipsdMAC4", macaddress_4,1);
	   sprintf (buffer,"sh %s ", wipsdSCRIPTS);

	   ret = system (buffer);
	  }



// alert
//
//		alert if more then MAXASSO occur in
//						   Maxasso time
	if ( fc->subtype == 0)  //  association packet
		{
			if ( assoc_counter == 0  )  //  only first time round
	   		oassoc_time = wipsd_hdr.ts.tv_sec;

			assoc_counter++;
// if in MAXASSO number of association request
//   less the MAXASSOTIME seconds have transpired
//   you are being flooded
//
			if ( assoc_counter > MAXASSO   )  //  probe  packets
	  		{
				oassoc_time = wipsd_hdr.ts.tv_sec;
				assoc_counter =  1;

				if ( difftime( wipsd_hdr.ts.tv_sec , oassoc_time) < MAXASSOTIME )
			{
		  			do_alert (" Alert association flood ", (char *) wipsd_hdr.SSID,
						macaddress_1,
						macaddress_2,
						macaddress_3,
						macaddress_4);
		   		}
	   	}
	 }
//

// alert
//
//		alert if more then MAXdeauth  occur in
//						   Maxdeauth  time
	if ( fc->subtype == 12 )  //  deAUTH	  packet
		{
			if (  deauth_counter == 0  )  //  only first time round
	   	odeauth_time = wipsd_hdr.ts.tv_sec;

			deauth_counter++;
// if in MAXdeauth  number of deauth request
//   less the MAXdeauthtiME seconds have transpired
//   you are being WLANJACKED
//
   	 	if ( deauth_counter > MAXDEAUTH )  //  deauth   packets
			{
				odeauth_time = wipsd_hdr.ts.tv_sec;
	   		 deauth_counter =  1;

				if ( difftime( wipsd_hdr.ts.tv_sec , odeauth_time) < MAXDEAUTHTIME )
		   		{
		   			do_alert ( " Alert WLANJACk flood ", (char *) wipsd_hdr.SSID,
						macaddress_1,
						macaddress_2,
						macaddress_3,
						macaddress_4);
		   		}
			}
		 }
//
//
// end loop
//
//
//
	printf ("\n");
}






/**************************************************
 Load memory
 **************************************************/
void
loadpattern(char *p, int len , char *CONF_FILE )
  {
  char target[100];
  int i;
  FILE *ff;

  if ( (ff=fopen(CONF_FILE,"r")) == NULL )
	perror("file");


   for (i=0; i < len; i++)
	 {
	 if ( fgets(target, 80 , ff) == NULL )
	{
	return ;
	}
	  strcat(p,target) ;

	  if ( DEBUG )
		 printf("Debug: Loadpattern() loading index# %i with  pattern=%s \n",i, (char *)target) ;
	 }
		 fclose(ff);
  }
/**************************************************
  *read 'probemon.conf' switch status and read config information about good/bad mac/ssid  enable script
 **Y************************************************/
#if 0 /*closed*/
void init()
{
  FILE *ff;
  char buffy[100];

  if ( (ff=fopen(PROBEMONCONF,"r")) == NULL )
	perror("file probemon.conf");

while( fgets(buffy, 80 , ff) != NULL )
	{
		if (  strchr(buffy,'#') != NULL )
		continue;
		if (  strstr(buffy,"usebadmacs=y") != NULL )
	   {
			use_mac_blacklist=1;
	   loadpattern(badmacs, 500			, BADMACFILE);
	   printf("HHH %s\n", "usebadmacs=y");
	   printf("HHH %s\n", badmacs);
	   }
	//
	//
	//
		if (  strstr(buffy,"usegoodmacs=y") != NULL )
	   {
			use_mac_whitelist=1;
	   loadpattern(goodmacs, 500			, GOODMACFILE);
	   printf("HHH %s\n", "usegoodmacs=y");
	   printf("HHH %s\n", goodmacs);
	   }
	//
	//
	//
		if (  strstr(buffy,"usebadssids=y") != NULL )
	   {
			use_ssid_blacklist=1;
		loadpattern(badssids, 500			, BADSSIDFILE);
			printf("HHH %s\n","usebadssids=y");
			printf("HHH %s\n", badssids);
	   }
		if (  strstr(buffy,"usescripts=y") != NULL )
	   {
			use_scripts=1;
			printf("HHH %s\n", "usescripts=y");

	   }
		 }
		 fclose(ff);
}
#else
#if 0
void init(const char *interface_name)
{

	int ret;
	sqlite3 *sql;

	/* check tools <for adding> */
	//check sqlite & check wireless_security.db & check ap_table sta_table action_table
	//.wlanconfig	create a monitor

	//read conf file

	// check/set	sqlite
	// check/set	*.db file
	//open a db file or create a db file
	// check/set	table
	ret = sqlite3_open(DB_FILE,&sql);
	if(ret != SQLITE_OK){
		printf("++++++++++++++ sqlite err !!!");
		//exit programe
		exit(1);
	}

	ret = -sqlite3_exec(sql,DROP_AP_LIST,NULL,NULL,NULL);
	ret = -sqlite3_exec(sql,CREATE_AP_LIST,NULL,NULL,NULL);

	ret = -sqlite3_exec(sql,DROP_STA_LIST,NULL,NULL,NULL);
	ret = -sqlite3_exec(sql,CREATE_STA_LIST,NULL,NULL,NULL);

	ret = -sqlite3_exec(sql,DROP_MANAGEMENT_LIST,NULL,NULL,NULL);
	ret = -sqlite3_exec(sql,CREATE_MANAGEMENT_LIST,NULL,NULL,NULL);

	wipsd_sqlite3_close(sql);

	if(access(WIPS_LOG_DB,F_OK)) {
		ret = sqlite3_open(WIPS_LOG_DB, &sql);
		if(ret != SQLITE_OK){
			printf("open sqlite table wips_log.db failed!");
			exit(1);
		}

		ret = -sqlite3_exec(sql, "drop table wips_event", NULL, NULL, NULL);
		ret = -sqlite3_exec(sql, "create table wips_event( bssid nvarchar( 24 ), mac nvarchar( 24 ), channel varchar( 4 ),  "
			"ipaddr nvarchar( 16 ), vendor nvarchar(128), alert nvarchar( 32 ), permit nvarchar(4), pri nvarchar(8), "
			" up_time TIMESTAMP default (datetime('now', 'localtime')), id nvarchar(4), is_grp nvarchar(4), grp_id nvarchar(4))", NULL, NULL, NULL);

		wipsd_sqlite3_close(sql);
	}

	ret = system("/sbin/ifconfig ath0 down");
	ret = system("/usr/hls/bin/wlanconfig ath0 destroy");
	ret = system("/usr/hls/bin/wlanconfig ath0 create wlandev wifi0 wlanmode monitor");
	ret = system("/usr/hls/bin/iwconfig ath0 ch 1");
	ret = system("/sbin/ifconfig ath0 up");
	ret = system("/sbin/ifconfig ath0 promisc");

	ret = sqlite3_open("/usr/hls/log/log/wconfig.db",&sql);
	if(ret != SQLITE_OK){
		printf("++++++++++++++ sqlite err !!!");
		//exit programe
		exit(1);
	}

	sqlite3_exec(sql,"drop table wevent",NULL,NULL,NULL);
	sqlite3_exec(sql,"CREATE TABLE wevent(id nvarchar(4), is_grp nvarchar(4), grp_id nvarchar(4), pri nvarchar(8), name nvarchar(32),desc nvarchar(512),ref nvarchar(128));",NULL,NULL,NULL);
//起始ID不能变，ID必须顺序增加
	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"name\") values (\"1\", \"1\", \"0\", \"全部\")",NULL,NULL,NULL);

	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"name\") values (\"2\", \"1\", \"1\", \"错误配置类\")",NULL,NULL,NULL);
	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"pri\", \"name\",\"desc\") values (\"3\", \"0\", \"2\", \"高\", \"未设置加密方式\", \"未设置加密方式的AP为开放系统，任何客户端均可访问。\");",NULL,NULL,NULL);
	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"pri\", \"name\",\"desc\") values (\"4\", \"0\", \"2\", \"高\", \"加密方式为WEP\", \"WEP由于加密强度不够，是一种可以被轻易破解的加密方式。\");",NULL,NULL,NULL);
	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"pri\", \"name\",\"desc\") values (\"5\", \"0\", \"2\", \"低\", \"WPS功能开启\", \"WPS开启过程中，AP增加了受到黑客攻击的可能性。\");",NULL,NULL,NULL);
	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"pri\", \"name\",\"desc\") values (\"6\", \"0\", \"2\", \"低\", \"AP开启WDS功能\", \"WDS开启之后，AP增加了受到黑客攻击的可能性。\");",NULL,NULL,NULL);
	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"pri\", \"name\",\"desc\") values (\"7\", \"0\", \"2\", \"低\", \"STA开启WDS功能\", \"WDS开启之后，客户端增加了受到黑客攻击的可能性。\");",NULL,NULL,NULL);
	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"pri\", \"name\",\"desc\") values (\"8\", \"0\", \"2\", \"低\", \"Ad-hoc设备\", \"工作在Ad-hoc模式的无线设备，Ad-hoc允许两台无线设备直接相连，给内网安全带来隐患。\");",NULL,NULL,NULL);

	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"name\") values (\"9\", \"1\", \"1\", \"流氓AP类\")",NULL,NULL,NULL);
	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"pri\", \"name\",\"desc\") values (\"10\", \"0\", \"9\", \"中\", \"未授权AP\", \"未经无线安全策略许可的AP，通常为私自架设，给内网安全带来隐患。\");",NULL,NULL,NULL);
	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"pri\", \"name\",\"desc\") values (\"11\", \"0\", \"9\", \"高\", \"非法信道AP\", \"工作在非802.11合法信道的AP，非法信道通常位于合法信道之间或之外，由于可逃避多数无线安全设备的检测，该威胁较为隐蔽。\");",NULL,NULL,NULL);
	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"pri\", \"name\",\"desc\") values (\"12\", \"0\", \"9\", \"高\", \"代理AP\", \"通过无线客户端代理无线接入点，信息泄露风险较大。\");",NULL,NULL,NULL);

	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"name\") values (\"13\", \"1\", \"1\", \"无线扫描探测类\");",NULL,NULL,NULL);
	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"pri\", \"name\",\"desc\") values (\"14\", \"0\", \"13\", \"低\", \"NetStumbler扫描\", \"Netstumbler是知名的扫描无线接入点的工具，用于获取无线网络SSID、加密方式、MAC地址等详细信息，恶意攻击着通常用来收集网络信息，为攻击做准备。\");",NULL,NULL,NULL);

	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"name\") values (\"15\", \"1\", \"1\", \"无线欺骗类\");",NULL,NULL,NULL);
	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"pri\", \"name\",\"desc\") values (\"16\", \"0\", \"15\", \"中\", \"钓鱼AP\", \"通过伪造信息来搭设钓鱼AP，用于仿冒内网合法AP，欺骗无线用户与其关联，攻击者通常会试图获取无线客户的网络加密信息，如果钓鱼成功，更可继续获得更多有价值的信息。\");",NULL,NULL,NULL);
	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"pri\", \"name\",\"desc\") values (\"17\", \"0\", \"15\", \"中\", \"HotSpotter攻击\", \"通过监听客户端的探测帧，利用自身的常用热点SSID构造假冒AP，允许客户端认证和关联，建立连接后发起下一步攻击。\");",NULL,NULL,NULL);

	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"name\") values (\"18\", \"1\", \"1\", \"无线DOS攻击类\");",NULL,NULL,NULL);
	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"pri\", \"name\",\"desc\") values (\"19\", \"0\", \"18\", \"中\", \"DeAuthentication攻击\", \"攻击者通过仿造无线客户地址大量发送去认证报文，使得无线用户的合法接入招到破坏，影响网络使用。\");",NULL,NULL,NULL);
	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"pri\", \"name\",\"desc\") values (\"20\", \"0\", \"18\", \"中\", \"DeAssociation攻击\", \"攻击者通过仿造无线客户地址大量发送去关联报文，使得无线用户的合法接入招到破坏，影响网络使用。\");",NULL,NULL,NULL);
	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"pri\", \"name\",\"desc\") values (\"21\", \"0\", \"18\", \"中\", \"认证帧泛洪攻击\", \"攻击者大量发送虚假的认证报文，使得无线接入点工作出现异常或网络繁忙，影响网络的正常使用。\");",NULL,NULL,NULL);
	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"pri\", \"name\",\"desc\") values (\"22\", \"0\", \"18\", \"中\", \"关联帧泛洪攻击\", \"攻击者大量发送虚假的关联报文，使得无线接入点工作出现异常或网络繁忙，影响网络的正常使用。\");",NULL,NULL,NULL);
	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"pri\", \"name\",\"desc\") values (\"23\", \"0\", \"18\", \"中\", \"管理帧泛洪攻击\", \"攻击者大量发送虚假的管理报文，使得无线接入点工作出现异常或网络繁忙，影响网络的正常使用。\");",NULL,NULL,NULL);
	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"pri\", \"name\",\"desc\") values (\"24\", \"0\", \"18\", \"中\", \"探测帧泛洪攻击\", \"攻击者大量发送虚假的探测报文，使得无线接入点工作出现异常或网络繁忙，影响网络的正常使用。\");",NULL,NULL,NULL);
	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"pri\", \"name\",\"desc\") values (\"25\", \"0\", \"18\", \"中\", \"关联帧ACK泛洪攻击\", \"攻击者大量发送关联ACK报文，使得无线接入点工作出现异常或网络繁忙，影响网络的正常使用。\");",NULL,NULL,NULL);
	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"pri\", \"name\",\"desc\") values (\"26\", \"0\", \"18\", \"中\", \"关联帧RTS泛洪攻击\", \"攻击者大量发送关联RTS报文，使得无线接入点工作出现异常或网络繁忙，影响网络的正常使用。\");",NULL,NULL,NULL);
	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"pri\", \"name\",\"desc\") values (\"27\", \"0\", \"18\", \"中\", \"关联帧CTS泛洪攻击\", \"攻击者大量发送关联CTS报文，使得无线接入点工作出现异常或网络繁忙，影响网络的正常使用。\");",NULL,NULL,NULL);

	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"name\") values (\"28\", \"1\", \"1\", \"异常无线报文类\");",NULL,NULL,NULL);
	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"pri\", \"name\",\"desc\") values (\"29\", \"0\", \"28\", \"低\", \"NullProbeResponse\", \"非法无线报文，可能存在攻击行为，并影响无线网络性能。\");",NULL,NULL,NULL);

	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"name\") values (\"30\", \"1\", \"1\", \"无线破解类\");",NULL,NULL,NULL);
	sqlite3_exec(sql,"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"pri\", \"name\",\"desc\") values (\"31\", \"0\", \"30\", \"中\", \"无线暴力破解\", \"攻击者通过使用攻击字典进行暴力破解，试图获取无线用户接入网络的加密信息。\");",NULL,NULL,NULL);

	wipsd_sqlite3_close(sql);

	ret = system("chmod 777 /usr/hls/log/log/beacon_test.db");
	ret = system("chmod 777 /usr/hls/log/log/wconfig.db");
	ret = system("chmod 777 /usr/hls/log/log/wips_log.db");

}
#endif
#endif
/**************************************************
	loadpattern(badmacs, sizeof(badmacs), BADMACFILE);
 *
 *
 ************************************************/
