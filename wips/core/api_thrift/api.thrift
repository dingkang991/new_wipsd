struct ReportEvent{  
 1: i16 eventId,
 2: i16 eventLibId,
 3: i64	timeNow,
 4: string eventInfo,
 5: string eventDesc,  
 6: string mac,
 7: string peerMac,
 8: string proberMac,
 9: string proberIp,
 10: string proberPort,
 11: i16 channel
 12: i16 signal
 13: i16 band 
 14: string ssid
 15: string bssid  
}  
service ReportEventService{  
 void report(1: ReportEvent e),  
} 
