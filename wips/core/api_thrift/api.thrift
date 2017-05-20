struct ReportEvent{  
 1: i16 eventId,
 2: string eventDesc,  
 3: string mac,
 4: string peerMac,  
}  
service ReportEventService{  
 void report(1: ReportEvent e),  
} 
