#ifndef MEMSHARE_H
#define MEMSHARE_H

struct attack_share_pkt {
  int wevent_key;
  int wevent_kindnum;
  int wevent_grpnum;
};

#define MAX_SHARE_PKT_SIZE sizeof(struct attack_share_pkt)

#endif
