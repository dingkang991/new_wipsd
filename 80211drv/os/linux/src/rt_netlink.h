#ifndef _RT_NETLINK_H_
#define _RT_NETLINK_H_

struct rt_assoc_info {
    u_int8_t cmd;
    u_int8_t name[IFNAMSIZ];
    u_int8_t macaddr[IEEE80211_ADDR_LEN];
};

enum {
    RT_ACTION_ASSOC_NOTIFY = 0,
    RT_ACTION_DISASSOC_NOTIFY,
    RT_ACTION_ADD_NOTIFY,
    RT_ACTION_MAX,
};

#define IWEVASSOCACTION  0x8C10

int rt_assoc_notify(wlan_if_t vap, u_int8_t *macaddr, u_int8_t cmd);

#endif /* _RT_NETLINK_H_ */

