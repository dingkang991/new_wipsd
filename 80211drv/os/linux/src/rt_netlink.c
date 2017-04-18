/*
 *  Copyright (c) 2010, Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include "linux/if.h"
#include "linux/socket.h"
#include <net/rtnetlink.h>
#include <net/sock.h>
#include <net/iw_handler.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/cache.h>
#include <linux/proc_fs.h>
#include "if_athvar.h"
#include "rt_netlink.h"
#include "osif_private.h"

static void rt_notify(struct net_device *dev, void *info_data, u_int32_t info_len)
{
    union iwreq_data wrqu;

    if (!dev)
    {
        printk("%s-%d: dev is null!\n", __func__, __LINE__);
        return;
    }
    
    memset(&wrqu, 0, sizeof(wrqu));

    wrqu.data.length = info_len;

    wireless_send_event(dev, IWEVASSOCACTION, &wrqu, (char *)info_data);

    return;
}

int rt_assoc_notify(wlan_if_t vap, u_int8_t *macaddr, u_int8_t cmd)
{
    struct net_device *dev;
    struct rt_assoc_info info; 

    if (!vap)
    {
        printk("%s-%d: vap is null!\n", __func__, __LINE__);
        return -1;
    }
    
    info.cmd = cmd;
    dev = ((osif_dev *)vap->iv_ifp)->netdev;
    strcpy(info.name, dev->name);
    memcpy(info.macaddr, macaddr, IEEE80211_ADDR_LEN);

    rt_notify(dev, &info, sizeof(info));

    return 0;
}

EXPORT_SYMBOL(rt_assoc_notify);

