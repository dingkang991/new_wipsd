#include "io_support.h"
#include "getopt.h"
#include "ieee80211.h"
#include "wipsd_parse.h"
#include "main.h"
//#include "hostap_wlan.h"

#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)


int wipsd_ieee80211_frequency_to_channel(int freq)
{
	if (freq == 2484)
		return 14;

	if (freq < 2484)
		return (freq - 2407) / 5;

	/* FIXME: dot11ChannelStartingFactor (802.11-2007 17.3.8.3.2) */
	if (freq < 45000)
		return freq/5 - 1000;

	if (freq >= 58320 && freq <= 64800)
		return (freq - 56160) / 2160;

	return 0;
}

int wipsd_ieee80211_frequency_to_band(int freq)
{
	if (freq == 2484)
		return 2;

	if (freq < 2484)
		return 2;

	/* FIXME: dot11ChannelStartingFactor (802.11-2007 17.3.8.3.2) */
	if (freq < 45000)
		return 5;

	if (freq >= 58320 && freq <= 64800)
		return 5;

	return 0;
}



int wipsd_ieee80211_radiotap_iterator_init(struct ieee80211_radiotap_iterator *iterator,
										    struct ieee80211_radiotap_header *radiotap_header,
										    int max_length)
{
	/* Linux only supports version 0 radiotap format */
	if (radiotap_header->it_version)
		return -EINVAL;

	/* sanity check for allowed length and radiotap length field */
	if (max_length < __le16_to_cpu(get_unaligned(&radiotap_header->it_len)))
		return -EINVAL;

	iterator->rtheader = radiotap_header;
	iterator->max_length = __le16_to_cpu(get_unaligned(&radiotap_header->it_len));
	iterator->arg_index = 0;
	iterator->bitmap_shifter = __le32_to_cpu(get_unaligned(&radiotap_header->it_present));
	iterator->arg = (u8 *)radiotap_header + sizeof(*radiotap_header);
	iterator->this_arg = NULL;

	/* find payload start allowing for extended bitmap(s) */
	if (unlikely(iterator->bitmap_shifter & (1<<IEEE80211_RADIOTAP_EXT))) {
		while (__le32_to_cpu(get_unaligned((__le32 *)iterator->arg)) &
				   (1<<IEEE80211_RADIOTAP_EXT)) {
			iterator->arg += sizeof(u32);

			/*
			 * check for insanity where the present bitmaps
			 * keep claiming to extend up to or even beyond the
			 * stated radiotap header length
			 */

			if (((ulong)iterator->arg - (ulong)iterator->rtheader)
			    > (ulong)iterator->max_length)
				return -EINVAL;
		}

		iterator->arg += sizeof(u32);

		/*
		 * no need to check again for blowing past stated radiotap
		 * header length, because ieee80211_radiotap_iterator_next
		 * checks it before it is dereferenced
		 */
	}

	/* we are all initialized happily */

	return 0;
}


/**
 * ieee80211_radiotap_iterator_next - return next radiotap parser iterator arg
 * @iterator: radiotap_iterator to move to next arg (if any)
 *
 * Returns: 0 if there is an argument to handle,
 * -ENOENT if there are no more args or -EINVAL
 * if there is something else wrong.
 *
 * This function provides the next radiotap arg index (IEEE80211_RADIOTAP_*)
 * in @this_arg_index and sets @this_arg to point to the
 * payload for the field.  It takes care of alignment handling and extended
 * present fields.  @this_arg can be changed by the caller (eg,
 * incremented to move inside a compound argument like
 * IEEE80211_RADIOTAP_CHANNEL).  The args pointed to are in
 * little-endian format whatever the endianess of your CPU.
 *
 * Alignment Gotcha:
 * You must take care when dereferencing iterator.this_arg
 * for multibyte types... the pointer is not aligned.  Use
 * get_unaligned((type *)iterator.this_arg) to dereference
 * iterator.this_arg for type "type" safely on all arches.
 */

int wipsd_ieee80211_radiotap_iterator_next(struct ieee80211_radiotap_iterator *iterator)
{

	/*
	 * small length lookup table for all radiotap types we heard of
	 * starting from b0 in the bitmap, so we can walk the payload
	 * area of the radiotap header
	 *
	 * There is a requirement to pad args, so that args
	 * of a given length must begin at a boundary of that length
	 * -- but note that compound args are allowed (eg, 2 x u16
	 * for IEEE80211_RADIOTAP_CHANNEL) so total arg length is not
	 * a reliable indicator of alignment requirement.
	 *
	 * upper nybble: content alignment for arg
	 * lower nybble: content length for arg
	 */

	static const u8 rt_sizes[] = {
		[IEEE80211_RADIOTAP_TSFT] = 0x88,
		[IEEE80211_RADIOTAP_FLAGS] = 0x11,
		[IEEE80211_RADIOTAP_RATE] = 0x11,
		[IEEE80211_RADIOTAP_CHANNEL] = 0x24,
		[IEEE80211_RADIOTAP_FHSS] = 0x22,
		[IEEE80211_RADIOTAP_DBM_ANTSIGNAL] = 0x11,
		[IEEE80211_RADIOTAP_DBM_ANTNOISE] = 0x11,
		[IEEE80211_RADIOTAP_LOCK_QUALITY] = 0x22,
		[IEEE80211_RADIOTAP_TX_ATTENUATION] = 0x22,
		[IEEE80211_RADIOTAP_DB_TX_ATTENUATION] = 0x22,
		[IEEE80211_RADIOTAP_DBM_TX_POWER] = 0x11,
		[IEEE80211_RADIOTAP_ANTENNA] = 0x11,
		[IEEE80211_RADIOTAP_DB_ANTSIGNAL] = 0x11,
		[IEEE80211_RADIOTAP_DB_ANTNOISE] = 0x11,
		[IEEE80211_RADIOTAP_RX_FLAGS] = 0x22,
		[IEEE80211_RADIOTAP_TX_FLAGS] = 0x22,
		[IEEE80211_RADIOTAP_RTS_RETRIES] = 0x11,
		[IEEE80211_RADIOTAP_DATA_RETRIES] = 0x11,
		/*
		 * add more here as they are defined in
		 * include/net/ieee80211_radiotap.h
		 */
	};

	/*
	 * for every radiotap entry we can at
	 * least skip (by knowing the length)...
	 */
	while (iterator->arg_index < (int) sizeof(rt_sizes)) {
		int hit = 0;
		int pad;

		if (!(iterator->bitmap_shifter & 1))
			goto next_entry; /* arg not present */

		/*
		 * arg is present, account for alignment padding
		 *  8-bit args can be at any alignment
		 * 16-bit args must start on 16-bit boundary
		 * 32-bit args must start on 32-bit boundary
		 * 64-bit args must start on 64-bit boundary
		 *
		 * note that total arg size can differ from alignment of
		 * elements inside arg, so we use upper nybble of length
		 * table to base alignment on
		 *
		 * also note: these alignments are ** relative to the
		 * start of the radiotap header **.  There is no guarantee
		 * that the radiotap header itself is aligned on any
		 * kind of boundary.
		 *
		 * the above is why get_unaligned() is used to dereference
		 * multibyte elements from the radiotap area
		 */

		pad = (((ulong)iterator->arg) -
			((ulong)iterator->rtheader)) &
			((rt_sizes[iterator->arg_index] >> 4) - 1);

		if (pad)
			iterator->arg +=
				(rt_sizes[iterator->arg_index] >> 4) - pad;

		/*
		 * this is what we will return to user, but we need to
		 * move on first so next call has something fresh to test
		 */
		iterator->this_arg_index = iterator->arg_index;
		iterator->this_arg = iterator->arg;
		hit = 1;

		/* internally move on the size of this arg */
		iterator->arg += rt_sizes[iterator->arg_index] & 0x0f;

		/*
		 * check for insanity where we are given a bitmap that
		 * claims to have more arg content than the length of the
		 * radiotap section.  We will normally end up equalling this
		 * max_length on the last arg, never exceeding it.
		 */

		if (((ulong)iterator->arg - (ulong)iterator->rtheader) >
		    (ulong) iterator->max_length)
			return -EINVAL;

next_entry:
		iterator->arg_index++;
		if (unlikely((iterator->arg_index & 31) == 0)) {
			/* completed current u32 bitmap */
			if (iterator->bitmap_shifter & 1) {
				/* b31 was set, there is more */
				/* move to next u32 bitmap */
				iterator->bitmap_shifter = __le32_to_cpu(
					get_unaligned(iterator->next_bitmap));
				iterator->next_bitmap++;
			} else
				/* no more bitmaps: end */
				iterator->arg_index = sizeof(rt_sizes);
		} else /* just try the next bit */
			iterator->bitmap_shifter >>= 1;

		/* if we found a valid arg earlier, return it now */
		if (hit)
			return 0;
	}

	/* we don't know how to handle any more args, we're done */
	return -ENOENT;
}

int wipsd_ieee80211_packet_radiotap(unsigned char *buff, u32 *len)
{
	struct ieee80211_radiotap_header *rhdr = (struct ieee80211_radiotap_header *)buff;

	*len = __le16_to_cpu(rhdr->it_len);
	return (rhdr->it_version == PKTHDR_RADIOTAP_VERSION);
} 

int wipsd_ieee80211_packet_prism(unsigned char *buff, u32 *len)
{
	wlan_ng_prism2_header *phdr = NULL;

	phdr = (wlan_ng_prism2_header *)buff;
	*len = phdr->msglen;
	return (phdr->msgcode == 0x00000044);
}

int wipsd_ieee80211_prism_parse(u8 *buff, radioInfo_t *value)
{
	wlan_ng_prism2_header *phdr = NULL;

	phdr = (wlan_ng_prism2_header *)buff;
#if 0
	value->RSSI = buffer[RSSI_BYTE] - ATHEROS_CONV_VALUE;	//RSSI in dBm

	value->signal = buffer[SIGNAL_BYTE] - ATHEROS_CONV_VALUE;
	value->noise = buffer[NOISE_BYTE];
	value->SNR = (char)value->signal - value->noise;	//RSN in dB
	
	value->dataRate = (buffer[DATARATE_BYTE] / 2) * 10;	//Data rate in Mbps*10
#else
	value->signal = phdr->signal.data;
	value->freq_band = (phdr->channel.data > 13 ) ? 5:2;
	value->channel = phdr->channel.data;
	value->rates = phdr->rate.data;
	value->noise = phdr->noise.data;
#endif
	return 1;
}

int wipsd_ieee80211_radiotap_parse(u8 *buf, int buflen,
											radioInfo_t *value)
{
	int ret = 0;
	int freq = 0;
	struct ieee80211_radiotap_header *radiotap_header = NULL;
	struct ieee80211_radiotap_iterator iter;

	memset((void *)&iter, 0, sizeof(struct ieee80211_radiotap_iterator));
	radiotap_header = (struct ieee80211_radiotap_header *)buf;
	if (wipsd_ieee80211_radiotap_iterator_init(&iter, radiotap_header, buflen)) {
		log_error("nl80211: received invalid radiotap frame!\t\n");
		return -1;
	}

	while (!ret) {
		ret = wipsd_ieee80211_radiotap_iterator_next(&iter);
		if (ret) {
			continue;
		}
		
		switch (iter.this_arg_index) {
			case IEEE80211_RADIOTAP_FLAGS:
				//if (*iter.this_arg & IEEE80211_RADIOTAP_F_FCS)
				//	buflen -= 4;
				break;
			case IEEE80211_RADIOTAP_RX_FLAGS:
				//rxflags = 1;
				break;
			case IEEE80211_RADIOTAP_TX_FLAGS:
				//injected = 1;
				//failed = le_to_host16((*(u16 *) iter.this_arg)) &
				//		IEEE80211_RADIOTAP_F_TX_FAIL;
				break;
			case IEEE80211_RADIOTAP_DATA_RETRIES:
				break;
			case IEEE80211_RADIOTAP_CHANNEL:
				/* TODO: convert from freq/flags to channel number */
				freq = __le16_to_cpu(*(u16 *) iter.this_arg);
				value->channel = wipsd_ieee80211_frequency_to_channel(freq);
				value->freq_band = wipsd_ieee80211_frequency_to_band(freq);
				break;
			case IEEE80211_RADIOTAP_RATE:
				value->rates= *iter.this_arg * 5;
				break;
			case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
				value->signal = (s8) *iter.this_arg;
				break;
			case IEEE80211_RADIOTAP_DBM_ANTNOISE:
				value->noise = (s8) *iter.this_arg;
				break;
		}
	}

	if (freq == 0){
		log_error("nl80211: received invalid radiotap freq frame!\t\n");
		return -3;
	}

	return 0;
}


