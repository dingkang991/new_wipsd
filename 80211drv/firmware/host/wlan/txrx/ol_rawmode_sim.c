/*
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <adf_nbuf.h>                       /* adf_nbuf_t */
#include <ieee80211_var.h>                  /* Generally required constructs */
#include <ol_rawmode_sim.h>
#include <ol_rawmode_sim_api.h>
#include <ol_txrx_internal.h>               /* Node add, delete APIs */
#include <ol_if_athvar.h>                   /* ol_ath_vap_get() */

#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION

/* Raw Mode simulation - conversion between Raw 802.11 format and other
 * formats.
 */

/* Rx side helper functions */

static int is_80211amsdu(adf_nbuf_t msdu);

static int
ol_rx_fragstream_init(ol_rx_fragstream_ctx *sctx,
                      adf_nbuf_t list_head,
                      u_int16_t headersize,
                      u_int16_t trailersize,
                      u_int32_t total_bytes,
                      u_int32_t preconsumed_bytes);

static void
ol_rx_fragstream_deinit(ol_rx_fragstream_ctx *sctx);

static int
ol_rx_fragstream_peek(ol_rx_fragstream_ctx *sctx,
                      u_int32_t soffset,
                      u_int32_t numbytes,
                      u_int8_t *dst);

static int
ol_rx_fragstream_consume(ol_rx_fragstream_ctx *sctx,
                         u_int32_t soffset,
                         u_int32_t numbytes,
                         u_int8_t *dst);

static int
decap_dot11withamsdu_to_8023(ol_txrx_pdev_handle pdev,
                             struct ol_txrx_vdev_t *vdev,
                             adf_nbuf_t *deliver_list_head,
                             adf_nbuf_t *deliver_list_tail,
                             u_int32_t total_mpdu_len,
                             struct ol_txrx_peer_t *peer);

static int
decap_dot11_to_8023(adf_nbuf_t msdu, struct ol_txrx_peer_t *peer);


/* Tx side helper functions */

static int encap_eth_to_dot11(
    adf_nbuf_t nbuf, enum ieee80211_opmode mode, u_int8_t *bssid);

static int encap_eth_to_dot11_amsdu(adf_nbuf_t nbuf,
                                        enum ieee80211_opmode mode,
                                        u_int8_t *bssid);

static int form_amsdu_packet(adf_nbuf_t nbuf);

static int check_ip_pkt(adf_nbuf_t nbuf);

static int check_ip_more_frag(adf_nbuf_t nbuf);

static int check_multicast(adf_nbuf_t nbuf);

static void
ol_rsim_txstats_inc_mpdu_noamsdu(ol_txrx_vdev_handle vdev);

static void
ol_rsim_txstats_inc_mpdu_withamsdu(ol_txrx_vdev_handle vdev);


/**
 * @brief Determine if nbuf contains an A-MSDU
 * @details
 *  Determine if nbuf contains the starting of a raw mode MPDU having an
 *  A-MSDU. It is the caller's responsibility to ensure that if scatter/gather
 *  is being used, it passes only the first (head) fragment to this function.
 *
 * @param mpdu - nbuf bearing the MPDU.
 * @return Integer status value.
 *      0  -> Success
 *      -1 -> Failure
 */
static int is_80211amsdu(adf_nbuf_t mpdu)
{
    struct ieee80211_frame *wh;
    a_uint8_t is_4addr;

    if (adf_nbuf_len(mpdu) < sizeof(struct ieee80211_frame)) {
        adf_os_print("MPDU length invalid.\n");
        return -1;
    }

    wh = (struct ieee80211_frame *)adf_nbuf_data(mpdu);

    if (((wh->i_fc[0]) & IEEE80211_FC0_SUBTYPE_MASK) !=
            IEEE80211_FC0_SUBTYPE_QOS) {
        return 0;
    }

    is_4addr = ((wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) ==
                    IEEE80211_FC1_DIR_DSTODS) ? 1:0;

    if (!is_4addr) {
        if (adf_nbuf_len(mpdu) < sizeof(struct ieee80211_qosframe)) {
           adf_os_print("MPDU length invalid.\n");
           return -1;
        }

        return
            (((struct ieee80211_qosframe *)wh)->i_qos[0] &
             IEEE80211_QOS_AMSDU) ? 1:0;
    } else {
        if (adf_nbuf_len(mpdu) < sizeof(struct ieee80211_qosframe_addr4)) {
           adf_os_print("MPDU length invalid.\n");
           return -1;
        }

        return
            (((struct ieee80211_qosframe_addr4*)wh)->i_qos[0] &
                IEEE80211_QOS_AMSDU) ? 1:0;
    }
}

/* Fragment stream processing functionality.
 * This functionality provides the ability to treat the contents of multiple
 * nbuf fragments as a continuous stream of bytes, and carry out operations
 * such as peeking at data and consuming data. The functionality provided is
 * intended only for use in simulation, and provides limited abilities just
 * sufficient for the simulation. See documentation for each function, for more
 * details.
 *
 */

/**
 * @brief Initialize fragment stream
 * @details
 *  Initialize a context corresponding to a fragment stream. The caller can
 *  specify the number the bytes in first fragment already consumed. This is to
 *  allow for use cases such as the caller processing the first MSDU in the head
 *  fragment independent of the fragment stream processing routines.
 *
 * @param sctx - Context corresponding to the fragment stream.
 * @param list_head - Head of linked list of fragments, i.e. the first fragment.
 * @param headersize - 802.11 header size (should be present in list_head).
 * @param trailersize - 802.11 trailer size.
 * @param total_bytes - Total number of bytes in MPDU.
 * @param preconsumed_bytes - Number of bytes in first fragment already
 *      consumed.
 * @return Integer status value.
 *      0  -> Success
 *      -1 -> Failure
 */
static int
ol_rx_fragstream_init(ol_rx_fragstream_ctx *sctx,
                      adf_nbuf_t list_head,
                      u_int16_t headersize,
                      u_int16_t trailersize,
                      u_int32_t total_bytes,
                      u_int32_t preconsumed_bytes)
{
    u_int32_t head_frag_size = 0;
    u_int32_t unconsumed_cnt_total = 0;

    /* Note: Some of the checks below are for completeness. Can be removed
     * during future optimization if desired, but included currently since
     * they are for use only during simulation and clarity is more important.
     */
    if (sctx == NULL) {
        adf_os_print("NULL fragment stream context passed\n");
        return -1;
    }
   
    if (sctx->is_valid == 1) {
        adf_os_print("Previously initialized stream context passed\n");
        return -1;
    }

    if (list_head == NULL) {
        adf_os_print("NULL list head passed\n");
        return -1;
    }

    /* Minimum sanity check: We need at least bare 802.11 data header size */
    if (headersize < sizeof(struct ieee80211_frame)) {
        adf_os_print("Invalid header size passed\n");
        return -1;
    }

    /* Minimum sanity check: We need atleast FCS */
    if (trailersize < 4) {
        adf_os_print("Invalid trailer size passed\n");
        return -1;
    }
 
    head_frag_size = adf_nbuf_len(list_head);

    if (preconsumed_bytes > head_frag_size) {
        adf_os_print("Pre-consumed bytes exceed head fragment size\n");
        return -1;
    }

    unconsumed_cnt_total = total_bytes - preconsumed_bytes;

    if (unconsumed_cnt_total < trailersize) {
        adf_os_print("Unconsumed bytes less than expected trailer size\n");
        return -1;
    }

    sctx->list_head = list_head;
    sctx->headersize = headersize;
    sctx->trailersize = trailersize;

    /* Pre-consumption of bytes from head nbuf by caller is supported for nbuf
     * handling efficiency purposes (re-using head nbuf to carry decap output
     * for first MSDU).
     */
    if (preconsumed_bytes == head_frag_size) {
        sctx->currnbuf = adf_nbuf_next(list_head);
        sctx->currnbuf_ptr = adf_nbuf_data(sctx->currnbuf);
        sctx->unconsumed_cnt_curr = adf_nbuf_len(sctx->currnbuf);
        if (adf_nbuf_is_chfrag_end(sctx->currnbuf)) {
            sctx->nextnbuf = NULL;
        } else { 
            sctx->nextnbuf = adf_nbuf_next(sctx->currnbuf);
        }
    } else {
        sctx->currnbuf = list_head;
        sctx->currnbuf_ptr = adf_nbuf_data(list_head)+ preconsumed_bytes;
        sctx->unconsumed_cnt_curr = head_frag_size - preconsumed_bytes;
        sctx->nextnbuf = adf_nbuf_next(list_head);
    }
    
    sctx->unconsumed_cnt_total = unconsumed_cnt_total;

    sctx->is_valid = 1;

    return 0;
}

/**
 * @brief De-initialize fragment stream
 * @details
 *  De-initialize a context corresponding to a fragment stream.
 *
 * @param sctx - Context corresponding to the fragment stream.
 */
static void
ol_rx_fragstream_deinit(ol_rx_fragstream_ctx *sctx)
{
    adf_os_mem_zero(sctx, sizeof(*sctx));
}

/**
 * @brief Peek at contents in fragment stream
 * @details
 *  Retrieve a number of bytes of content at some offset from the current
 *  pointer in the fragment stream, without actually consuming (i.e. discarding)
 *  them after the copy. Thus the current pointer is not updated. This is useful
 *  for looking ahead at some fields such as length in order to allocate the
 *  requisite buffer prior to full-fledged consumption.  Note that some
 *  restrictions have been placed on the offset and number of bytes that can be
 *  peeked at, for simplicity. These restrictions center around the assumption
 *  that not more than one fragment boundary will need to be crossed in the
 *  process of peeking. This assumption holds true for the typical size of
 *  receive nbufs queued to hardware, and the use cases for the peek operations.
 *
 *  Note: It is the responsibility of the caller to ensure that the destination
 *  buffer has sufficient space.
 *
 * @param sctx - Context corresponding to the fragment stream.
 * @param soffset - Number of bytes to skip before starting peek. Should not be
 *      more than OL_RX_FRAGSTREAM_PEEK_OFFSET_MAX.
 * @param numbytes - Number of bytes to copy. Should not be more than
 *      OL_RX_FRAGSTREAM_PEEK_NBYTES_MAX.
 * @param dst - Destination buffer.
 * @return Integer status value.
 *      0  -> Success
 *      -1 -> Failure
 */
static int
ol_rx_fragstream_peek(ol_rx_fragstream_ctx *sctx,
                      u_int32_t soffset,
                      u_int32_t numbytes,
                      u_int8_t *dst)
{   
    u_int8_t *next_ptr = NULL;

    /* Note: Some of the checks below are for completeness. Can be removed
     * during future optimization if desired, but included currently since
     * they are for use only during simulation and clarity and correctness are
     * more important.
     */
    if (sctx == NULL){
        adf_os_print("NULL fragment stream context passed\n");
        return -1;
    }
    
    if (sctx->is_valid != 1) {
        adf_os_print("Invalid context passed\n");
        return -1;
    }

    if (dst == NULL){
        adf_os_print("NULL destination buffer passed\n");
        return -1;
    }

    if (soffset > OL_RX_FRAGSTREAM_PEEK_OFFSET_MAX) {
        adf_os_print("Invalid value %u passed for offset\n", soffset);
        return -1;
    }

    if (numbytes > OL_RX_FRAGSTREAM_PEEK_NBYTES_MAX) {
        adf_os_print("Invalid value %u passed for num bytes required\n",
                numbytes);
        return -1;
    }

    if ((soffset + numbytes) > sctx->unconsumed_cnt_total ) {
        adf_os_print("Attempt detected to peek beyond stream boundary."
                     "offset=%u num bytes=%u unconsumed total count=%u\n",
                     soffset, numbytes, sctx->unconsumed_cnt_total);
        return -1;
    }

    /* It is the responsibility of the caller to ensure that dst
     * has space for numbytes.
     */

    if (sctx->unconsumed_cnt_curr <= soffset) {
        /* Offset falls into next nbuf */
        next_ptr = adf_nbuf_data(sctx->nextnbuf) +
                   soffset -
                   sctx->unconsumed_cnt_curr;

        adf_os_mem_copy(dst, next_ptr, numbytes);
    } else if (sctx->unconsumed_cnt_curr < (soffset + numbytes)) {
        /* Offset remains in current nbuf, but peek will overflow into next
         * nbuf
         */
        adf_os_mem_copy(dst,
                        sctx->currnbuf_ptr + soffset,
                        sctx->unconsumed_cnt_curr - soffset);
        
        next_ptr = adf_nbuf_data(sctx->nextnbuf);
        adf_os_mem_copy(dst,
                        next_ptr,
                        numbytes - (sctx->unconsumed_cnt_curr - soffset));
    } else {
        /* Everything is contained in current nbuf */
        adf_os_mem_copy(dst,
                        sctx->currnbuf_ptr + soffset,
                        numbytes);
    }

    return 0;
}

/**
 * @brief Copy and consume contents in fragment stream
 * @details
 *  Copy and consume a number of bytes of content at some offset from the
 *  current pointer in the fragment stream. The current pointer is updated to go
 *  past the offset and number of bytes copied . Thus the bytes at both the
 *  locations skipped by the offset and those covered by the copy are considered
 *  to have been consumed. These bytes will no longer be available through this
 *  context.
 *
 *  Note: It is the responsibility of the caller to ensure that the destination
 *  buffer has sufficient space.
 *
 * @param sctx - Context corresponding to the fragment stream.
 * @param soffset - Number of bytes to skip before starting consumption.
 * @param numbytes - Number of bytes to copy.
 * @param dst - Destination buffer.
 * @return Integer status value.
 *      0  -> Success
 *      -1 -> Failure
 */
static int
ol_rx_fragstream_consume(ol_rx_fragstream_ctx *sctx,
                         u_int32_t soffset,
                         u_int32_t numbytes,
                         u_int8_t *dst)
{
    u_int32_t jmp_remaining = 0;
    u_int32_t cpy_remaining = 0;
    u_int32_t dstoffset = 0;

    /* Note: Some of the checks below are for completeness. Can be removed
     * during future optimization if desired, but included currently since
     * they are for use only during simulation and clarity is more important.
     */
    if (sctx == NULL){
        adf_os_print("NULL fragment stream context passed\n");
        return -1;
    }
   
    if (sctx->is_valid != 1) {
        adf_os_print("Invalid context passed\n");
        return -1;
    }

    if ((soffset + numbytes) > sctx->unconsumed_cnt_total ) {
        adf_os_print("Attempt detected to consume bytes beyond stream boundary.\n"
                     "offset=%u num bytes=%u unconsumed total count=%u\n",
                     soffset, numbytes, sctx->unconsumed_cnt_total);
        return -1;
    }

    /* It is the responsibility of the caller to ensure that dst
     * has space for numbytes (except if it is NULL, which indicates that the
     * caller merely wants a discard operation)..
     */

    jmp_remaining = soffset;

    while (jmp_remaining && sctx->currnbuf) {
        if (jmp_remaining >= sctx->unconsumed_cnt_curr) {
            jmp_remaining -= sctx->unconsumed_cnt_curr;
            sctx->unconsumed_cnt_total -= sctx->unconsumed_cnt_curr;
            sctx->currnbuf = sctx->nextnbuf;
            if (sctx->currnbuf) {
                if (adf_nbuf_is_chfrag_end(sctx->currnbuf)) {
                    sctx->nextnbuf = NULL;
                } else { 
                    sctx->nextnbuf = adf_nbuf_next(sctx->currnbuf);
                }
                sctx->unconsumed_cnt_curr = adf_nbuf_len(sctx->currnbuf);
                sctx->currnbuf_ptr = adf_nbuf_data(sctx->currnbuf);
            }
        } else {
           sctx->unconsumed_cnt_curr -= jmp_remaining;
           sctx->unconsumed_cnt_total -= jmp_remaining;
           sctx->currnbuf_ptr += jmp_remaining;
           jmp_remaining = 0;
        }
    }
    
    if (sctx->currnbuf == NULL) {
        /* Unexpected condition */
        adf_os_print("Ran out of fragments while fast forwarding to offset."
                     "Invalidating context.\n"
                     "offset=%u num bytes=%u unconsumed total count=%u\n",
                     soffset, numbytes, sctx->unconsumed_cnt_total);
        sctx->is_valid = 0;
        return -1;
    }

    cpy_remaining = numbytes;
    
    while (cpy_remaining && sctx->currnbuf) {
        if (cpy_remaining >= sctx->unconsumed_cnt_curr) {
            if (dst) {
                adf_os_mem_copy(dst + dstoffset,
                        sctx->currnbuf_ptr,
                        sctx->unconsumed_cnt_curr);
            }
            cpy_remaining -= sctx->unconsumed_cnt_curr;
            sctx->unconsumed_cnt_total -= sctx->unconsumed_cnt_curr;
            dstoffset += sctx->unconsumed_cnt_curr;
            sctx->currnbuf = sctx->nextnbuf;
            if (sctx->currnbuf) {
                if (adf_nbuf_is_chfrag_end(sctx->currnbuf)) {
                    sctx->nextnbuf = NULL;
                } else { 
                    sctx->nextnbuf = adf_nbuf_next(sctx->currnbuf);
                }
                sctx->unconsumed_cnt_curr = adf_nbuf_len(sctx->currnbuf);
                sctx->currnbuf_ptr = adf_nbuf_data(sctx->currnbuf);
            }
        } else {
            if (dst) {
                adf_os_mem_copy(dst + dstoffset,
                        sctx->currnbuf_ptr,
                        cpy_remaining);
            }

           sctx->unconsumed_cnt_curr -= cpy_remaining;
           sctx->unconsumed_cnt_total -= cpy_remaining;
           sctx->currnbuf_ptr += cpy_remaining;
           cpy_remaining = 0;
        }
    }

    if (sctx->currnbuf == NULL) {
        /* Unexpected condition */
        adf_os_print("Ran out of fragments while copying bytes."
                     "Invalidating context.\n"
                     "offset=%u num bytes=%u unconsumed total count=%u\n",
                     soffset, numbytes, sctx->unconsumed_cnt_total);
        sctx->is_valid = 0;
        return -1;
    }

    return 0;
}

/* End of fragment stream processing functionality */


/**
 * @brief Decap an 802.11 MPDU containing an A-MSDU, into Ethernet II frames.
 * @details
 *   This function generates a linked list of nbufs, each nbuf containing an
 *   Ethernet II frame bearing the payload from an MSDU.
 *
 *   If the MPDU is fragmented: The original linked list passed to the function
 *   is modified to link the above nbufs. The same head nbuf as passed in the
 *   input linked list is used as-is after decapping unwanted fields from
 *   802.11. However, the remaining nbufs if any will be newly allocated.  This
 *   is because the emphasis of the simulation is clean testability rather than
 *   performance. For similar reasons, certain minor potential optimizations
 *   have not been taken up in order to facilitate testability.
 *
 *   If the MPDU is not fragmented: Similar to above. It is the responsibility
 *   of the caller to link back the newly generated linked list into the main
 *   linked list containing the rest of the non-AMSDU nbufs. The caller should
 *   pass the single nbuf using deliver_list_head.  *deliver_list_tail can be
 *   kept NULL: deliver_list_tail will be used to point to the last Ethernet II
 *   frame at the end of the operation.
 *
 *   The function does not validate the DA and SA.
 *
 *   Workaround: In case of an error in parsing the MSDUs, the function returns
 *   the MSDUs parsed successfully so far. This is to be able to interwork with
 *   certain implementations which might send a garbage MSDU (mostly) in the
 *   end, and with valid FCS. The policy we adopt in this case is to treat each
 *   MSDU as a distinct entity and not penalize other MSDUs in case of parsing
 *   failures. It is up to higher layers to further analyze the MSDUs. A
 *   statistic is recorded to track this. Currently, the function doesn't extend
 *   the same handling to trailer parsing failures, assuming all MSDUs have been
 *   parsed successfully. Though it could be argued that the above relaxation
 *   might as well be extended here, we should avoid extending the scope of
 *   workarounds where not supported by real world requirements.
 *
 *   Assumptions:
 *   - the caller has verified that the first nbuf corresponds to the start of a
 *     raw MPDU containing an A-MSDU sequence.
 *   - all the nbufs in the list correspond to that MPDU.
 *
 *   NB: HTC not considered, since TxBF isn't involved.
 *
 * @param pdev - The data physical device receiving the data
 *      (for accessing the OS device for nbuf allocation).
 * @param vdev - The virtual device receiving the data.
 * @param deliver_list_head - If fragmentation is used: pointer to the head of
 *      the linked list containing the MPDU fragments. If fragmentation is not
 *      used: Pointer to the single nbuf containing the MPDU.
 * @param deliver_list_tail - If fragmentation is used: pointer to the tail of
 *       the linked list containing the MPDU fragments. Upon success, it will be
 *       modified to link last decapped Ethernet II frame bearing nbuf. If
 *       fragmentation is not used: pointer to location where last decapped
 *       Ethernet II bearing nbuf should be linked upon success.
 * @param total_mpdu_len - Total MPDU length.
 * @param peer - The peer which has sent the frames.
 * @return Integer status value.
 *      0  -> Success
 *      1  -> Partial success (see description of workaround in details)
 *      -1 -> Failure
 */
static int
decap_dot11withamsdu_to_8023(ol_txrx_pdev_handle pdev,
                             struct ol_txrx_vdev_t *vdev,
                             adf_nbuf_t *deliver_list_head,
                             adf_nbuf_t *deliver_list_tail,
                             u_int32_t total_mpdu_len,
                             struct ol_txrx_peer_t *peer)
{
    struct ieee80211_qosframe wh;
    a_uint8_t sec_idx;
    a_uint32_t hdrsize=0, trailersize = 4; /* Account for FCS */
    a_uint16_t msdulen = 0;

    adf_nbuf_t headsrcnbuf, dstnbuf, nbuf, next;
    ol_rx_fragstream_ctx sctx;
    struct ether_header *src_eth_hdr, *dst_eth_hdr;
    a_uint8_t is_4addr = 0;
    adf_nbuf_t deliver_list_head_new = NULL;
    adf_nbuf_t deliver_list_tail_new = NULL;
    u_int32_t preconsumed_bytes = 0;
    u_int8_t msdu_padding = 0;
    u_int32_t first_ethpktsize = 0;
    u_int8_t is_frag = 0;
    u_int32_t unconsumed_cnt = 0;
    u_int32_t unconsumed_cnt_nonfrag = 0;
    u_int32_t total_msdulen = 0;
    u_int32_t adj_total_mpdu_len = 0;
    u_int8_t *headsrcnbufptr = NULL;
    int err;
    int parsing_error = 0;

    if ((deliver_list_head == NULL) || (*deliver_list_head == NULL)) {
        adf_os_print("List head/pointer to list head is NULL\n");
        return -1;
    }
    
    if (deliver_list_tail == NULL) {
        adf_os_print("Pointer to list tail is NULL\n");
        return -1;
    }

    is_frag = adf_nbuf_is_chfrag_start(*deliver_list_head);

    if (is_frag && (*deliver_list_tail == NULL)) {
        adf_os_print("NULL list tail passed. List tail required since fragments are "
                     "present\n");
        return -1;
    }

    headsrcnbuf = *deliver_list_head;

    adf_os_mem_copy(&wh, adf_nbuf_data(headsrcnbuf), sizeof(wh));
    
    /* XXX: Potential optimization if required: Re-use these determinations from
     * check of whether the frame is an A-MSDU 
     */
    is_4addr = ((wh.i_fc[1] & IEEE80211_FC1_DIR_MASK) ==
                    IEEE80211_FC1_DIR_DSTODS) ? 1:0;

    hdrsize = sizeof(struct ieee80211_qosframe);

    if (is_4addr) {
        hdrsize += IEEE80211_ADDR_LEN;
    }

    if (wh.i_fc[1] & IEEE80211_FC1_WEP) {
        /* For encrypted frames offset header accordingly. Strip
         * any crypto trailers along with FCS */
        if(wh.i_addr1[0] & 0x01) {
            sec_idx = txrx_sec_mcast;
        } else {
            sec_idx = txrx_sec_ucast;
        }
    
        if(peer->security[sec_idx].sec_type == htt_sec_type_wapi) {
            static unsigned warn_once_in_1k = 1000; 
            if(warn_once_in_1k == 0) {
                adf_os_print("WAPI Not supported in simulation - decap "
                             "failed !!\n");
                warn_once_in_1k = 1000;
            }
            --warn_once_in_1k;
            return -1;
        }
        
        if(peer->security[sec_idx].sec_type == htt_sec_type_wep128 ||
           peer->security[sec_idx].sec_type == htt_sec_type_wep104 ||
           peer->security[sec_idx].sec_type == htt_sec_type_wep40) {

            hdrsize += 4;
            trailersize += 4;
        } else {
            hdrsize += 8; //TKIP or TKIP-NOMIC or AES-CCMP
            if(peer->security[sec_idx].sec_type == htt_sec_type_tkip) {
                trailersize += 12;
            } else if(peer->security[sec_idx].sec_type ==
                        htt_sec_type_tkip_nomic) {
                trailersize += 4;
            } else { //AES-CCMP
                trailersize += 8;
            }
        }
    }

    /* Decap first nbuf so it contains just the first MSDU */
    
    /*
     * Move the data pointer to the beginning of the A-MSDU delimiter:
     * new-header = old-hdr + 802.11 hdrsize
     */
    adf_nbuf_pull_head(headsrcnbuf, hdrsize);
    adj_total_mpdu_len = total_mpdu_len - hdrsize;
    unconsumed_cnt = adj_total_mpdu_len;

    /* Access A-MSDU delimiter, using an Ethernet struct for the purpose. */
    /* XXX: Check if we could use A-MSDU delimiter header instead */
    src_eth_hdr = (struct ether_header *)(adf_nbuf_data(headsrcnbuf));
    msdulen = adf_os_ntohs(src_eth_hdr->ether_type);

    if ((msdulen < sizeof(struct llc)) ||
        (msdulen > MAX_SIM_80211_MSDU_LEN)) {
        vdev->rsim_rxstats.num_rx_inval_len_msdu++;
        return -1;
    }

    total_msdulen = msdulen + sizeof(struct ether_header);

    if (unconsumed_cnt < (total_msdulen + trailersize)) {
         adf_os_print("Error while parsing MPDU. Insufficient "
                      "bytes %u remaining. Expected at least %u\n",
                      unconsumed_cnt,
                      (total_msdulen + trailersize));
        vdev->rsim_rxstats.num_rx_tooshort_mpdu++;
        return -1;
    }

    if ((unconsumed_cnt - total_msdulen) > trailersize) {
        /* This is not expected to be the last MSDU */
        msdu_padding = (msdulen + sizeof(struct ether_header)) & 0x03;
        total_msdulen += msdu_padding;

        if (unconsumed_cnt < (total_msdulen + trailersize)) {
             adf_os_print("Error while parsing MPDU. Expecting %u MSDU padding "
                          "bytes but unable to parse MDPU given %u bytes "
                          "remaining in MPDU.",
                          msdu_padding,
                          unconsumed_cnt);
            vdev->rsim_rxstats.num_rx_tooshort_mpdu++;
            return -1;
        }
    } else {
        msdu_padding = 0;
    }

    src_eth_hdr->ether_type =
        L_GET_LLC_ETHTYPE((u_int8_t*)src_eth_hdr +
                          sizeof(struct ether_header));

    /* Get rid of LLC */
    adf_os_mem_move((u_int8_t*)src_eth_hdr + sizeof(struct llc),
                    src_eth_hdr,
                    sizeof(struct ether_header));
    adf_nbuf_pull_head(headsrcnbuf, sizeof(struct llc));
    adj_total_mpdu_len -=  sizeof(struct llc);

    preconsumed_bytes = total_msdulen - sizeof(struct llc);
    unconsumed_cnt -= preconsumed_bytes;
    first_ethpktsize = preconsumed_bytes - msdu_padding;

    if (is_frag) {
        adf_os_mem_zero(&sctx, sizeof(sctx));

        err = ol_rx_fragstream_init(&sctx,
                *deliver_list_head,
                hdrsize,
                trailersize,
                adj_total_mpdu_len,
                preconsumed_bytes);
        
        if (err < 0) {
            goto err1;
        }
    } else {
        unconsumed_cnt_nonfrag = unconsumed_cnt;
        headsrcnbufptr = adf_nbuf_data(headsrcnbuf) + preconsumed_bytes;
    }

    while (GET_UNCONSUMED_CNT(is_frag, &sctx, unconsumed_cnt_nonfrag) >
                trailersize)
    {
        if (is_frag) {
             err = ol_rx_fragstream_peek(&sctx,
                    2 * ETHER_ADDR_LEN,
                    2,
                    (u_int8_t*)&msdulen);

            if (err < 0) {
                parsing_error = 1;
                break;
            }

            msdulen = adf_os_ntohs(msdulen);
        } else {
            src_eth_hdr = (struct ether_header *)(headsrcnbufptr);
            msdulen = adf_os_ntohs(src_eth_hdr->ether_type);
        }

        if ((msdulen < sizeof(struct llc)) ||
            (msdulen > MAX_SIM_80211_MSDU_LEN)) {
            vdev->rsim_rxstats.num_rx_inval_len_msdu++;
            parsing_error = 1;
            break;
        }

        total_msdulen = msdulen + sizeof(struct ether_header);

        unconsumed_cnt = GET_UNCONSUMED_CNT(is_frag,
                                            &sctx,
                                            unconsumed_cnt_nonfrag);
        if (unconsumed_cnt < (total_msdulen + trailersize)) {
             adf_os_print("Error while parsing MPDU. Insufficient "
                          "bytes %u remaining. Expected at least %u\n",
                          unconsumed_cnt,
                          (total_msdulen + trailersize));
            parsing_error = 1;
            vdev->rsim_rxstats.num_rx_tooshort_mpdu++;
            break;
        }

        msdu_padding = 0;
        if ((unconsumed_cnt - total_msdulen) > trailersize) {
            /* This is not expected to be the last MSDU */
            msdu_padding = (msdulen + sizeof(struct ether_header)) & 0x03;
            total_msdulen += msdu_padding;

            if (unconsumed_cnt < (total_msdulen + trailersize)) {
                 adf_os_print("Error while parsing MPDU. Expecting %u MSDU padding "
                              "bytes but unable to parse MDPU given %u bytes "
                              "remaining in MPDU.",
                              msdu_padding,
                              unconsumed_cnt);
                parsing_error = 1;
                vdev->rsim_rxstats.num_rx_tooshort_mpdu++;
                break;
            }
        }

        dstnbuf =
            adf_nbuf_alloc(pdev->osdev,
                           msdulen + sizeof(struct ether_header),  /* size    */
                           0,                                      /* reserve */
                           4,                                      /* align   */
                           FALSE);                                 /* prio    */

        if (!dstnbuf) {
            adf_os_print("Unable to allocate nbuf\n");
            /* We treat this similar to a parsing error, so we can attempt to
             * deliver MSDUs successfully decapped so far
             */
            parsing_error = 1;
            break;
        }

        adf_nbuf_set_pktlen(dstnbuf,
                msdulen + sizeof(struct ether_header) - sizeof(struct llc));
        
        dst_eth_hdr = (struct ether_header *)adf_nbuf_data(dstnbuf);

        /* Copy addresses, populate ethter type field, and move to end of LLC */
        if (is_frag) {
            err = ol_rx_fragstream_consume(&sctx,
                    0,
                    2 * ETHER_ADDR_LEN,
                    (u_int8_t*)dst_eth_hdr);

            if (err < 0) {
                adf_nbuf_free(dstnbuf);
                parsing_error = 1;
                break;
            }
            
            /* Populate the ether type field. This also has the effect of
             * skipping LLC
             */
            err = ol_rx_fragstream_consume(&sctx,
                    L_ETH_ETHTYPE_SIZE + L_LLC_ETHTYPE_OFFSET,
                    sizeof(dst_eth_hdr->ether_type),
                    (u_int8_t*)&dst_eth_hdr->ether_type);
            
            if (err < 0) {
                adf_nbuf_free(dstnbuf);
                parsing_error = 1;
                break;
            }
            
        } else {
            adf_os_mem_copy((u_int8_t*)dst_eth_hdr,
                    headsrcnbufptr,
                    2 * ETHER_ADDR_LEN);
            
            /* Populate the ether type field. */
            dst_eth_hdr->ether_type = 
                L_GET_LLC_ETHTYPE(headsrcnbufptr + sizeof(struct ether_header));

            /* Skip headers */
            headsrcnbufptr += (sizeof(struct ether_header) + sizeof(struct llc));
            unconsumed_cnt_nonfrag -=
                (sizeof(struct ether_header) + sizeof(struct llc));
        }

        /* Copy data */
        if (is_frag) {
            err = ol_rx_fragstream_consume(&sctx,
                    0,
                    msdulen - sizeof(struct llc),
                    adf_nbuf_data(dstnbuf) + sizeof(struct ether_header));
            
            if (err < 0) {
                adf_nbuf_free(dstnbuf);
                parsing_error = 1;
                break;
            }
        } else {
            adf_os_mem_copy(adf_nbuf_data(dstnbuf) + sizeof(struct ether_header),
                    headsrcnbufptr,
                    msdulen - sizeof(struct llc));
            
            headsrcnbufptr += (msdulen - sizeof(struct llc));
            unconsumed_cnt_nonfrag -= (msdulen - sizeof(struct llc));
        }
        
        if (msdu_padding) {
            /* Discard the padding */
            if (is_frag) {
                err = ol_rx_fragstream_consume(&sctx,
                        0,
                        msdu_padding,
                        NULL);

                if (err < 0) {
                    adf_nbuf_free(dstnbuf);
                    parsing_error = 1;
                    break;
                }
            } else {
                headsrcnbufptr += msdu_padding;
                unconsumed_cnt_nonfrag -= msdu_padding;
            }
        }

        OL_TXRX_LIST_APPEND(deliver_list_head_new,
            deliver_list_tail_new,
            dstnbuf);
        adf_nbuf_set_next(deliver_list_tail_new, NULL);
    }

    if (!parsing_error &&
        (GET_UNCONSUMED_CNT(is_frag,
                            &sctx,
                            unconsumed_cnt_nonfrag) != trailersize)) {
       adf_os_print("Unexpected residue found at end of MPDU containing "
                    "A-MSDU\n");
       vdev->rsim_rxstats.num_rx_toolong_mpdu++;
       goto err2;
    }
    
    if (is_frag && (sctx.currnbuf == NULL)) {
       adf_os_print("Unable to find expected trailer/residue at end of MPDU "
                    "containing A-MSDU\n");
       vdev->rsim_rxstats.num_rx_tooshort_mpdu++;
       goto err2;
    }

    adf_nbuf_trim_tail(headsrcnbuf,
            adf_nbuf_len(headsrcnbuf) - first_ethpktsize);

    if (is_frag) {
        /* Release expended fragments except the first one */
        adf_nbuf_set_chfrag_start(headsrcnbuf, 0);
        nbuf = adf_nbuf_next(headsrcnbuf);
        while (nbuf && (nbuf != (*deliver_list_tail))) {
            next = adf_nbuf_next(nbuf);
            adf_nbuf_free(nbuf);
            nbuf = next;
        }
        
        if (nbuf) {
            adf_nbuf_free(nbuf);
        }
    }

    if (!deliver_list_head_new) {
        OL_TXRX_LIST_APPEND(deliver_list_head_new,
                deliver_list_tail_new,
                headsrcnbuf);
        adf_nbuf_set_next(deliver_list_tail_new, NULL);
    } else {
        adf_nbuf_set_next(headsrcnbuf, deliver_list_head_new);
        deliver_list_head_new = headsrcnbuf;
    }

    *deliver_list_head = deliver_list_head_new;
    *deliver_list_tail = deliver_list_tail_new;
    
    if (parsing_error) {
        return 1;
    } else {
        return 0;
    }

err2:
    if (deliver_list_head_new) {
        nbuf = adf_nbuf_next(deliver_list_head_new);
        while (nbuf) {
            next = adf_nbuf_next(nbuf);
            adf_nbuf_free(nbuf);
            nbuf = next;
        }
    }

err1:
    return -1;
}

/**
 * @brief Decap an 802.11 MPDU not containing an A-MSDU, into an Ethernet II
 *   frame.
 * @details
 *   This function decaps a single nbuf corresponding to an 802.11 MPDU not
 *   containing an A-MSDU, into a single Ethernet II frame in the same nbuf.
 *
 *   NB: HTC not considered, since TxBF isn't involved.
 *
 * @param mpdu - nbuf bearing the 802.11 MPDU.
 * @param peer - The peer which has sent the frame.
 * @return Integer status value.
 *      0  -> Success
 *      -1 -> Failure
 */
static int
decap_dot11_to_8023(adf_nbuf_t mpdu, struct ol_txrx_peer_t *peer)
{
    struct ieee80211_frame wh;
    struct ieee80211_frame_addr4 *wh4addr;
    a_uint8_t type,subtype,sec_idx;
    a_uint32_t hdrsize=0, trailersize = 4; //Account for FCS
    struct llc llchdr;
    struct ether_header *eth_hdr;
    a_uint8_t is_4addr = 0;

    adf_os_mem_copy(&wh, adf_nbuf_data(mpdu), sizeof(wh));
    type = wh.i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    subtype = wh.i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
    is_4addr = ((wh.i_fc[1] & IEEE80211_FC1_DIR_MASK) ==
                    IEEE80211_FC1_DIR_DSTODS) ? 1:0;

    if (subtype == IEEE80211_FC0_SUBTYPE_QOS) {
        hdrsize = sizeof(struct ieee80211_qosframe);
    } else {
        hdrsize = sizeof(struct ieee80211_frame);
    }

    if (is_4addr) {
        hdrsize += IEEE80211_ADDR_LEN;
        /* We don't need to bother about whether the frame is QoS, here.
           The QoS field occurs after the 4th address, and we don't access
           the field. */
        wh4addr = (struct ieee80211_frame_addr4 *)adf_nbuf_data(mpdu);
    }

    if (wh.i_fc[1] & IEEE80211_FC1_WEP) {

        /* For encrypted frames offset header accordingly. Strip
         * any crypto trailers along with FCS */

        if(wh.i_addr1[0] & 0x01) {
            sec_idx = txrx_sec_mcast;
        } else {
            sec_idx = txrx_sec_ucast;
        }
    
        if(peer->security[sec_idx].sec_type == htt_sec_type_wapi) {
            static unsigned warn_once_in_1k = 1000; 
            if(warn_once_in_1k == 0) {
                adf_os_print("WAPI Not supported in simulation - decap failed !!\n");
                warn_once_in_1k = 1000;
            }
            --warn_once_in_1k;
            return -1;
        }
        
        if(peer->security[sec_idx].sec_type == htt_sec_type_wep128 ||
           peer->security[sec_idx].sec_type == htt_sec_type_wep104 ||
           peer->security[sec_idx].sec_type == htt_sec_type_wep40) {

            hdrsize += 4;
            trailersize += 4;
        } else {
            hdrsize += 8; //TKIP or TKIP-NOMIC or AES-CCMP
            if(peer->security[sec_idx].sec_type == htt_sec_type_tkip) {
                trailersize += 12;
            } else if(peer->security[sec_idx].sec_type == htt_sec_type_tkip_nomic) {
                trailersize += 4;
            } else { //AES-CCMP
                trailersize += 8;
            }
        }
    }

    adf_os_mem_copy(&llchdr, ((a_uint8_t *)adf_nbuf_data(mpdu)) + hdrsize,
              sizeof(struct llc));

    /*
     * Now move the data pointer to the beginning of the MAC header :
     * new-header = old-hdr + (wifhdrsize + llchdrsize - ethhdrsize)
     */
    adf_nbuf_pull_head(
        mpdu, (hdrsize + sizeof(struct llc) - sizeof(struct ether_header)));

    /* Strip out 802.11 FCS + trailers if any */
    adf_nbuf_trim_tail(mpdu, trailersize);

    eth_hdr = (struct ether_header *)(adf_nbuf_data(mpdu));
    switch (wh.i_fc[1] & IEEE80211_FC1_DIR_MASK) {
        case IEEE80211_FC1_DIR_NODS:
            adf_os_mem_copy(
                eth_hdr->ether_dhost, wh.i_addr1, IEEE80211_ADDR_LEN);
            adf_os_mem_copy(
                eth_hdr->ether_shost, wh.i_addr2, IEEE80211_ADDR_LEN);
            break;
        case IEEE80211_FC1_DIR_TODS:
            adf_os_mem_copy(
                eth_hdr->ether_dhost, wh.i_addr3, IEEE80211_ADDR_LEN);
            adf_os_mem_copy(
                eth_hdr->ether_shost, wh.i_addr2, IEEE80211_ADDR_LEN);
            break;
        case IEEE80211_FC1_DIR_FROMDS:
            adf_os_mem_copy(
                eth_hdr->ether_dhost, wh.i_addr1, IEEE80211_ADDR_LEN);
            adf_os_mem_copy(
                eth_hdr->ether_shost, wh.i_addr3, IEEE80211_ADDR_LEN);
            break;
        case IEEE80211_FC1_DIR_DSTODS:
            adf_os_mem_copy(
                eth_hdr->ether_dhost, wh4addr->i_addr3, IEEE80211_ADDR_LEN);
            adf_os_mem_copy(
                eth_hdr->ether_shost, wh4addr->i_addr4, IEEE80211_ADDR_LEN);
            break;
    }
    eth_hdr->ether_type = llchdr.llc_un.type_snap.ether_type;

    return 0;
}


/**
 * @brief Encap an Ethernet II frame into an 802.11 MPDU
 * @details
 *   This function encaps a single nbuf corresponding to an Ethernet II frame
 *   into an 802.11 QoS MPDU frame in the same nbuf.
 *   The emphasis is on testability, hence certain potential optimizations have
 *   not been carried out.
 *
 * @param mpdu  - nbuf bearing the Ethernet II frame.
 * @param mode  - The operating mode.
 * @param bssid - The BSSID under which the MPDU is to be sent.
 * @return Integer status value.
 *      0  -> Success
 *      -1 -> Failure
 */
static int encap_eth_to_dot11(
    adf_nbuf_t nbuf, enum ieee80211_opmode mode, u_int8_t *bssid)
{
    u_int8_t *datap;
    u_int16_t typeorlen;
    u_int32_t hdrsize;
    struct ether_header eth_hdr;
    struct llc *llcHdr;
    struct ieee80211_frame *wh;

    adf_os_assert_always(nbuf != NULL);

    if (adf_nbuf_headroom(nbuf) <
        (sizeof(struct ieee80211_qosframe) +  sizeof(*llcHdr)))
    {
        adf_os_print("### Raw Mode simulation encap: Don't have enough "
                     "headroom\n");
        return -1;
    }

    datap = adf_nbuf_data(nbuf);

    typeorlen = *(u_int16_t *)(datap + IEEE80211_ADDR_LEN * 2);

    /*
     * Save addresses to be inserted later. Both destination and source
     * addresses get copied in one operation.
     */
    adf_os_mem_copy(eth_hdr.ether_dhost, datap, IEEE80211_ADDR_LEN * 2);

    adf_nbuf_pull_head(nbuf, sizeof(eth_hdr));

    /*
     * Make room for LLC + SNAP headers
     */
    if (adf_nbuf_push_head(nbuf, sizeof(*llcHdr)) == NULL) {
        adf_os_print("### Raw Mode simulation encap: Failed to push LLC "
                     "header\n");
        return -1;
    }
    datap = adf_nbuf_data(nbuf);

    llcHdr = (struct llc *)(datap);
    llcHdr->llc_dsap                     = LLC_SNAP_LSAP;
    llcHdr->llc_ssap                     = LLC_SNAP_LSAP;
    llcHdr->llc_un.type_snap.control     = LLC_UI;
    llcHdr->llc_un.type_snap.org_code[0] = RFC1042_SNAP_ORGCODE_0;
    llcHdr->llc_un.type_snap.org_code[1] = RFC1042_SNAP_ORGCODE_1;
    llcHdr->llc_un.type_snap.org_code[2] = RFC1042_SNAP_ORGCODE_2;
    llcHdr->llc_un.type_snap.ether_type  = typeorlen;

    /* Make room for 802.11 header */
    /* For now send only QoS frames in this simulation */
    if (!IEEE80211_IS_MULTICAST(eth_hdr.ether_dhost)) {

        /* Peregrine does not need IV padding for QoS frame */
        hdrsize = sizeof(struct ieee80211_qosframe);
        if (adf_nbuf_push_head(nbuf, hdrsize) == NULL) {
            adf_os_print("### Raw Mode simulation encap: No headroom for 80211 "
                         "header\n");
            return -1;
        }
        adf_os_mem_set(adf_nbuf_data(nbuf), 0, hdrsize);
        wh = (struct ieee80211_frame *) adf_nbuf_data(nbuf);
        wh->i_fc[0] = IEEE80211_FC0_SUBTYPE_QOS;
    } else {
        hdrsize = sizeof(struct ieee80211_frame);
        if (adf_nbuf_push_head(nbuf, hdrsize) == NULL) {
            adf_os_print("### Raw Mode simulation encap: No headroom for 80211 "
                         "header\n");
            return -1;
        }
        adf_os_mem_set(adf_nbuf_data(nbuf), 0, hdrsize);
        wh = (struct ieee80211_frame *) adf_nbuf_data(nbuf);
        wh->i_fc[0] = IEEE80211_FC0_SUBTYPE_DATA;
    }

    /* We don't currently support IBSS */
    adf_os_assert_always(mode != IEEE80211_M_IBSS);

    if (mode == IEEE80211_M_STA) {
        IEEE80211_ADDR_COPY(wh->i_addr1, bssid);
        IEEE80211_ADDR_COPY(wh->i_addr2, eth_hdr.ether_shost);
        IEEE80211_ADDR_COPY(wh->i_addr3, eth_hdr.ether_dhost);
        wh->i_fc[1] = IEEE80211_FC1_DIR_TODS;
    } else if (mode == IEEE80211_M_HOSTAP) {
        IEEE80211_ADDR_COPY(wh->i_addr1, eth_hdr.ether_dhost);
        IEEE80211_ADDR_COPY(wh->i_addr2, bssid);
        IEEE80211_ADDR_COPY(wh->i_addr3, eth_hdr.ether_shost);
        wh->i_fc[1] = IEEE80211_FC1_DIR_FROMDS;
    }

    wh->i_fc[0] |= (IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_DATA);

    /* We let the callers maintain encap stats in case they'd like to account for
     * additional factors.
     */

    return 0;
}

/**
 * @brief Encap 802.11 AMSDU lead network buffer
 * @details
 *   This function encaps the lead network buffer in a chain of fragments
 *   into the header and initial MSDU in an 802.11 AMSDU bearing MPDU.
 *   The emphasis is on testability, hence certain potential optimizations have
 *   not been carried out.
 *
 * @param mpdu  - nbuf bearing the first Ethernet II frame.
 * @param mode  - The operating mode.
 * @param bssid - The BSSID under which the MPDU is to be sent.
 * @return Integer status value.
 *      0  -> Success
 *      -1 -> Failure
 */
static int encap_eth_to_dot11_amsdu(adf_nbuf_t nbuf,
                                        enum ieee80211_opmode mode,
                                        u_int8_t *bssid)
{
    u_int8_t *datap;
    u_int32_t hdrsize;
    struct ether_header eth_hdr;
    struct ieee80211_qosframe *wh;

    adf_os_assert_always(nbuf != NULL);

    datap = adf_nbuf_data(nbuf);

    /*
     * Save addresses to be inserted later. Both destination and source
     * addresses get copied in one operation.
     */
    adf_os_mem_copy(eth_hdr.ether_dhost, datap, IEEE80211_ADDR_LEN * 2);


    /* Make room for 802.11 header */
    /* For now send only QoS frames in this simulation */

    /* Peregrine does not need IV padding for QoS frame */
    hdrsize = sizeof(struct ieee80211_qosframe);
    if (adf_nbuf_push_head(nbuf, hdrsize) == NULL) {
        adf_os_print("### Raw Mode simulation encap: No headroom for 80211 "
                     "header\n");
        return -1;
    }
    adf_os_mem_set(adf_nbuf_data(nbuf), 0, hdrsize);
    wh = (struct ieee80211_qosframe *) adf_nbuf_data(nbuf);
    wh->i_fc[0] = IEEE80211_FC0_SUBTYPE_QOS;
    wh->i_qos[0] |= (1 << IEEE80211_QOS_AMSDU_S) & IEEE80211_QOS_AMSDU;

   /* We don't currently support IBSS */
   adf_os_assert_always(mode != IEEE80211_M_IBSS);

    if (mode == IEEE80211_M_STA) {
        IEEE80211_ADDR_COPY(wh->i_addr1, bssid);
        IEEE80211_ADDR_COPY(wh->i_addr2, eth_hdr.ether_shost);
        IEEE80211_ADDR_COPY(wh->i_addr3, eth_hdr.ether_dhost);
        wh->i_fc[1] = IEEE80211_FC1_DIR_TODS;
    } else if (mode == IEEE80211_M_HOSTAP) {
        IEEE80211_ADDR_COPY(wh->i_addr1, eth_hdr.ether_dhost);
        IEEE80211_ADDR_COPY(wh->i_addr2, bssid);
        IEEE80211_ADDR_COPY(wh->i_addr3, eth_hdr.ether_shost);
        wh->i_fc[1] = IEEE80211_FC1_DIR_FROMDS;
    }

    wh->i_fc[0] |= (IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_DATA);

    /* We let the callers maintain encap stats in case they'd like to account for
     * additional factors.
     */

    return 0;
}

/**
 * @brief Encap an Ethernet II frame into an 802.11 AMSDU Subframe
 * @details
 *   This function forms a single AMSDU Subframe
 *   corresponding to an Ethernet II frame
 *
 * @param mpdu  - nbuf bearing the Ethernet II frame.
 * @return Integer status value.
 *      0  -> Success
 *      -1 -> Failure
 */
static int form_amsdu_packet(adf_nbuf_t nbuf)
{
    u_int8_t *datap;
    u_int16_t typeorlen, length;
    u_int32_t padding;
    struct ether_header eth_hdr;
    struct llc *llcHdr;

    adf_os_assert_always(nbuf != NULL);

    if (adf_nbuf_headroom(nbuf) <
         (sizeof(struct ieee80211_qosframe) +  sizeof(*llcHdr)))
    {
        adf_os_print("### Raw Mode simulation encap: Don't have enough "
                     "headroom\n");
        return -1;
    }
    datap = adf_nbuf_data(nbuf);

    typeorlen = *(u_int16_t *)(datap + IEEE80211_ADDR_LEN * 2);

    /*
     * Save addresses to be inserted later. Both destination and source
     * addresses get copied in one operation.
     */
    adf_os_mem_copy(eth_hdr.ether_dhost, datap, IEEE80211_ADDR_LEN * 2);

    /*
     * Make room for LLC + SNAP headers
     */
    if (adf_nbuf_push_head(nbuf, sizeof(*llcHdr)) == NULL) {
        adf_os_print("### Raw Mode simulation encap: Failed to push LLC "
                     "header\n");
        return -1;
    }

    length = adf_nbuf_len(nbuf);
    eth_hdr.ether_type = htons(length - 14);

    datap = adf_nbuf_data(nbuf);
    adf_os_mem_copy(datap, &eth_hdr, sizeof(eth_hdr));
    datap = adf_nbuf_data(nbuf) + sizeof(eth_hdr);

    llcHdr = (struct llc *)(datap);
    llcHdr->llc_dsap                     = LLC_SNAP_LSAP;
    llcHdr->llc_ssap                     = LLC_SNAP_LSAP;
    llcHdr->llc_un.type_snap.control     = LLC_UI;
    llcHdr->llc_un.type_snap.org_code[0] = RFC1042_SNAP_ORGCODE_0;
    llcHdr->llc_un.type_snap.org_code[1] = RFC1042_SNAP_ORGCODE_1;
    llcHdr->llc_un.type_snap.org_code[2] = RFC1042_SNAP_ORGCODE_2;
    llcHdr->llc_un.type_snap.ether_type  = typeorlen;

    /* Padding is not required for last msdu */
    if (nbuf->next) {
        padding = length & 0x03;
        datap = adf_nbuf_data(nbuf);
        adf_nbuf_put_tail(nbuf, padding);
        adf_os_mem_set(datap + length , 0, padding);
    }

    return 0;
} 

static int check_ip_pkt(adf_nbuf_t nbuf)
{
    u_int16_t typeorlen;

    adf_os_assert_always(nbuf != NULL);

    typeorlen = *((u_int16_t *)(adf_nbuf_data(nbuf) + IEEE80211_ADDR_LEN * 2));

    if (ntohs(typeorlen) == ETHERTYPE_IP) {
        return 1;
    } else {
        return 0;
    }
}

static int check_ip_more_frag(adf_nbuf_t nbuf) 
{
    struct iphdr *ip = NULL;

    adf_os_assert_always(nbuf != NULL);

    ip = (struct iphdr*)(adf_nbuf_data(nbuf) + sizeof(struct ether_header));
    if (ip->frag_off & htons(IP_MF)) {
        return 1;
    } else {
        return 0;
    }
}

static int check_multicast(adf_nbuf_t nbuf)
{
    struct ether_header *eth_hdr;

    adf_os_assert_always(nbuf != NULL);

    eth_hdr = (struct ether_header *)adf_nbuf_data(nbuf);
   
    if (IEEE80211_IS_MULTICAST(eth_hdr->ether_dhost)) {
        return 1;
    } else {
        return 0;
    }
}

static void
ol_rsim_txstats_inc_mpdu_noamsdu(ol_txrx_vdev_handle vdev)
{
    vdev->rsim_txstats.num_tx_mpdu_noamsdu++;
}

static void
ol_rsim_txstats_inc_mpdu_withamsdu(ol_txrx_vdev_handle vdev)
{
    vdev->rsim_txstats.num_tx_mpdu_withamsdu++;
}


/* APIs */

void
ol_rsim_rx_decap(struct ol_txrx_vdev_t *vdev,
        struct ol_txrx_peer_t *peer,
        adf_nbuf_t *pdeliver_list_head,
        adf_nbuf_t *pdeliver_list_tail)
{
   int is_amsdu = 0;
   u_int8_t is_chfrag_start = 0;
   u_int8_t is_chfrag_end = 0;
   int ret;
   adf_nbuf_t nbuf = NULL;
   adf_nbuf_t deliver_sublist_head = NULL;
   adf_nbuf_t deliver_sublist_tail = NULL;
   u_int32_t total_mpdu_len = 0;
   ol_txrx_pdev_handle pdev = vdev->pdev;
   struct ol_ath_softc_net80211 *scn =
                      (struct ol_ath_softc_net80211 *)pdev->ctrl_pdev;
   struct ieee80211vap *vap = ol_ath_vap_get(scn, vdev->vdev_id);
   adf_nbuf_t tmpskb = NULL;
   int index = 0;
   adf_nbuf_t  prev = NULL;
   adf_nbuf_t  next = NULL;

   if ((pdeliver_list_head == NULL) || (*pdeliver_list_head == NULL)) {
        adf_os_print("List head/pointer to list head is NULL\n");
        return;
   }

   if ((pdeliver_list_tail == NULL) || (*pdeliver_list_tail == NULL)) {
        adf_os_print("List tail/pointer to list tail is NULL\n");
        return;
   }
 
   if (vap == NULL) {
        adf_os_print("vap is NULL\n");
        return;
   }

   nbuf = *pdeliver_list_head;

   while (nbuf) {
       is_amsdu = is_80211amsdu(nbuf);
       is_chfrag_start = adf_nbuf_is_chfrag_start(nbuf);

       /* Note: Preferably do not change order of below if-else checks.
        * They are in order of descending probability, except for the
        * initial error check.
        *
        * Note: Due to subtle differences in the actions to be taken for
        * each of the below scenarios, we do not derive common routines
        * beyond a certain point.
        */
       if (is_amsdu < 0) {
           /* Discard the nbuf(s) */
           next = adf_nbuf_next(nbuf);

           OL_TXRX_NODE_DELETE(*pdeliver_list_head,
                   *pdeliver_list_tail,
                   prev,
                   nbuf);

           nbuf = next;

           if (is_chfrag_start && nbuf) {
               while(nbuf) {
                    next = adf_nbuf_next(nbuf);
                    is_chfrag_end = adf_nbuf_is_chfrag_end(nbuf);
                    OL_TXRX_NODE_DELETE(*pdeliver_list_head,
                           *pdeliver_list_tail,
                           prev,
                           nbuf);

                    nbuf = next;

                    if (is_chfrag_end) {
                        break;
                    }
               }
           }
       } else if (!is_amsdu && !is_chfrag_start) {
           next = adf_nbuf_next(nbuf);

           if (vap->iv_rawmodesim_debug) {
               adf_os_print("Rx 802.11 packet hexdump before decap\n");
               RAWSIM_PKT_HEXDUMP(adf_nbuf_data(nbuf), adf_nbuf_len(nbuf));
           }
           ret = decap_dot11_to_8023(nbuf, peer);
           if (vap->iv_rawmodesim_debug) {
               adf_os_print("Rx Ethernet II packet hexdump after decap\n");
               RAWSIM_PKT_HEXDUMP(adf_nbuf_data(nbuf), adf_nbuf_len(nbuf));
           }

           if (ret < 0) {
               OL_TXRX_NODE_DELETE(*pdeliver_list_head,
                       *pdeliver_list_tail,
                       prev,
                       nbuf);
           } else {
               vdev->rsim_rxstats.num_rx_mpdu_noamsdu++;
               prev = nbuf;
           }

           nbuf = next;
       } else if (is_amsdu && is_chfrag_start) {
           deliver_sublist_head = nbuf;
           total_mpdu_len = 0;

           while(nbuf && !adf_nbuf_is_chfrag_end(nbuf)) {
               total_mpdu_len += adf_nbuf_len(nbuf);
               nbuf = adf_nbuf_next(nbuf); 
           }

           if (!nbuf) {
               adf_os_print(
                   "Unterminated fragment chain received!! Discarding.\n");

               deliver_sublist_tail = *pdeliver_list_tail;
               if (deliver_sublist_tail) {
                   OL_TXRX_SUBLIST_DELETE(*pdeliver_list_head,
                           *pdeliver_list_tail,
                           prev,
                           deliver_sublist_head,
                           deliver_sublist_tail);
               }
               break;
           }

           total_mpdu_len += adf_nbuf_len(nbuf);
           deliver_sublist_tail = nbuf;
           next = adf_nbuf_next(deliver_sublist_tail);

           if (vap->iv_rawmodesim_debug) {
               adf_os_print("Rx 802.11 packet hexdump before decap\n");
               for (index = 0, tmpskb = deliver_sublist_head;
                       tmpskb != deliver_sublist_tail; 
                       tmpskb = adf_nbuf_next(tmpskb)) {
                   adf_os_print("Framgment No : %d\n", ++index);
                   RAWSIM_PKT_HEXDUMP(adf_nbuf_data(tmpskb),
                                      adf_nbuf_len(tmpskb));
               }
           }
           ret = decap_dot11withamsdu_to_8023(pdev,
                       vdev,
                       &deliver_sublist_head,
                       &deliver_sublist_tail,
                       total_mpdu_len,
                       peer);

           if (ret < 0) {
               OL_TXRX_SUBLIST_DELETE(*pdeliver_list_head,
                       *pdeliver_list_tail,
                       prev,
                       deliver_sublist_head,
                       deliver_sublist_tail);
           } else {
               if (vap->iv_rawmodesim_debug) {
                   adf_os_print("Rx Ethernet II packet hexdump after decap\n");
                   for (index = 0, tmpskb = deliver_sublist_head;
                           tmpskb != deliver_sublist_tail; 
                           tmpskb = adf_nbuf_next(tmpskb)) {
                       printk("Framgment No : %d\n", ++index);
                       RAWSIM_PKT_HEXDUMP(adf_nbuf_data(tmpskb),
                                          adf_nbuf_len(tmpskb));
                   }
               }
               /* Stitch new nbufs back into main list */
               prev = deliver_sublist_tail;
               adf_nbuf_set_next(deliver_sublist_tail, next);
               if (nbuf == *pdeliver_list_tail) {
                   *pdeliver_list_tail = deliver_sublist_tail;
               }

               vdev->rsim_rxstats.num_rx_largempdu_withamsdu++;
           }

           nbuf = next;
       } else if (is_amsdu && !is_chfrag_start) {
           next = adf_nbuf_next(nbuf);
           /* This will be populated by decap_dot11withamsdu_to_8023() */
           deliver_sublist_tail = NULL;
           if (vap->iv_rawmodesim_debug) {
               adf_os_print("Rx 802.11 packet hexdump before decap\n");
               RAWSIM_PKT_HEXDUMP(adf_nbuf_data(nbuf), adf_nbuf_len(nbuf));
           }
           ret = decap_dot11withamsdu_to_8023(pdev,
                       vdev,
                       &nbuf,
                       &deliver_sublist_tail,
                       adf_nbuf_len(nbuf),
                       peer);

           if (ret < 0) {
               OL_TXRX_NODE_DELETE(*pdeliver_list_head,
                       *pdeliver_list_tail,
                       prev,
                       nbuf);
           } else {
               if (vap->iv_rawmodesim_debug) {
                   adf_os_print("Rx Ethernet II packet hexdump after decap\n");
                   for (index = 0, tmpskb = nbuf; 
                           tmpskb != deliver_sublist_tail; 
                           tmpskb = adf_nbuf_next(tmpskb)) {
                       printk("Framgment No : %d\n", ++index);
                       RAWSIM_PKT_HEXDUMP(adf_nbuf_data(tmpskb),
                                          adf_nbuf_len(tmpskb));
                   }
               }

               /* Stitch new nbufs back into main list */
               prev = deliver_sublist_tail;
               adf_nbuf_set_next(deliver_sublist_tail, next);
               if (nbuf == *pdeliver_list_tail) {
                   *pdeliver_list_tail = deliver_sublist_tail;
               }

               vdev->rsim_rxstats.num_rx_smallmpdu_withamsdu++;
           }

           nbuf = next;
       } else {
           /* !is_amsdu && is_chfrag_start */
           adf_os_print(
               "Fragmented MPDU without A-MSDU not currently handled!!\n");

           vdev->rsim_rxstats.num_rx_chainedmpdu_noamsdu++;

           /* Discard the entire chain */
           while(nbuf) {
               next = adf_nbuf_next(nbuf);
               is_chfrag_end = adf_nbuf_is_chfrag_end(nbuf);
               OL_TXRX_NODE_DELETE(*pdeliver_list_head,
                       *pdeliver_list_tail,
                       prev,
                       nbuf);
               nbuf = next;

               if (is_chfrag_end) {
                   break;
               }
           }
       }
   }
}

int
ol_rsim_tx_encap(ol_txrx_vdev_handle vdev, adf_nbuf_t *pnbuf)
{   
    u_int8_t bssid[IEEE80211_ADDR_LEN];
    int is_ip_pkt = 0;
    static u_int8_t frag_count = 0;
    u_int8_t more_frag = 0;
    static adf_nbuf_t nbuf_list_head = NULL, nbuf_list_tail = NULL;
    struct sk_buff *tmpnbuf, *nextchnbuf; /* next chained nbuf */
    ol_txrx_pdev_handle pdev = vdev->pdev;
    struct ol_ath_softc_net80211 *scn =
                      (struct ol_ath_softc_net80211 *)pdev->ctrl_pdev;
    struct ieee80211vap *vap = ol_ath_vap_get(scn, vdev->vdev_id);

    if (vap == NULL) {
         adf_os_print("vap is NULL\n");
         return -1;
    }

    if(vap->iv_rawmodesim_debug) {
        printk("Tx Ethernet II type packet hexdump before encap\n");
        RAWSIM_PKT_HEXDUMP(adf_nbuf_data(*pnbuf), adf_nbuf_len(*pnbuf));
    }

    is_ip_pkt = check_ip_pkt(*pnbuf); 
    wlan_vap_get_bssid(vap, bssid);
    
    /* For Non IP packet & Multicast packet, don't do fragmentation */
    if (is_ip_pkt && !check_multicast(*pnbuf)) {
        more_frag = check_ip_more_frag(*pnbuf);
        if (!more_frag && (nbuf_list_head == NULL)) {
            /* SW encapsulation */
            if(encap_eth_to_dot11(*pnbuf, wlan_vap_get_opmode(vap), bssid)) {
                return -1;
            }

            ol_rsim_txstats_inc_mpdu_noamsdu(vdev);
            adf_nbuf_set_next(*pnbuf, NULL);
        } else {
            /* Create chained nbufs by splitting up incoming nbuf into two
             * parts, each corresponding to an MSDU. The two MSDUs are
             * encapped into an A-MSDU (distributed across 2 nbufs).
             */
            adf_nbuf_set_next(*pnbuf, NULL);
            RAWSIM_TX_FRAG_LIST_APPEND(nbuf_list_head, nbuf_list_tail, *pnbuf);
            frag_count++;

            if (!more_frag || (frag_count == 2)) {
                *pnbuf = nbuf_list_head;

                while (nbuf_list_head) {
                    struct sk_buff *next = adf_nbuf_next(nbuf_list_head);
                    if (form_amsdu_packet(nbuf_list_head)) {
                        return -1;
                    }
                    nbuf_list_head = next;
                }
                /* Emptying out the temporary holding area */
                nbuf_list_head = NULL;
                nbuf_list_tail = NULL;
                frag_count = 0;
                /* SW encapsulation */
                if(encap_eth_to_dot11_amsdu(*pnbuf,
                            wlan_vap_get_opmode(vap), bssid)) {
                    return -1;
                }

                ol_rsim_txstats_inc_mpdu_withamsdu(vdev);
            } else {
                return 1;
            }
        }
    } else {
        /* SW encapsulation */
        if(encap_eth_to_dot11(*pnbuf, wlan_vap_get_opmode(vap), bssid)) {
            return -1;
        }

        ol_rsim_txstats_inc_mpdu_noamsdu(vdev);
        adf_nbuf_set_next(*pnbuf, NULL);
    }

    if(vap->iv_rawmodesim_debug) {
        tmpnbuf = *pnbuf;
        int i = 0;
        adf_os_print("Tx 802.11 packet hexdump after encap\n");
        while (*pnbuf) {
            nextchnbuf = adf_nbuf_next(*pnbuf);
            if (adf_nbuf_next(tmpnbuf) != NULL) {
                adf_os_print("Fragment No. %d\n", ++i);
            }

            RAWSIM_PKT_HEXDUMP(adf_nbuf_data(*pnbuf), adf_nbuf_len(*pnbuf));
            *pnbuf = nextchnbuf;
        }
        *pnbuf = tmpnbuf;
    }

    return 0;
}

void
ol_txrx_print_rawmode_pkt_sim_stats(ol_txrx_vdev_handle vdev)
{
   adf_os_print("\nRaw Mode simulation module internal statistics:\n"
                "Note: These do not cover events outside the simulation \n"
                "module, such as higher layer failure to process successfully\n"
                "decapped MPDUs, etc. \n\n");
   
   adf_os_print("Rx side:\n");
   adf_os_print("--------\n\n");

   adf_os_print("Decap successes:\n");
   adf_os_print("Number of non-AMSDU bearing MPDUs decapped = %llu\n",
                vdev->rsim_rxstats.num_rx_mpdu_noamsdu);
   adf_os_print("Number of A-MSDU bearing MPDUs (fitting within single nbuf)"
                "decapped = %llu\n",
                vdev->rsim_rxstats.num_rx_smallmpdu_withamsdu);
   adf_os_print("Number of A-MSDU bearing MPDUs (requiring multiple nbufs) "
                "decapped = %llu\n",
                vdev->rsim_rxstats.num_rx_largempdu_withamsdu);

   adf_os_print("\nDecap errors\n");
   adf_os_print("Number of MSDUs (contained in A-MSDU) with invalid length "
                "field = %llu\n",
                vdev->rsim_rxstats.num_rx_inval_len_msdu);
   adf_os_print("Number of A-MSDU bearing MPDUs which are shorter than expected "
                "from parsing A-MSDU fields = %llu\n",
                vdev->rsim_rxstats.num_rx_tooshort_mpdu);
   adf_os_print("Number of A-MSDU bearing MPDUs received which are longer than "
                "expected from parsing A-MSDU fields = %llu\n",
                vdev->rsim_rxstats.num_rx_toolong_mpdu);
   adf_os_print("Number of non-AMSDU bearing MPDUs (requiring multiple nbufs) "
                "seen (unhandled and discarded) = %llu\n",
                vdev->rsim_rxstats.num_rx_chainedmpdu_noamsdu);

   adf_os_print("\nTx side:\n");
   adf_os_print("--------\n\n");

   adf_os_print("Number of non-AMSDU bearing MPDUs encapped = %llu\n",
                vdev->rsim_txstats.num_tx_mpdu_noamsdu);

   adf_os_print("Number of A-MSDU bearing MPDUs encapped = %llu\n",
                vdev->rsim_txstats.num_tx_mpdu_withamsdu);

   adf_os_print("\n");
}

void
ol_txrx_clear_rawmode_pkt_sim_stats(ol_txrx_vdev_handle vdev)
{
    OS_MEMZERO(&vdev->rsim_rxstats, sizeof(vdev->rsim_rxstats));
    OS_MEMZERO(&vdev->rsim_txstats, sizeof(vdev->rsim_txstats));
}

#endif /* QCA_SUPPORT_RAWMODE_PKT_SIMULATION */
