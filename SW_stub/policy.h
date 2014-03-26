//
//  policy.h
//  P33
//
//  Created by Charlie Bashford on 20/03/2014.
//  Copyright (c) 2014 Charlie Bashford. All rights reserved.
//

#ifndef POLICY_H
#define POLICY_H

#include "sr_router.h"
#include "lwip/cc.h"
#include "lwip/ip_addr.h"

#define ESP_HEADER_LENGTH 8
#define ESP_TAIL_LENGTH 2+16
#define ESP_PACKET_LENGTH(len) (len+ESP_HEADER_LENGTH+ESP_TAIL_LENGTH)

struct esp_hdr {
    PACK_STRUCT_FIELD(uint32_t _spi);
    PACK_STRUCT_FIELD(uint32_t _seq_no);
} PACK_STRUCT_STRUCT;

#define ESP_SPI(hdr) (ntohl((hdr)->_spi))
#define ESP_SEQ_NO(hdr) (ntohl((hdr)->_seq_no))

#define ESP_SPI_SET(hdr, spi) (hdr)->_spi = (htonl(spi))
#define ESP_SEQ_NO_SET(hdr, seq_no) (hdr)->_seq_no = (htonl(seq_no))

struct esp_tail {
    uint8_t _pad_len;
    uint8_t _next_hdr;
    uint8_t icv[16];
} PACK_STRUCT_STRUCT;

#define ESP_PAD_LEN(hdr) ((hdr)->_pad_len)
#define ESP_NEXT_HDR(hdr) ((hdr)->_next_hdr)

#define ESP_PAD_LEN_SET(hdr, pad_len) (hdr)->_pad_len = (pad_len)
#define ESP_NEXT_HDR_SET(hdr, next_hdr) (hdr)->_next_hdr = (next_hdr)


void handle_IP_ENCAP_packet(packet_info_t *pi);

uint8_t *add_ESP_packet(uint8_t *payload, unsigned offset, uint32_t spi, uint32_t seq_no, uint8_t pad_len, uint8_t next_hdr, char *secret, int len);

void calc_sha256(uint8_t answer[16], uint8_t *payload, unsigned offset, unsigned len, char *secret);

void free_policy(policy_t *policy);

policy_t *router_find_matching_policy_sending( router_t* router, addr_ip_t matching_src_ip, addr_ip_t matching_dest_ip);

policy_t *router_find_matching_policy_receiving( router_t* router, addr_ip_t matching_src_ip, addr_ip_t matching_dest_ip, addr_ip_t matching_local_end, addr_ip_t matching_remote_end);

void router_add_policy( router_t* router, addr_ip_t src_ip, addr_ip_t src_mask, addr_ip_t dest_ip, addr_ip_t dest_mask, addr_ip_t local_end, addr_ip_t remote_end, const char *secret, uint8_t encrypt_rot, uint32_t spi);

policy_t *router_find_policy_entry( router_t *router, addr_ip_t src_ip, addr_ip_t src_mask, addr_ip_t dest_ip, addr_ip_t dest_mask, addr_ip_t local_end, addr_ip_t remote_end);

bool router_delete_policy_entry( router_t *router, addr_ip_t src_ip, addr_ip_t src_mask, addr_ip_t dest_ip, addr_ip_t dest_mask, addr_ip_t local_end, addr_ip_t remote_end);

void router_delete_all_policy( router_t *router);

#endif
