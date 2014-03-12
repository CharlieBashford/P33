//
//  arp.h
//  P33
//
//  Created by Charlie Bashford on 12/03/2014.
//  Copyright (c) 2014 Charlie Bashford. All rights reserved.
//

#ifndef ARP_H
#define ARP_H

#include "lwip/cc.h"
#include "lwip/ip_addr.h"
#include "sr_common.h"
#include "sr_router.h"
#include "sr_integration.h"


struct arp_hdr {
    PACK_STRUCT_FIELD(uint16_t _hard_type);
    PACK_STRUCT_FIELD(uint16_t _proto_type);
    uint8_t _hard_len;
    uint8_t _proto_len;
    PACK_STRUCT_FIELD(uint16_t _op);
    addr_mac_t _sender_mac;
    struct ip_addr _sender_ip;
    addr_mac_t _target_mac;
    struct ip_addr _target_ip;
} PACK_STRUCT_STRUCT;

#define ARH_HARD_TYPE(hdr) (ntohs((hdr)->_hard_type))
#define ARH_PROTO_TYPE(hdr) (ntohs((hdr)->_proto_type))
#define ARH_HARD_LEN(hdr) ((hdr)->_hard_len)
#define ARH_PROTO_LEN(hdr) ((hdr)->_proto_len)
#define ARH_OP(hdr) (ntohs((hdr)->_op))
#define ARH_SENDER_MAC(hdr) ((hdr)->_sender_mac)
#define ARH_SENDER_IP(hdr) ((hdr)->_sender_ip.addr)
#define ARH_TARGET_MAC(hdr) ((hdr)->_target_mac)
#define ARH_TARGET_IP(hdr) ((hdr)->_target_ip.addr)

#define ARH_HARD_TYPE_SET(hdr, hard_type) (hdr)->_hard_type = (htons(hard_type))
#define ARH_PROTO_TYPE_SET(hdr, proto_type) (hdr)->_proto_type = (htons(proto_type))
#define ARH_HARD_LEN_SET(hdr, hard_len) (hdr)->_hard_len = (hard_len)
#define ARH_PROTO_LEN_SET(hdr, proto_len) (hdr)->_proto_len = (proto_len)
#define ARH_OP_SET(hdr, op) (hdr)->_op = (htons(op))
#define ARH_SENDER_MAC_SET(hdr, sender_mac) (hdr)->_sender_mac = (sender_mac)
#define ARH_SENDER_IP_SET(hdr, sender_ip) (hdr)->_sender_ip.addr = (sender_ip)
#define ARH_TARGET_MAC_SET(hdr, target_mac) (hdr)->_target_mac = (target_mac)
#define ARH_TARGET_IP_SET(hdr, target_ip) (hdr)->_target_ip.addr = (target_ip)




void handle_ARP_packet(packet_info_t *pi);

void handle_not_repsponding_to_arp(byte *payload, unsigned len);

void generate_pending_ARP_thread();

void send_ARP_request(addr_ip_t ip, int num);

void router_add_arp_entry( router_t *router, addr_mac_t mac, addr_ip_t ip, bool dynamic);

bool router_delete_arp_entry( router_t *router, addr_ip_t ip);

void router_delete_all_arp_entries(router_t *router, bool dynamic);

ip_mac_t *router_find_arp_entry( router_t *router, addr_ip_t ip);

#endif
