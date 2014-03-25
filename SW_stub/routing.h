//
//  routing.h
//  P33
//
//  Created by Charlie Bashford on 12/03/2014.
//  Copyright (c) 2014 Charlie Bashford. All rights reserved.
//

#ifndef ROUTING_H
#define ROUTING_H

#include "lwip/cc.h"
#include "lwip/ip_addr.h"
#include "sr_router.h"

#define PWOSPF_HEADER_LENGTH 24
#define LSU_HEADER_LENGTH 8
#define LSU_HEADER_LENGTH 8
#define LSU_AD_LENGTH 12
#define HELLO_HEADER_LENGTH 8

#define TYPE_HELLO 1
#define TYPE_LSU 4


struct pwospf_hdr {
    PACK_STRUCT_FIELD(uint16_t _ver_type);
    PACK_STRUCT_FIELD(uint16_t _packet_len);
    PACK_STRUCT_FIELD(uint32_t _router_id);
    PACK_STRUCT_FIELD(uint32_t _area_id);
    PACK_STRUCT_FIELD(uint16_t _chksum);
    PACK_STRUCT_FIELD(uint16_t _au_type);
    PACK_STRUCT_FIELD(uint64_t _auth);
} PACK_STRUCT_STRUCT;

#define PWHDR_VER(hdr) (NTOHS((hdr)->_ver_type) >> 8)
#define PWHDR_TYPE(hdr) (NTOHS((hdr)->_ver_type) & 0xff)
#define PWHDR_LEN(hdr) ((hdr)->_packet_len)
#define PWHDR_ROUTER_ID(hdr) ((hdr)->_router_id)
#define PWHDR_AREA_ID(hdr) ((hdr)->_area_id)
#define PWHDR_CHKSUM(hdr) ((hdr)->_chksum)

#define PWHDR_VER_SET(hdr, ver) (hdr)->_ver_type = HTONS((ver) << 8 | PWHDR_TYPE(hdr))
#define PWHDR_TYPE_SET(hdr, type) (hdr)->_ver_type = HTONS(PWHDR_VER(hdr) << 8 | (type))
#define PWHDR_VER_TYPE_SET(hdr, ver, type) (hdr)->_ver_type = HTONS((ver) << 8 | (type))
#define PWHDR_LEN_SET(hdr, len) (hdr)->_packet_len = (len)
#define PWHDR_ROUTER_ID_SET(hdr, router_id) (hdr)->_router_id = (router_id)
#define PWHDR_AREA_ID_SET(hdr, area_id) (hdr)->_area_id = (area_id)
#define PWHDR_CHKSUM_SET(hdr, chksum) (hdr)->_chksum = (chksum)
#define PWHDR_AU_TYPE_SET(hdr, au_type) (hdr)->_au_type = (au_type)
#define PWHDR_AUTH_SET(hdr, auth) (hdr)->_auth = (auth)

struct hello_hdr {
    PACK_STRUCT_FIELD(uint32_t _sub_mask);
    PACK_STRUCT_FIELD(uint16_t _hello_int);
    PACK_STRUCT_FIELD(uint16_t _padding)
} PACK_STRUCT_STRUCT;

#define HEHDR_SUB_MASK(hdr) ((hdr)->_sub_mask)
#define HEHDR_HELLO_INT(hdr) ((hdr)->_hello_int)

#define HEHDR_SUB_MASK_SET(hdr, sub_mask) (hdr)->_sub_mask = (sub_mask)
#define HEHDR_HELLO_INT_SET(hdr, hello_int) (hdr)->_hello_int = (hello_int)
#define HEHDR_PADDING_SET(hdr) (hdr)->_padding = 0

struct lsu_hdr {
    PACK_STRUCT_FIELD(uint16_t _seq_no);
    PACK_STRUCT_FIELD(uint16_t _ttl);
    PACK_STRUCT_FIELD(uint32_t _advert_no);
};

#define LSHDR_SEQ_NO(hdr) ((hdr)->_seq_no)
#define LSHDR_TTL(hdr) ((hdr)->_ttl)
#define LSHDR_ADVERT_NO(hdr) ((hdr)->_advert_no)

#define LSHDR_TTL_DEC(hdr) (hdr)->_ttl = (htons(ntohs(LSHDR_TTL(hdr))-1))


#define LSHDR_SEQ_NO_SET(hdr, seq_no) (hdr)->_seq_no = (seq_no)
#define LSHDR_TTL_SET(hdr, ttl) (hdr)->_ttl = (ttl)
#define LSHDR_ADVERT_NO_SET(hdr, advert_no) (hdr)->_advert_no = (advert_no)

struct lsu_ad {
    PACK_STRUCT_FIELD(uint32_t _subnet_no);
    PACK_STRUCT_FIELD(uint32_t _mask);
    PACK_STRUCT_FIELD(uint32_t _router_id);
};

#define LSUAD_SUBNET_NO(hdr) ((hdr)->_subnet_no)
#define LSUAD_MASK(hdr) ((hdr)->_mask)
#define LSUAD_ROUTER_ID(hdr) ((hdr)->_router_id)

#define LSUAD_SUBNET_NO_SET(hdr, subnet_no) (hdr)->_subnet_no = (subnet_no)
#define LSUAD_MASK_SET(hdr, mask) (hdr)->_mask = (mask)
#define LSUAD_ROUTER_ID_SET(hdr, router_id) (hdr)->_router_id = (router_id)

void handle_PWOSPF_packet(packet_info_t *pi);

void print_database();

void update_routing_table();

void send_HELLO_packet(interface_t *intf);

void send_LSU_packet(unsigned seq_no);

void generate_HELLO_thread();

void router_add_route( router_t* router, addr_ip_t prefix, addr_ip_t next_hop,
                      addr_ip_t subnet_mask, const char *intf_name, bool dynamic);

route_t *router_find_route_entry( router_t *router, addr_ip_t dest, addr_ip_t gw, addr_ip_t mask, const char *intf_name);

bool router_delete_route_entry( router_t *router, addr_ip_t dest, addr_ip_t gw, addr_ip_t mask, const char *intf_name);

void router_delete_all_route_entries(router_t *router, bool dynamic);

void sr_read_routes_from_file( router_t* router, const char* filename );

link_t *database_find_link(database_entry_t *database_entry, uint32_t router_id, uint32_t subnet_no);

database_entry_t *router_find_database_entry( router_t* router, uint32_t router_id);

void router_add_link_to_database_entry( router_t *router, database_entry_t *database_entry, link_t *link_to_add);

bool router_remove_link_from_database_entry( router_t *router, database_entry_t *database_entry, uint32_t router_id);

void router_add_database_entry( router_t* router, uint32_t router_id, link_t link[], unsigned num_links, uint16_t seq_no, byte *packet, unsigned len);

int router_find_database_entry_position(router_t *router, uint32_t router_id);

#endif
