//
//  ip.h
//  P33
//
//  Created by Charlie Bashford on 12/03/2014.
//  Copyright (c) 2014 Charlie Bashford. All rights reserved.
//

#ifndef IP_H
#define IP_H

#include "sr_common.h"
#include "sr_router.h"

#define ICMP_PROTOCOL 1
#define IP_ENCAP_PROTOCOL 4
#define TCP_PROTOCOL 6
#define ESP_PROTOCOL 50
#define PWOSPF_PROTOCOL 89

#define IPV4_HEADER_LENGTH 20
#define IPV4_HEADER_OFFSET 14

void handle_IPv4_packet(packet_info_t *pi);

void handle_TCP_packet(packet_info_t *pi);

uint16_t calc_checksum(byte *header, int len);

uint8_t *add_IPv4_header(uint8_t* payload, unsigned location, uint8_t  proto, uint32_t src, uint32_t dest, int len);

void handle_no_route_to_host(packet_info_t *pi);

#endif
