//
//  icmp.h
//  P33
//
//  Created by Charlie Bashford on 12/03/2014.
//  Copyright (c) 2014 Charlie Bashford. All rights reserved.
//

#ifndef ICMP_H
#define ICMP_H

#include "sr_common.h"
#include "sr_router.h"

#define ICMP_TIME_EX_IP_HEADER_OFFSET 8

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_ECHO_REQUEST 8

bool handle_ICMP_packet(packet_info_t *pi);

bool generate_response_ICMP_packet(packet_info_t *pi, int type, int code);

void send_ping(router_t *router, addr_ip_t dest_ip, addr_ip_t src_ip, uint16_t id, uint16_t count);

void handle_ping_reply(packet_info_t *pi);

#endif
