//
//  ip.c
//  P33
//
//  Created by Charlie Bashford on 12/03/2014.
//  Copyright (c) 2014 Charlie Bashford. All rights reserved.
//

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "ip.h"
#include "sr_common.h"
#include "lwtcp/lwip/ip.h"
#include "sr_router.h"
#include "icmp.h"

void handle_IPv4_packet(packet_info_t *pi) {
    printf("Packet is IPv4\n");
    /*unsigned i;
     for (i = 0; i < pi->len; i += 2)
     printf("%02X%02X ", *(pi->packet+i),*(pi->packet+i+1));
     printf("\n");*/
    
    struct ip_hdr *iphdr = (void *)pi->packet+IPV4_HEADER_OFFSET;
    
    uint8_t IHL = IPH_HL(iphdr);
    if (IHL > 5) {
        printf("Options in IPv$ packet, dropping packet!\n");
    } else if (IHL < 5) {
        printf("Incomplete packet, dropping packet!\n");
        return;
    }
    
    /*if (ntohs(IPH_LEN(iphdr)) != pi->len-IPV4_HEADER_OFFSET) {
     unsigned i;
     for (i = 0; i < pi->len; i += 2)
     printf("%02X%02X ", *(pi->packet+i),*(pi->packet+i+1));
     printf("\n");
     printf("Incomplete packet, missing %d bytes, dropping packed!\n", (ntohs(IPH_LEN(iphdr))-(pi->len-IPV4_HEADER_OFFSET)));
     return;
     }*/
    
    if (calc_checksum(pi->packet+IPV4_HEADER_OFFSET, 20)) {
        printf("Checksum failed, dropping packet!\n");
        return;
    }
    char ip_str[16];
    ip_to_string(ip_str, IPH_DEST(iphdr));
    if (router_lookup_interface_via_ip(get_router(), IPH_DEST(iphdr)) || IPH_DEST(iphdr) == OSPF_IP) {
        printf("Packet for router!\n");
        uint8_t protocol = IPH_PROTO(iphdr);
        
        switch (protocol) {
            case ICMP_PROTOCOL:
                if (handle_ICMP_packet(pi)) return;
                IPH_TTL_SET(iphdr, 33); //Will be decreased, so ends up at 32.
                swap_bytes(&IPH_SRC(iphdr), &IPH_DEST(iphdr), 4);
                swap_bytes(pi->packet+6, pi->packet, 6);
                break;
            case TCP_PROTOCOL:
                handle_TCP_packet(pi);
                return;
                break;
            case PWOSPF_PROTOCOL:
                handle_PWOSPF_packet(pi);
                return;
                break;
            default:
                printf("Generating protocol unreachable packet!\n");
                if (generate_response_ICMP_packet(pi, 3, 2)) return;
                iphdr = (void *)pi->packet+IPV4_HEADER_OFFSET;
                break;
                
        }
        
    }
    if (IPH_TTL(iphdr) > 1) {
        IPH_TTL_DEC(iphdr);
    } else {
        printf("Generating time exceeded packet!\n");
        if (generate_response_ICMP_packet(pi, 11, 0)) return;
        iphdr = (void *)pi->packet+IPV4_HEADER_OFFSET;
    }
    IPH_CHKSUM_SET(iphdr, 0);
    IPH_CHKSUM_SET(iphdr, htons(calc_checksum(pi->packet+IPV4_HEADER_OFFSET, 20)));
    
    addr_ip_t target_ip = sr_integ_findnextip(IPH_DEST(iphdr));
    char target_ip_str[16];
    ip_to_string(target_ip_str, target_ip);
    printf("Sending packet to %s via %s\n",  ip_str, target_ip_str);
    send_packet(pi->packet+14, IPH_SRC(iphdr), target_ip, pi->len-14, FALSE, FALSE);
}

void handle_TCP_packet(packet_info_t *pi) {
    printf("Recieved a TCP packet:\n");
    sr_transport_input(pi->packet+IPV4_HEADER_OFFSET);
    printf("Called sr_transport_input\n");
}

uint16_t calc_checksum(byte *header, int len) {
    uint32_t total = 0;
    uint16_t *data = (uint16_t *) header;
    unsigned i;
    for (i = 0; i < len/2; i++) {
        total += ntohs(data[i]);
    }
    uint16_t checksum = (total >> 16) + (total & 0xffff);
    
    return ~checksum;
}

uint8_t *add_IPv4_header(uint8_t* payload, uint8_t  proto, uint32_t src, uint32_t dest, int len) {
    printf("Adding IPv4 header.\n");
    /*unsigned i;
     for (i = 0; i < len; i++)
     printf("(%d %02X) ", i, (int)*(payload+i));
     printf("\n");*/
    
    byte *ipv4_packet = malloc((20+len)*sizeof(byte)); //TODO: Free!
    struct ip_hdr *iphdr;
    
    iphdr = (void *)ipv4_packet;
    IPH_VHLTOS_SET(iphdr, 4, 5, 16);
    IPH_LEN_SET(iphdr, htons(len+20));
    IPH_TTL_SET(iphdr, 32);
    IPH_PROTO_SET(iphdr, proto);
    iphdr->src.addr = src;
    iphdr->dest.addr = dest;
    IPH_CHKSUM_SET(iphdr, htons(calc_checksum(ipv4_packet, 20)));
    
    memcpy(ipv4_packet+20, payload, len);
    payload = malloc((20+len)*sizeof(byte));
    memcpy(payload, ipv4_packet, len+20);
    len += 20;
    return payload;
}



void handle_no_route_to_host(packet_info_t *pi) {
    printf("No route to host!\n");
    
    if (generate_response_ICMP_packet(pi, 3, 0)) return;
    struct ip_hdr *iphdr = (void *)pi->packet+IPV4_HEADER_OFFSET;
    
    IPH_CHKSUM_SET(iphdr, 0);
    IPH_CHKSUM_SET(iphdr, htons(calc_checksum(pi->packet+IPV4_HEADER_OFFSET, 20)));
    
    addr_ip_t target_ip = sr_integ_findnextip(IPH_DEST(iphdr));
    char target_ip_str[16];
    ip_to_string(target_ip_str, target_ip);
    printf("target_ip=%s\n", target_ip_str);
    
    send_packet(pi->packet+14, IPH_SRC(iphdr), target_ip, pi->len-14, FALSE, FALSE);
}
