//
//  icmp.c
//  P33
//
//  Created by Charlie Bashford on 12/03/2014.
//  Copyright (c) 2014 Charlie Bashford. All rights reserved.
//

#include <stdio.h>
#include "icmp.h"
#include "lwtcp/lwip/ip.h"
#include "lwtcp/lwip/icmp.h"
#include "ip.h"

bool handle_ICMP_packet(packet_info_t *pi) {
    printf("Packet is ICMP\n");
    byte *icmp_packet = pi->packet+IPV4_HEADER_OFFSET+IPV4_HEADER_LENGTH;
    struct icmp_echo_hdr *icmp_hdr = (void *)pi->packet+IPV4_HEADER_OFFSET+IPV4_HEADER_LENGTH;
    /*unsigned i;
     for (i = 0; i < pi->len-IPV4_HEADER_OFFSET-IPV4_HEADER_LENGTH; i++)
     printf("(%d %02X) ", i, (int)*(icmp_packet+i));
     printf("\n");*/
    
    if (calc_checksum(icmp_packet, pi->len-IPV4_HEADER_OFFSET-IPV4_HEADER_LENGTH)) {
        printf("ICMP checksum failed, dropping packet!\n");
        return 1;
    }
    
    uint8_t type = ICMPH_TYPE(icmp_hdr);
    
    switch (type) {
        case ICMP_TYPE_ECHO_REQUEST: ICMPH_TYPE_SET(icmp_hdr, 0);
            break;
        case ICMP_TYPE_ECHO_REPLY: handle_ping_reply(pi); return 1;
        default: debug_println("Dropping packet: type %d unknown.", type); return 1;
            
    }
    ICMPH_CHKSUM_SET(icmp_hdr, 0);
    ICMPH_CHKSUM_SET(icmp_hdr, htons(calc_checksum(icmp_packet, pi->len-IPV4_HEADER_OFFSET-IPV4_HEADER_LENGTH)));
    /*for (i = 0; i < pi->len-IPV4_HEADER_OFFSET-IPV4_HEADER_LENGTH; i++)
     printf("(%d %02X) ", i, (int)*(icmp_packet+i));
     printf("\n");*/
    return 0;
}

bool generate_response_ICMP_packet(packet_info_t *pi, int type, int code) {
    byte *old_packet = malloc(pi->len-14);
    memcpy(old_packet, pi->packet+14, pi->len-14);
    
    struct ip_hdr *old_iphdr = (void *)old_packet;
    
    pi->len = 14+20+36;//14 for Ethernet header, 20 for IPv4 header and 36 for ICMP time exceeded packet.
    pi->packet = malloc((pi->len)*sizeof(byte));
    
    struct ip_hdr *iphdr = (void *)pi->packet+IPV4_HEADER_OFFSET;
    
    IPH_VHLTOS_SET(iphdr, 4, 5, 0); //Set version and IHL.
    IPH_LEN_SET(iphdr, htons(20+36));
    IPH_TTL_SET(iphdr, 32);
    IPH_PROTO_SET(iphdr, 1);
    
    addr_ip_t dest = IPH_SRC(old_iphdr);
    addr_ip_t target = sr_integ_findnextip(dest);
    interface_t *source_intf = sr_integ_findsrcintf(target);
    
    if (source_intf == NULL) {
        char ip_str[STRLEN_IP], target_str[STRLEN_IP];
        ip_to_string(ip_str, dest);
        ip_to_string(target_str, target);
        printf("No route to source %s with target %s, dropping packet!\n", ip_str, target_str);
        return 1;
    }
    addr_ip_t source = source_intf->ip;
    
    char dest_str[15];
    ip_to_string(dest_str, dest);
    char source_str[15];
    ip_to_string(source_str, source);
    
    printf("dest=%s, source=%s\n", dest_str, source_str);
    
    memcpy(&IPH_SRC(iphdr), &source, 6);
    memcpy(&IPH_DEST(iphdr), &dest, 6);
    byte *icmp_packet = pi->packet+IPV4_HEADER_OFFSET+IPV4_HEADER_LENGTH;
    struct icmp_dur_hdr *icmp_hdr = (void *)pi->packet+IPV4_HEADER_OFFSET+IPV4_HEADER_LENGTH;
    ICMPH_TYPE_SET(icmp_hdr, type);
    ICMPH_CODE_SET(icmp_hdr, code);
    memcpy(icmp_packet+ICMP_TIME_EX_IP_HEADER_OFFSET, old_packet, IPV4_HEADER_LENGTH + 8);
    ICMPH_CHKSUM_SET(icmp_hdr, 0);
    ICMPH_CHKSUM_SET(icmp_hdr, htons(calc_checksum(icmp_packet, pi->len-IPV4_HEADER_OFFSET-IPV4_HEADER_LENGTH)));
    
    return 0;
}

void send_ping(router_t *router, addr_ip_t dest_ip, addr_ip_t src_ip, uint16_t id, uint16_t count) {
    int len = IPV4_HEADER_LENGTH+8;
    byte *payload = malloc(len*sizeof(byte));
    struct ip_hdr *iphdr = (void *)payload;
    IPH_VHLTOS_SET(iphdr, 4, 5, 0);
    IPH_LEN_SET(iphdr, htons(len));
    IPH_ID_SET(iphdr, 0);
    IPH_TTL_SET(iphdr, 64);
    IPH_PROTO_SET(iphdr, 1);
    iphdr->src.addr = src_ip;
    iphdr->dest.addr = dest_ip;
    IPH_CHKSUM_SET(iphdr, 0);
    uint16_t checksum = calc_checksum(payload, IPV4_HEADER_LENGTH);
    IPH_CHKSUM_SET(iphdr, htons(checksum));
    struct icmp_echo_hdr *pihdr = (void *)payload+IPV4_HEADER_LENGTH;
    ICMPH_TYPE_SET(pihdr, ICMP_TYPE_ECHO_REQUEST);
    pihdr->id = id;
    pihdr->seqno = count;
    ICMPH_CHKSUM_SET(pihdr, htons(calc_checksum(payload+IPV4_HEADER_LENGTH, 8)));
    send_packet(payload, src_ip, dest_ip, len, FALSE, FALSE);
}

void handle_ping_reply(packet_info_t *pi) {
    struct ip_hdr *iphdr = (void *)pi->packet+IPV4_HEADER_OFFSET;
    struct icmp_echo_hdr *pihdr = (void *)pi->packet+IPV4_HEADER_OFFSET+IPV4_HEADER_LENGTH;
    cli_ping_handle_reply(IPH_SRC(iphdr), pihdr->seqno);
}
