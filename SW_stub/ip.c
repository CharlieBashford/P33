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
#include "sr_lwtcp_glue.h"
#include "lwtcp/lwip/ip.h"
#include "sr_router.h"
#include "icmp.h"
#include "sr_integration.h"
#include "routing.h"
#include "policy.h"
#include "sha256.h"

void handle_IPv4_packet(packet_info_t *pi) {
    debug_println("Packet is IPv4");
    /*unsigned i;
     for (i = 0; i < pi->len; i += 2)
     printf("%02X%02X ", *(pi->packet+i),*(pi->packet+i+1));
     printf("\n");*/
    
    struct ip_hdr *iphdr = (void *)pi->packet+IPV4_HEADER_OFFSET;
    
    uint8_t IHL = IPH_HL(iphdr);
    if (IHL > 5) {
        debug_println("Options in IPv4 packet, dropping packet!");
        return;
    } else if (IHL < 5) {
        debug_println("Incomplete packet, dropping packet!");
        return;
    }
    
    /*if (ntohs(IPH_LEN(iphdr)) != pi->len-IPV4_HEADER_OFFSET) {
     unsigned i;
     for (i = 0; i < pi->len; i += 2)
     printf("%02X%02X ", *(pi->packet+i),*(pi->packet+i+1));
     printf("\n");
     debug_println("Incomplete packet, missing %d bytes, dropping packed!\n", (ntohs(IPH_LEN(iphdr))-(pi->len-IPV4_HEADER_OFFSET)));
     return;
     }*/
    
    if (calc_checksum(pi->packet+IPV4_HEADER_OFFSET, 20)) {
        debug_println("Checksum failed, dropping packet!");
        return;
    }
    
    char ip_str[16];
    ip_to_string(ip_str, IPH_DEST(iphdr));
    if (router_lookup_interface_via_ip(get_router(), IPH_DEST(iphdr)) || IPH_DEST(iphdr) == OSPF_IP) {
        debug_println("Packet for router!");
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
            case IP_ENCAP_PROTOCOL:
            case ESP_PROTOCOL:
                handle_IP_ENCAP_packet(pi);
                return;
                break;
            default:
                debug_println("Generating protocol unreachable packet!");
                if (generate_response_ICMP_packet(pi, 3, 2)) return;
                iphdr = (void *)pi->packet+IPV4_HEADER_OFFSET;
                break;
                
        }
        
    }
    if (IPH_TTL(iphdr) > 1) {
        IPH_TTL_DEC(iphdr);
    } else {
        debug_println("Generating time exceeded packet!");
        if (generate_response_ICMP_packet(pi, 11, 0)) return;
        iphdr = (void *)pi->packet+IPV4_HEADER_OFFSET;
    }
    IPH_CHKSUM_SET(iphdr, 0);
    IPH_CHKSUM_SET(iphdr, htons(calc_checksum(pi->packet+IPV4_HEADER_OFFSET, 20)));
    
    /* POLICY_MATCHING */
    
    policy_t *policy = router_find_matching_policy_sending(get_router(), IPH_SRC(iphdr), IPH_DEST(iphdr));
    if (policy != NULL) {
        debug_println("Found matching policy! (sending)");
        unsigned protocol;
        if ((policy->secret == NULL || strlen(policy->secret) == 0) && policy->encrypt_rot == 0) {
            debug_println("There is no secret nor ecryption, just doing IP tunneling!");
            protocol = IP_ENCAP_PROTOCOL;
        } else {
            if (policy->secret != NULL && strlen(policy->secret) != 0) {
                if (policy->encrypt_rot != 0)
                    debug_println("There is a secret and encryption, going to do ESP!");
                else
                    debug_println("There is a secret, going to do ESP!");
            } else {
                 debug_println("There is encryption, going to do ESP!");
            }
            protocol = ESP_PROTOCOL;
        }
        uint8_t *temp = add_IPv4_header(pi->packet, IPV4_HEADER_OFFSET, protocol, policy->local_end, policy->remote_end, pi->len);
        free(pi->packet);
        
        pi->packet = temp;
        pi->len += IPV4_HEADER_LENGTH;
        iphdr = (void *)pi->packet+IPV4_HEADER_OFFSET;
        
        if ((policy->secret != NULL && strlen(policy->secret) != 0) || policy->encrypt_rot != 0) {
            uint8_t *temp = add_ESP_packet(pi->packet, IPV4_HEADER_OFFSET+IPV4_HEADER_LENGTH, 0, 0, 0, IP_ENCAP_PROTOCOL, policy->secret, policy->encrypt_rot, pi->len);
            free(pi->packet);
            
            pi->packet = temp;
            pi->len += ESP_HEADER_LENGTH + ESP_TAIL_LENGTH; //incl padding
            iphdr = (void *)pi->packet+IPV4_HEADER_OFFSET;
        }
        
        IPH_LEN_SET(iphdr, htons(pi->len-IPV4_HEADER_OFFSET));
        IPH_CHKSUM_SET(iphdr, 0);
        IPH_CHKSUM_SET(iphdr, htons(calc_checksum(pi->packet+IPV4_HEADER_OFFSET, 20)));
        
        free_policy(policy);
    }
    
    /* END_POLICY_MATCHING */
    
    addr_ip_t target_ip = sr_integ_findnextip(IPH_DEST(iphdr));
    char target_ip_str[16];
    ip_to_string(target_ip_str, target_ip);
    debug_println("Sending packet to %s via %s",  ip_str, target_ip_str);
    send_packet(pi->packet+14, IPH_SRC(iphdr), target_ip, pi->len-14, FALSE, FALSE);
}

void handle_TCP_packet(packet_info_t *pi) {
    debug_println("Recieved a TCP packet:");//Look for port
    sr_transport_input(pi->packet+IPV4_HEADER_OFFSET);
    debug_println("Called sr_transport_input");
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

uint8_t *add_IPv4_header(uint8_t *payload, unsigned offset, uint8_t  proto, uint32_t src, uint32_t dest, int len) {
    debug_println("Adding IPv4 header.");
    /*unsigned i;
     for (i = 0; i < len; i++)
     printf("(%d %02X) ", i, (int)*(payload+i));
     printf("\n");*/
    
    uint8_t *ipv4_packet = malloc_or_die((IPV4_HEADER_LENGTH+len)*sizeof(uint8_t)); //Needs to be free'd outside call.
    struct ip_hdr *iphdr = (void *)ipv4_packet + offset;
    
    IPH_VHLTOS_SET(iphdr, 4, 5, 16);
    IPH_LEN_SET(iphdr, htons(len+IPV4_HEADER_LENGTH-offset));
    IPH_ID_SET(iphdr, 0);
    IPH_OFFSET_SET(iphdr, 0);
    IPH_TTL_SET(iphdr, 32);
    IPH_PROTO_SET(iphdr, proto);
    iphdr->src.addr = src;
    iphdr->dest.addr = dest;
    
    IPH_CHKSUM_SET(iphdr, 0);
    IPH_CHKSUM_SET(iphdr, htons(calc_checksum(ipv4_packet, IPV4_HEADER_LENGTH)));
    
    memcpy(ipv4_packet, payload, offset);
    memcpy(ipv4_packet+offset+IPV4_HEADER_LENGTH, payload+offset, len-offset);

    return ipv4_packet;
}



void handle_no_route_to_host(packet_info_t *pi) {
    debug_println("No route to host!");
    
    if (generate_response_ICMP_packet(pi, 3, 0)) return;
    struct ip_hdr *iphdr = (void *)pi->packet+IPV4_HEADER_OFFSET;
    
    IPH_CHKSUM_SET(iphdr, 0);
    IPH_CHKSUM_SET(iphdr, htons(calc_checksum(pi->packet+IPV4_HEADER_OFFSET, 20)));
    
    addr_ip_t target_ip = sr_integ_findnextip(IPH_DEST(iphdr));
    char target_ip_str[16];
    ip_to_string(target_ip_str, target_ip);
    debug_println("target_ip=%s", target_ip_str);
    
    send_packet(pi->packet+14, IPH_SRC(iphdr), target_ip, pi->len-14, FALSE, FALSE);
}
