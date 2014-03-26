//
//  arp.c
//  P33
//
//  Created by Charlie Bashford on 12/03/2014.
//  Copyright (c) 2014 Charlie Bashford. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "arp.h"
#include "lwtcp/lwip/ip.h"
#include "icmp.h"
#include "ip.h"

void handle_ARP_packet(packet_info_t *pi) {
    /*unsigned i;
     for (i = 0; i < pi->len; i++)
     printf("(%d %02X) ", i, (int)*(pi->packet+i));
     printf("\n");*/
    
    byte *ARP_packet = pi->packet+14;
    struct arp_hdr *arhdr = (void *)ARP_packet;
    
    addr_ip_t target_ip = ARH_TARGET_IP(arhdr);
    char target_ip_str[16];
    ip_to_string(target_ip_str, target_ip);
    uint16_t op = ARH_OP(arhdr);
    
    router_t *router = get_router();
    
    interface_t *target_intf = router_lookup_interface_via_ip(router, target_ip);
    addr_mac_t sender_mac = ARH_SENDER_MAC(arhdr);
    addr_ip_t sender_ip = ARH_SENDER_IP(arhdr);
    
    if (target_intf && op == 1) {
        char sender_ip_str[12];
        ip_to_string(sender_ip_str, sender_ip);
        debug_println("Packet is an ARP request from %s for %s.", sender_ip_str, target_ip_str);
        
        if (router_find_arp_entry(router, sender_ip)) {
            router_delete_arp_entry(router, sender_ip);
        }
        router_add_arp_entry(router, sender_mac, sender_ip, TRUE); //Save mac address.
        ARH_OP_SET(arhdr, 2);
        
        swap_bytes(&ARH_SENDER_MAC(arhdr),&ARH_TARGET_MAC(arhdr), ARH_HARD_LEN(arhdr)+ARH_PROTO_LEN(arhdr)); //Swap ARP source and dest mac and ip
        ARH_SENDER_MAC_SET(arhdr, target_intf->mac);
        
        send_packet(pi->packet+14, target_intf->ip, sender_ip, pi->len-14, TRUE, FALSE);
    } else if (target_intf && op == 2) {
        char sender_ip_str[12];
        ip_to_string(sender_ip_str, sender_ip);
        debug_println("Packet is an ARP reply from %s for %s.\n", sender_ip_str, target_ip_str);
        
        if (router_find_arp_entry(router, sender_ip)) {
            router_delete_arp_entry(router, sender_ip);
        }
        router_add_arp_entry(router, sender_mac, sender_ip, TRUE); //Save mac address.
        
        debug_println("about to get lock!");
        pthread_mutex_lock(&router->pending_arp_lock);
        
        debug_println("num_pending_arp=%d", router->num_pending_arp);
        unsigned i;
        for (i = 0; i < router->num_pending_arp; i++) {
            debug_println("i=%d", i);
            pending_arp_entry_t *pending_arp_entry = &router->pending_arp[i];
            if (pending_arp_entry->ip == sender_ip) {
                debug_println("Resending packet in entry %d", i);
                send_packet(pending_arp_entry->payload, pending_arp_entry->src, pending_arp_entry->ip, pending_arp_entry->len, FALSE, FALSE);
                unsigned j;
                for (j = i; j < router->num_pending_arp-1; j++) {
                    router->pending_arp[j] = router->pending_arp[j+1];
                }
                router->num_pending_arp--;
                if (i != router->num_pending_arp)
                    i--; //Don't increase i on next go.
            }
        }
        
        
        pthread_mutex_unlock(&router->pending_arp_lock);
        
        
    }
}

void handle_not_repsponding_to_arp(byte *payload, unsigned len) {
    debug_println("Not responding to arp:\n");
    
    
    packet_info_t *pi = malloc_or_die(sizeof(packet_info_t));                   //Free'd (below).
    pi->packet = malloc_or_die((IPV4_HEADER_OFFSET+len)*sizeof(uint8_t));       //Free'd (below).
    pi->len = len;
    
    memcpy(pi->packet+IPV4_HEADER_OFFSET, payload, len);
    
    struct eth_hdr *ethhdr = (void *)pi->packet;
    ETH_DEST_SET(ethhdr, make_mac_addr(0, 0, 0, 0, 0, 0));
    ETH_SRC_SET(ethhdr, make_mac_addr(0, 0, 0, 0, 0, 0));
    ETH_TYPE_SET(ethhdr, 0);
    
    //Reverse soruce and destination again.
    struct ip_hdr *iphdr;/* = (void *)pi->packet+IPV4_HEADER_OFFSET;
    swap_bytes(&IPH_SRC(iphdr), &IPH_DEST(iphdr), 4);*/
    
    unsigned i;
    for (i = 0; i < pi->len; i += 2)
        printf("%02X%02X ", *(pi->packet+i),*(pi->packet+i+1));
    printf("\n");
    
    if (generate_response_ICMP_packet(pi, 3, 1)) return;
    iphdr = (void *)pi->packet+IPV4_HEADER_OFFSET; //pi->packet have moved in memory, so re-define.
    
    IPH_CHKSUM_SET(iphdr, 0);
    IPH_CHKSUM_SET(iphdr, htons(calc_checksum(pi->packet+IPV4_HEADER_OFFSET, IPV4_HEADER_LENGTH)));
    
    for (i = 0; i < pi->len; i += 2)
        printf("%02X%02X ", *(pi->packet+i),*(pi->packet+i+1));
    printf("\n");
    
    addr_ip_t target_ip = sr_integ_findnextip(IPH_DEST(iphdr));
    char target_ip_str[STRLEN_IP];
    ip_to_string(target_ip_str, target_ip);
    debug_println("target_ip=%s", target_ip_str);
    
    //send_packet(pi->packet+IPV4_HEADER_OFFSET, IPH_SRC(iphdr), target_ip, pi->len-IPV4_HEADER_OFFSET, FALSE, FALSE);

    free(pi->packet);
    free(pi);
}

void generate_pending_ARP_thread() {
    router_t *router = get_router();
    pending_arp_entry_t expiring_arp_entry[router->num_pending_arp];
    unsigned i;
    while (TRUE) {
        
        unsigned num_expiring = 0;
        
        pthread_mutex_lock(&router->pending_arp_lock);
        for (i = 0; i < router->num_pending_arp; i++) {
            pending_arp_entry_t *pending_arp_entry = &router->pending_arp[i];
            if (pending_arp_entry->num_sent >= 5) {
                debug_println("Not responding to ARP request!");
                expiring_arp_entry[num_expiring].payload = pending_arp_entry->payload;
                expiring_arp_entry[num_expiring].len = pending_arp_entry->len;
                num_expiring++;
                unsigned j;
                for (j = i; j < router->num_pending_arp-1; j++) {
                    router->pending_arp[j] = router->pending_arp[j+1];
                }
                router->num_pending_arp--;
                if (i != router->num_pending_arp)
                    i--; //Don't increase i on next go.
                continue;
            }
            send_ARP_request(pending_arp_entry->ip, ++pending_arp_entry->num_sent); //Shouldn't need lock.
        }
        debug_println("num_pending_arp=%d", router->num_pending_arp);
        pthread_mutex_unlock(&router->pending_arp_lock);
        
        for (i = 0; i < num_expiring; i++) {
            struct ip_hdr *iphdr = (void *)expiring_arp_entry[i].payload;
            if (router_lookup_interface_via_ip(router, IPH_SRC(iphdr)) == NULL) { //Don't send a response to itself.
                handle_not_repsponding_to_arp(expiring_arp_entry[i].payload, expiring_arp_entry[i].len);
            } else {
                debug_println("NOT sending response, because it originated from own interface.");
            }
            free(expiring_arp_entry[i].payload);
            expiring_arp_entry[i].payload = NULL;
        }
        
        sleep(1);
        debug_println("Pending ARP thread sleeping for 1s.");
    }
}

void send_ARP_request(addr_ip_t ip, int num) {
    char ip_str[16];
    ip_to_string(ip_str, ip);
    debug_println("Sending an ARP request (number %d) to %s:", num, ip_str);
    
    byte *packet = malloc_or_die(ARP_PACKET_LENGTH*sizeof(byte));     //Free'd (below).
    struct arp_hdr *arhdr = (void *)packet;
    ARH_HARD_TYPE_SET(arhdr, 1);
    ARH_PROTO_TYPE_SET(arhdr, IPV4_ETHERTYPE);
    ARH_HARD_LEN_SET(arhdr, 6);
    ARH_PROTO_LEN_SET(arhdr, 4);
    ARH_OP_SET(arhdr, 1);
    
    interface_t *interface = sr_integ_findsrcintf(ip);
    if (interface == NULL) {
        debug_println("ERROR: can't send ARP request, ip %s is not next hop!", ip_str);
        return;
    }
    
    ARH_SENDER_MAC_SET(arhdr, interface->mac);
    ARH_SENDER_IP_SET(arhdr, interface->ip);
    ARH_TARGET_IP_SET(arhdr, ip);
    ARH_TARGET_MAC_SET(arhdr, make_mac_addr(0, 0, 0, 0, 0, 0));
    
    send_packet(packet, interface->ip, ip, 28, TRUE, FALSE);
    free(packet);
}

void router_add_arp_entry( router_t *router, addr_mac_t mac, addr_ip_t ip, bool dynamic) {
    ip_mac_t *arp_entry;
    
    pthread_mutex_lock(&router->arp_cache_lock);
    
    debug_println("Adding arp entry.");    // TODO remove debugging line
    
    arp_entry = &router->arp_cache[router->num_arp_cache];
    
    arp_entry->mac = mac;
    arp_entry->ip = ip;
    arp_entry->time = get_time();
    arp_entry->dynamic = dynamic;
    
    router->num_arp_cache += 1;
    
#ifdef _CPUMODE_
    
    writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_IP, ntohl(ip));
    writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_MAC_LOW, mac_lo(&mac));
    writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_MAC_HIGH, mac_hi(&mac));
    writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_WR_ADDR, router->num_arp_cache-1);
#endif
    
    pthread_mutex_unlock(&router->arp_cache_lock);
    
}

bool router_delete_arp_entry( router_t *router, addr_ip_t ip) {
    
    pthread_mutex_lock(&router->arp_cache_lock);
    
    debug_println("Deleting arp entry.");    // TODO remove debugging line
    unsigned i;
    for (i = 0; i < router->num_arp_cache; i++) {
        if (router->arp_cache[i].ip == ip) {
            break;
        }
    }
    unsigned j;
    for (j = i; j < router->num_arp_cache-1; j++) {
        router->arp_cache[j] = router->arp_cache[j+1];
        
#ifdef _CPUMODE_
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_IP, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_MAC_LOW, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_MAC_HIGH, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_WR_ADDR, j+1);
        
        addr_mac_t *mac = &router->arp_cache[j].mac;
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_IP, ntohl(router->arp_cache[j].ip));
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_MAC_LOW, mac_lo(mac));
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_MAC_HIGH, mac_hi(mac));
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_WR_ADDR, j);
#endif
    }
    
#ifdef _CPUMODE_
    
    if (i == router->num_arp_cache -1) { //If not moving entries, just deleting last one.
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_IP, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_MAC_LOW, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_MAC_HIGH, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_WR_ADDR, i);
    }
    
#endif
    
    bool succeded = FALSE;
    if (i < router->num_arp_cache) {
        succeded = TRUE;
    }
    router->num_arp_cache -= 1;
    pthread_mutex_unlock(&router->arp_cache_lock);
    
    return succeded;
}

void router_delete_all_arp_entries(router_t *router, bool dynamic) {
    
    pthread_mutex_lock(&router->arp_cache_lock);
    
    debug_println("Deleting all %s arp entries.", (dynamic == TRUE) ? "dyanmic" : "static");    // TODO remove debugging line
    unsigned replace[router->num_arp_cache];
    unsigned num_replace = 0;
    unsigned replaced = 0;
    unsigned move[router->num_arp_cache];
    unsigned num_move = 0;
    unsigned moved = 0;
    unsigned i;
    for (i = 0; i < router->num_arp_cache; i++) {
        if (router->arp_cache[i].dynamic == dynamic) {
            replace[num_replace++] = i;
        } else if (num_replace > replaced) {
            router->arp_cache[replace[replaced]] = router->arp_cache[i];
            move[num_move++] = i;
            if (num_move > moved && move[moved] < replace[replaced]) {
                router->arp_cache[move[moved++]] = router->arp_cache[replace[replaced]];
            } else {
                replaced++;
            }
        } else if (num_move > moved) {
            router->arp_cache[move[moved++]] = router->arp_cache[i];
            move[num_move++] = i;
        }
    }
    router->num_arp_cache -= num_replace;
    
#ifdef _CPUMODE_
    
    for (i = 0; i < num_replace; i++) {
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_IP, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_MAC_LOW, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_MAC_HIGH, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_WR_ADDR, router->num_arp_cache+i);
    }
    
    for (i = router->num_arp_cache-1; i >= 0; i++) { //Backwards
        addr_mac_t *mac = &router->arp_cache[i].mac;
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_IP, ntohl(router->arp_cache[i].ip));
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_MAC_LOW, mac_lo(mac));
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_MAC_HIGH, mac_hi(mac));
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_WR_ADDR, i);
    }
    
#endif
    
    pthread_mutex_unlock(&router->arp_cache_lock);
}

ip_mac_t *router_find_arp_entry( router_t *router, addr_ip_t ip) {
    char ip_str[STRLEN_IP];
    ip_to_string(ip_str, ip);
    debug_println("Finding arp entry for %s.", ip_str);
    
    pthread_mutex_lock(&router->arp_cache_lock);
    
    unsigned i;
    for (i = 0; i < router->num_arp_cache; i++) {
        if (router->arp_cache[i].ip == ip) {
            pthread_mutex_unlock(&router->arp_cache_lock);
            return &router->arp_cache[i];
        }
    }
    
    pthread_mutex_unlock(&router->arp_cache_lock);
    
    return NULL;
}
