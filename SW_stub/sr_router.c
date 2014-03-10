/* Filename: sr_router.c */

#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include "common/nf10util.h"
#include "sr_cpu_extension_nf2.h"
#include "sr_router.h"
#include "sr_integration.h"
#include "sr_common.h"
#include "sr_lwtcp_glue.h"
#include "lwtcp/lwip/ip.h"
#include "lwtcp/lwip/icmp.h"
#include "cli/cli_ping.h"

void sys_thread_new(void (* thread)(void *arg), void *arg);

#define ICMP_PROTOCOL 1
#define TCP_PROTOCOL 6
#define PWOSPF_PROTOCOL 89

#define PWOSPF_HEADER_LENGTH 24
#define LSU_HEADER_LENGTH 8
#define LSU_AD_LENGTH 12
#define HELLO_HEADER_LENGTH 8

#define TYPE_HELLO 1
#define TYPE_LSU 4

#define IPV4_HEADER_LENGTH 20
#define IPV4_HEADER_OFFSET 14

#define ICMP_TIME_EX_IP_HEADER_OFFSET 8

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_ECHO_REQUEST 8

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

struct eth_hdr {
    addr_mac_t _dest;
    addr_mac_t _src;
    PACK_STRUCT_FIELD(uint16_t _eth_type);
} PACK_STRUCT_STRUCT;

#define ETH_DEST(hdr) ((hdr)->_dest)
#define ETH_SRC(hdr) ((hdr)->_src)
#define ETH_TYPE(hdr) ((hdr)->_eth_type)

#define ETH_DEST_SET(hdr, dest) (hdr)->_dest = (dest)
#define ETH_SRC_SET(hdr, src) (hdr)->_src = (src)
#define ETH_TYPE_SET(hdr, eth_type) (hdr)->_eth_type = (eth_type)

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

struct hello_hdr {
    PACK_STRUCT_FIELD(uint32_t _sub_mask);
    PACK_STRUCT_FIELD(uint16_t _hello_int);
} PACK_STRUCT_STRUCT;

#define HEHDR_SUB_MASK(hdr) ((hdr)->_sub_mask)
#define HEHDR_HELLO_INT(hdr) ((hdr)->_hello_int)

#define HEHDR_SUB_MASK_SET(hdr, sub_mask) (hdr)->_sub_mask = (sub_mask)
#define HEHDR_HELLO_INT_SET(hdr, hello_int) (hdr)->_hello_int = (hello_int)

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



void router_init( router_t* router ) {
#ifdef _CPUMODE_
    //init_registers(router);
    router->nf.device_name = "nf10";
    check_iface( &router->nf );
    if( openDescriptor( &router->nf ) != 0 )
        die( "Error: failed to connect to the hardware" );
    else {
        /* wait for the reset to complete */
        struct timespec pause;
        pause.tv_sec = 0;
        pause.tv_nsec = 5000 * 1000; /* 5ms */
        nanosleep( &pause, NULL );
    }
#endif
    
    router->num_interfaces = 0;
    router->num_routes = 0;
    router->num_arp_cache = 0;
    router->num_pending_arp = 0;
    router->lsuint = 30;
    router->added_links = FALSE;

    router->use_ospf = TRUE;
    
    pthread_mutex_init( &router->intf_lock, NULL );
    pthread_mutex_init( &router->route_table_lock, NULL );
    pthread_mutex_init( &router->arp_cache_lock, NULL );
    pthread_mutex_init( &router->pending_arp_lock, NULL);

#ifndef _THREAD_PER_PACKET_
    debug_println( "Initializing the router work queue with %u worker threads",
                   NUM_WORKER_THREADS );
    wq_init( &router->work_queue, NUM_WORKER_THREADS, &router_handle_work );
#else
    debug_println( "Router initialized (will use one thread per packet)" );
#endif
}

void router_destroy( router_t* router ) {
    pthread_mutex_destroy( &router->intf_lock );
    pthread_mutex_destroy( &router->route_table_lock );
    pthread_mutex_destroy( &router->arp_cache_lock );


#ifdef _CPUMODE_
    closeDescriptor( &router->nf );
#endif

#ifndef _THREAD_PER_PACKET_
    wq_destroy( &router->work_queue );
#endif
}

void swap_bytes(void *byte_p1, void *byte_p2, unsigned len) {
    byte temp[len];
    memcpy(&temp, byte_p1, len);
    memcpy(byte_p1, byte_p2, len);
    memcpy(byte_p2, &temp, len);
}

struct output_packet {
    uint8_t* payload;
    uint32_t src;
    uint32_t dest;
    int len;
};

bool send_packet_intf(interface_t *intf, byte *payload, uint32_t src, uint32_t dest, int len, bool is_arp_packet, bool is_hello_packet) {
    addr_mac_t src_mac = intf->mac;

    byte *packet = malloc((14+len)*sizeof(byte));
    addr_mac_t dest_mac;
    
    if (!is_arp_packet && !is_hello_packet) {
        ip_mac_t *entry = router_find_arp_entry(get_router(), dest);
        if (router_lookup_interface_via_ip(get_router(), dest)) {
            char dest_str[STRLEN_IP];
            ip_to_string(dest_str, dest);
            debug_println("ERROR: Trying to send ARP request for own interface %s!", dest_str);
            exit(-1);
        }
        if (entry == NULL || (get_time() - entry->time) > 15000) {
            if (entry != NULL) {
                router_delete_arp_entry(get_router(), dest);
            }
            printf("Couldn't find ip address in arp cache or is too old.\n");
            
            pthread_mutex_lock(&get_router()->pending_arp_lock);
            
            send_ARP_request(dest, 1);

            pending_arp_entry_t *pending_arp_entry = &get_router()->pending_arp[get_router()->num_pending_arp];
            pending_arp_entry->ip = dest;
            pending_arp_entry->src = src;
            pending_arp_entry->payload = payload;
            pending_arp_entry->len = len;
            pending_arp_entry->num_sent = 1;
            
            get_router()->num_pending_arp += 1;
            
            pthread_mutex_unlock(&get_router()->pending_arp_lock);
            return 0;
        }
        dest_mac = entry->mac;
    } else {
        dest_mac = make_mac_addr(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
    }
    struct eth_hdr *ethdr = (void *)packet;
    ETH_DEST_SET(ethdr, dest_mac);
    ETH_SRC_SET(ethdr, src_mac);
    
    if (is_arp_packet) {
        ETH_TYPE_SET(ethdr, htons(ARP_ETHERTYPE));
    } else {
        ETH_TYPE_SET(ethdr, htons(IPV4_ETHERTYPE));
    }
    bcopy(payload, packet+14, len);
    
    /*for (i = 0; i < len+14; i++)
     printf("(%d %02X) ", i, (int)*(packet+i));
     printf("\n");*/
    
    char src_mac_str[18], dest_mac_str[18];
    mac_to_string(src_mac_str, &src_mac);
    mac_to_string(dest_mac_str, &dest_mac);
    
    printf("Adding ethernet header: source=%s and dest=%s\n", src_mac_str, dest_mac_str);
    
    sr_integ_low_level_output(get_sr(), packet, len+14, intf);
    
    return 0;
}

bool send_packet(byte *payload, uint32_t src, uint32_t dest, int len, bool is_arp_packet, bool is_hello_packet) {
    interface_t *target_intf = sr_integ_findsrcintf(dest);
    if (dest != OSPF_IP && target_intf == NULL) {
        packet_info_t *pi = malloc(sizeof(packet_info_t)); //TODO: Free!
        pi->packet = malloc(len+14);
        memcpy(pi->packet+14, payload, len);
        pi->len = len;
        handle_no_route_to_host(pi);
        return 1;
    }
    return send_packet_intf(target_intf, payload, src, dest, len, is_arp_packet, is_hello_packet);
}

void send_ARP_request(addr_ip_t ip, int num) {
    char ip_str[16];
    ip_to_string(ip_str, ip);
    printf("Sending an ARP request (number %d) to %s:\n", num, ip_str);
    
    byte *packet = malloc(28*sizeof(byte));     //TODO: Free!
    struct arp_hdr *arhdr = (void *)packet;
    ARH_HARD_TYPE_SET(arhdr, 1);
    ARH_PROTO_TYPE_SET(arhdr, 0x0800);
    ARH_HARD_LEN_SET(arhdr, 6);
    ARH_PROTO_LEN_SET(arhdr, 4);
    ARH_OP_SET(arhdr, 1);
    
    interface_t *interface = sr_integ_findsrcintf(ip);
    if (interface == NULL) {
        printf("ERROR: can't send ARP request, ip %s is not next hop!\n", ip_str);
        return;
    }
    
    ARH_SENDER_MAC_SET(arhdr, interface->mac);
    ARH_SENDER_IP_SET(arhdr, interface->ip);
    ARH_TARGET_IP_SET(arhdr, ip);
    
    send_packet(packet, interface->ip, ip, 28, TRUE, FALSE);
}

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
        printf("Packet is an ARP request from %s for %s.\n", sender_ip_str, target_ip_str);

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
        printf("Packet is an ARP reply from %s for %s.\n", sender_ip_str, target_ip_str);
        
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

uint16_t calc_checksum(byte *header, int len) {
    uint32_t total = 0;
    uint16_t *data = (uint16_t *) header;
    unsigned i;
    for (i = 0; i < len/2; i++) {
        //printf("ntohs(header+%d)=%08X\n", i, ntohs(data[i]));
        total += ntohs(data[i]);
      //  printf("total=%08X\n", total);


    }
    //printf("total=%08X\n", total);

    uint16_t checksum = (total >> 16) + (total & 0xffff);

    return ~checksum;
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
        printf("No route to source, dropping packet!\n"); //TODO: ??
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

void handle_TCP_packet(packet_info_t *pi) {
    printf("Recieved a TCP packet:\n");
    sr_transport_input(pi->packet+IPV4_HEADER_OFFSET);
    printf("Called sr_transport_input\n");
}

void handle_not_repsponding_to_arp(byte *payload, unsigned len) {
    printf("Not responding to arp:\n");
    
    packet_info_t *pi = malloc(sizeof(packet_info_t));
    pi->packet = payload;
    pi->len = len;
    
    //Reverse soruce and destination again.
    /*struct ip_hdr *iphdr = (void *)pi->packet+IPV4_HEADER_OFFSET;
    swap_bytes(&IPH_SRC(iphdr), &IPH_DEST(iphdr), 4);*/
    
    unsigned i;
    for (i = 0; i < pi->len; i += 2)
        printf("%02X%02X ", *(pi->packet+i),*(pi->packet+i+1));
    printf("\n");
    
    if (generate_response_ICMP_packet(pi, 3, 1)) return;
    //pi->packet have moved in memory, so re-define.
    struct ip_hdr *iphdr = (void *)pi->packet+IPV4_HEADER_OFFSET;
    
    IPH_CHKSUM_SET(iphdr, 0);
    IPH_CHKSUM_SET(iphdr, htons(calc_checksum(pi->packet+IPV4_HEADER_OFFSET, 20)));
    
    for (i = 0; i < pi->len; i += 2)
        printf("%02X%02X ", *(pi->packet+i),*(pi->packet+i+1));
    printf("\n");
    
    addr_ip_t target_ip = sr_integ_findnextip(IPH_DEST(iphdr));
    char target_ip_str[16];
    ip_to_string(target_ip_str, target_ip);
    printf("target_ip=%s\n", target_ip_str);
    
    send_packet(pi->packet+14, IPH_SRC(iphdr), target_ip, pi->len-14, FALSE, FALSE);
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

int router_find_database_entry_position(router_t *router, uint32_t router_id) {
    //debug_println("called router_find_database_entry_position");    // TODO remove debugging line

    pthread_mutex_lock(&router->database_lock);
    
    unsigned i;
    for (i = 0; i < router->num_database; i++) {
        database_entry_t *database_entry = &router->database[i];
        if (database_entry->router_id == router_id) {
            pthread_mutex_unlock(&router->database_lock);
            return i;
        }
    }
    
    pthread_mutex_unlock(&router->database_lock);
    
    return -1;
}

void print_database() {
    router_t *router = get_router();
    database_entry_t *database_entry;
    debug_println("Router ID\tLinks");
    unsigned i,j;
    for (i = 0; i < router->num_database; i++) {
        database_entry = &router->database[i];
        char router_str[16];
        ip_to_string(router_str, database_entry->router_id);
        debug_println("%s \t%d", router_str, database_entry->num_links);
        debug_println("\tRouter ID\tSubnet");
        for (j = 0; j < database_entry->num_links; j++) {
            char id_str[16], subnet_str[16];
            link_t *link = &database_entry->link[j];
            ip_to_string(id_str, link->router_id);
            subnet_to_string(subnet_str, link->subnet_no, link->mask);
            debug_println("\t%s \t%s", id_str, subnet_str);
        }
    }
}

/*void check_links() {
    router_t *router = get_router();
    unsigned i, j;
    for (i = 0; i < router->num_database; i++) {
        database_entry_t *database_entry = &router->database[i];
        for (j = 0; j < database_entry->len; i++) {
            if (database_entry->link[j].router_id != 0) {
                database_entry_t *other_entry = router_find_database_entry(router, database_entry->link[j].router_id);
                if (other_entry == NULL) {
                    router_remove_link_from_database_entry(router, database_entry, database_entry->link[j].router_id);
                } else {
                    router_find_
                }
            }
        }
    }
}*/

#define INFINITY 999999
#define MIN(X,Y) ((X) < (Y)) ? (X) : (Y)

void update_routing_table() { // TODO:Mutli threading for interface and database?
    
    //check_links();
    
    router_t *router = get_router();
    debug_println("Running Dijkstra on:");
    print_database();
    unsigned link_count = 0;
    unsigned i,j;
    for (i = 0; i < router->num_database; i++) {
        link_count += router->database[i].num_links;
    }
    link_t *routes[link_count];
    unsigned routes_added = 0;
    unsigned k;
    for (i = 0; i < router->num_database; i++) {
        database_entry_t *database_entry = &router->database[i];
        for (j = 0; j < database_entry->num_links; j++) {
            link_t *link = &database_entry->link[j];
            bool found = FALSE;
            for (k = 0; k < routes_added; k++) {
                if (link->subnet_no == routes[k]->subnet_no) {
                    found = TRUE;
                    break;
                }
            }
            if (!found) {
                routes[routes_added] = link;
                routes_added++;
            }
        }
    }
    
    debug_println("... and look for routes to:");
    debug_println("Prefix\t\tGateway\t\tMask\t\tInterface");
    for (i = 0; i < routes_added; i++) {
        link_t *link = routes[i];
        char prefix[15], subnet[15];
        ip_to_string(prefix, link->subnet_no);
        ip_to_string(subnet, link->mask);
        debug_println("%s\t0.0.0.0 \t%s\t----", prefix, subnet);
    }
    
    bool visited[router->num_database];
    unsigned distance[router->num_database];
    uint32_t *first_router[router->num_database];
    for (i = 0; i < router->num_database; i++) {
        distance[i] = INFINITY;
        visited[i] = FALSE;
        first_router[i] = NULL;
    }
    distance[0] = 0; //Distance to current router is 0.
    int current_pos = 0; //Start at current router
    first_router[0] = &router->router_id;
    
    while (!visited[current_pos]) {
        database_entry_t *current_entry = &router->database[current_pos];
        debug_println("num_links=%d", current_entry->num_links);
        for (i = 0; i < current_entry->num_links; i++) {
            debug_println("i=%d", i);
            if (current_entry->link[i].router_id != 0) {
                int pos = router_find_database_entry_position(router, current_entry->link[i].router_id);
                debug_println("isn't 0, and pos=%d", pos);
                bool is_static = current_entry->router_id == router->router_id && current_entry->link[i].router_id == 0;
                if (pos != -1 && !visited[pos] && (((get_time() - current_entry->link[i].time_last) < 3*router->lsuint*1000) || is_static)) { //If not expired
                    debug_println("checking distance: distance[%d]=%d + 1 < %d", current_pos, distance[current_pos], distance[pos]);
                    if (distance[current_pos]+1 < distance[pos]) {
                        distance[pos] = distance[current_pos] + 1;
                        if (current_entry->router_id == router->router_id) {
                            first_router[pos] = &current_entry->link[i].router_id;
                        } else {
                            first_router[pos] = first_router[current_pos];
                        }
                    }
                }
            }
        }
        visited[current_pos] = TRUE;
        debug_println("set visited = true");
        int smallest = INFINITY;
        for (i = 0; i < router->num_database; i++) {
            if (!visited[i] && distance[i] < smallest) {
                current_pos = i;
                smallest = distance[i];
            }
        }
    }
    //debug_println("FINISHED INITIAL DJ -------------------------------------------------------");
    unsigned distance_to_routes[routes_added];
    uint32_t *first_router_for_routes[routes_added];
    for (i = 0; i < routes_added; i++) {
        distance_to_routes[i] = INFINITY;
        first_router_for_routes[i] = NULL;
    }
    for (i = 0; i < router->num_database; i++) {
        debug_println("%dth router.", i);
        database_entry_t *database_entry = &router->database[i];
        for (j = 0; j < database_entry->num_links; j++) {
            link_t *link = &database_entry->link[j];
            bool is_static = database_entry->router_id == router->router_id && link->router_id == 0;
            if (((get_time() - link->time_last) < 3*router->lsuint*1000) || is_static) {
                char subnet_no_str[16];
                ip_to_string(subnet_no_str, link->subnet_no);
                debug_println("finding route for %dth link with subnet_no=%s", j, subnet_no_str);
                for (k = 0; k < routes_added; k++) {
                    if (link->subnet_no == routes[k]->subnet_no) {
                        debug_println("checking distance: distance[%d]=%d + 1 < %d",i , distance[i], distance_to_routes[k]);
                        if (distance[i] + 1 < distance_to_routes[k]) {
                            distance_to_routes[k] = distance[i] + 1;
                            debug_println("set distance_to_routes[%d]=%d", k, distance_to_routes[k]);
                            first_router_for_routes[k] = first_router[i];
                        }
                        break;
                    }
                }
            }
        }
    }
    
    debug_println("Subnet No\tRouter ID\tDistance");
    for (i = 0; i < routes_added; i++) {
        char subnet_no_str[16], router_id_str[16];
        ip_to_string(subnet_no_str, routes[i]->subnet_no);
        if (first_router_for_routes[i] != NULL)
            ip_to_string(router_id_str, *first_router_for_routes[i]);
        else
            sprintf(router_id_str, "-------");
        debug_println("%s \t%s \t%d", subnet_no_str, router_id_str, distance_to_routes[i]);
    }
    
    router_delete_all_route_entries(router, TRUE);
    for (i = 0; i < routes_added; i++) {
        char subnet_no_str[16];
        ip_to_string(subnet_no_str, routes[i]->subnet_no);
        debug_println("%d subnet_no=%s",i, subnet_no_str);
        if (first_router_for_routes[i]) {
            char router_id_str[16];
            ip_to_string(router_id_str, *first_router_for_routes[i]);
            debug_println("isset and router_id=%s", router_id_str);
            if (*first_router_for_routes[i] == router->router_id) {
                for (j = 0; j < router->num_interfaces; j++) {
                    if (routes[i]->subnet_no == (router->interface[j].ip & router->interface[j].subnet_mask)) {
                        router_add_route(router, routes[i]->subnet_no, 0, router->interface[j].subnet_mask, router->interface[j].name, TRUE);
                        break;
                    }
                }
            } else {
                bool found = FALSE;
                for (j = 0; j < router->num_interfaces; j++) {
                    neighbor_t *neighbor = router->interface[j].neighbor_list_head;
                    while (neighbor != NULL) {
                        debug_println("neighbor->id=%lx, first_router_for_routes[%d]=%s", neighbor->id, i, router_id_str);
                        if (neighbor->id == *first_router_for_routes[i]) {
                            router_add_route(router, routes[i]->subnet_no, neighbor->ip, routes[i]->mask, router->interface[j].name, TRUE);
                            found = TRUE;
                            break;
                        }
                        neighbor = neighbor->next_neighbor;
                    }
                    if (found == TRUE)
                        break;
                }
                debug_println("found = %d", found);
            }
        }
    }
    
    debug_println("Routing table after Dijkstra:");
    //Print the routing table.
    debug_println("Prefix\t\tGateway\t\tMask\t\tInterface");
    for (i = 0; i < router->num_routes; i++) {
        route_t route = router->route[i];
        char prefix[15], next_hop[15], subnet[15];
        ip_to_string(prefix, route.prefix);
        ip_to_string(next_hop, route.next_hop);
        ip_to_string(subnet, route.subnet_mask);
        debug_println("%s \t%s \t%s\t%s", prefix, next_hop, subnet, route.interface.name);
    }
}

uint8_t *add_IPv4_header(uint8_t* payload /* given */,
                     uint8_t  proto,
                     uint32_t src, /* nbo */
                     uint32_t dest, /* nbo */
                     int len) {
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

void send_HELLO_packet(interface_t *intf) {
    unsigned len = PWOSPF_HEADER_LENGTH+HELLO_HEADER_LENGTH;
    byte *payload = malloc(len*sizeof(byte));
    struct pwospf_hdr *pwhdr = (void *)payload;
    PWHDR_VER_TYPE_SET(pwhdr, 2, TYPE_HELLO);
    PWHDR_LEN_SET(pwhdr, htons(len));
    PWHDR_ROUTER_ID_SET(pwhdr, get_router()->router_id);
    PWHDR_AREA_ID_SET(pwhdr, get_router()->area_id);
    pwhdr->_au_type = 0;
    pwhdr->_auth = 0;
    struct hello_hdr *hehdr = (void *)payload+PWOSPF_HEADER_LENGTH;
    HEHDR_SUB_MASK_SET(hehdr, intf->subnet_mask);
    HEHDR_HELLO_INT_SET(hehdr, htons(intf->helloint));
    PWHDR_CHKSUM_SET(pwhdr, 0);
    PWHDR_CHKSUM_SET(pwhdr, htons(calc_checksum(payload, len)));
    
    if (intf->neighbor_list_head != NULL) {
        byte *new_payload = add_IPv4_header(payload, PWOSPF_PROTOCOL, intf->ip, OSPF_IP, len);
        send_packet_intf(intf, new_payload, intf->ip, OSPF_IP, len+20, FALSE, TRUE);
    }
}

void send_LSU_packet(unsigned seq_no) {
    debug_println("Sending LSU packets (seq=%d)", seq_no);
    router_t *router = get_router();
    
    unsigned advert_no = 0;
    unsigned i;
    for (i = 0; i < router->num_interfaces; i++) {
        interface_t *intf = &router->interface[i];
        neighbor_t *neighbor = intf->neighbor_list_head;
        while (neighbor != NULL) {
            advert_no++;
            neighbor = neighbor->next_neighbor;
        }
    }
    unsigned len = PWOSPF_HEADER_LENGTH+LSU_HEADER_LENGTH+advert_no*LSU_AD_LENGTH;
    byte *payload = malloc(len*sizeof(byte));
    struct pwospf_hdr *pwhdr = (void *)payload;
    PWHDR_VER_TYPE_SET(pwhdr, 2, TYPE_LSU);
    PWHDR_LEN_SET(pwhdr, htons(len));
    PWHDR_ROUTER_ID_SET(pwhdr, router->router_id);
    PWHDR_AREA_ID_SET(pwhdr, router->area_id);
    pwhdr->_au_type = 0;
    pwhdr->_auth = 0;
    struct lsu_hdr *lshdr = (void *)payload+PWOSPF_HEADER_LENGTH;
    LSHDR_TTL_SET(lshdr, htons(32));
    LSHDR_SEQ_NO_SET(lshdr, htons(seq_no));
    unsigned advert_count = 0;
    if (advert_no > 0)
        debug_println("Router ID\tSubnet");
    for (i = 0; i < router->num_interfaces; i++) {
        interface_t *intf = &router->interface[i];
        neighbor_t *neighbor = intf->neighbor_list_head;
        while (neighbor != NULL) {
            char id_str[STRLEN_IP], subnet_str[STRLEN_IP];
            ip_to_string(id_str, neighbor->id);
            subnet_to_string(subnet_str, (neighbor->ip & intf->subnet_mask), intf->subnet_mask);
            debug_println("%s \t%s", id_str, subnet_str);
            struct lsu_ad *lsuad = (void *)payload+PWOSPF_HEADER_LENGTH+LSU_HEADER_LENGTH+advert_count*LSU_AD_LENGTH;
            LSUAD_SUBNET_NO_SET(lsuad, (neighbor->ip & intf->subnet_mask));
            LSUAD_MASK_SET(lsuad, intf->subnet_mask);
            LSUAD_ROUTER_ID_SET(lsuad, neighbor->id);
            advert_count++;
            neighbor = neighbor->next_neighbor;
        }
    }
    LSHDR_ADVERT_NO_SET(lshdr, htonl(advert_no));
    PWHDR_CHKSUM_SET(pwhdr, 0);
    PWHDR_CHKSUM_SET(pwhdr, htons(calc_checksum(payload, len)));
    
    for (i = 0; i < router->num_interfaces; i++) {
        interface_t *intf = &router->interface[i];
        neighbor_t *neighbor = intf->neighbor_list_head;
        while (neighbor != NULL) {
            if (neighbor->id != 0) {
                byte *new_payload = add_IPv4_header(payload, PWOSPF_PROTOCOL, intf->ip, neighbor->ip, len);
                send_packet_intf(intf, new_payload, intf->ip, neighbor->ip, len+20, FALSE, FALSE);
            }
            neighbor = neighbor->next_neighbor;
        }
    }
}

void generate_HELLO_thread() {
    router_t *router = get_router();
    double last_sent[router->num_interfaces];
    double last_LSU_send = get_time();
    unsigned seq_no = 0;
    unsigned i;
    for (i = 0; i < router->num_interfaces; i++) {
        last_sent[i] = 0;
    }
    while (TRUE) {
        for (i = 0; i < router->num_interfaces; i++) {
            interface_t *intf = &router->interface[i];
            if ((get_time() - last_sent[i]) > intf->helloint*1000) {
                if (i == 0) {
                    /*debug_println("Printing HW routing table:");
                    unsigned j;
                    for (j = 0; j < 32; j++) {
#ifdef _CPUMODE_
                        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_RD_ADDR, j);
                        uint32_t ip, mask, next_hop, oq;
                        readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP, &ip);
                        readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP_MASK, &mask);
                        readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_NEXT_HOP_IP, &next_hop);
                        readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_OQ, &oq);
                        char ip_str[STRLEN_IP], mask_str[STRLEN_IP], next_hop_str[STRLEN_IP];
                        ip_to_string(ip_str, ip);
                        ip_to_string(next_hop_str, next_hop);
                        ip_to_string(mask_str, mask);
                        debug_println("%s \t%s \t%s   \t%02X", ip_str, next_hop_str, mask_str, oq);
#endif
                    }
                    
                    debug_println("Printing HW IP Filter:");
                    
                    for (j = 0; j < 32; j++) {
#ifdef _CPUMODE_
                        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_FILTER_RD_ADDR, j);
                        uint32_t ip;
                        readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_FILTER_IP, &ip);
                        char ip_str[STRLEN_IP];
                        ip_to_string(ip_str, ip);
                        debug_println("%s", ip_str);
#endif
                    }
                    
                    debug_println("Printing HW ARP table:");
                    
                    for (j = 0; j < 32; j++) {
#ifdef _CPUMODE_
                        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_RD_ADDR, j);
                        uint32_t ip, low, high;
                        readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_IP, &ip);
                        readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_MAC_LOW, &low);
                        readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_MAC_HIGH, &high);
                        char ip_str[STRLEN_IP], low_str[STRLEN_IP], high_str[STRLEN_IP];
                        ip_to_string(ip_str, ip);
                        ip_to_string(low_str, low);
                        ip_to_string(high_str, high);
                        debug_println("%s %s %s", ip_str, low_str, high_str);
#endif
                    }*/
                
                }
                debug_println("Sending HELLO on interface %d.", i);
                send_HELLO_packet(intf);
                last_sent[i] = get_time();
            }
            
            neighbor_t *neighbor = intf->neighbor_list_head;
            neighbor_t *previous = NULL;
            while (neighbor != NULL) {
                if ((get_time() - neighbor->time_last) > 3*intf->helloint*1000 && neighbor->id != 0) {
                    debug_println("Neighbor timeout, exceeds %ds.", 3*intf->helloint);
                    if (previous) {
                        previous->next_neighbor = neighbor->next_neighbor;
                    } else {
                        intf->neighbor_list_head = neighbor->next_neighbor;
                    }
                    database_entry_t *database_entry = router_find_database_entry(router, router->router_id);
                    if (neighbor->id == 0 || !router_remove_link_from_database_entry(router, database_entry, neighbor->id)) {
                        debug_println("ERROR: removing link failed!");
                    }
                    //free(neighbor);
                    //neighbor = NULL;
                    update_routing_table();
                    send_LSU_packet(seq_no);
                    last_LSU_send = get_time();
                    seq_no++;
                }
                previous = neighbor;
                neighbor = neighbor->next_neighbor;
            }
        }
        if (router->num_database > 0 && (router->added_links || (get_time() - last_LSU_send) > router->lsuint*1000)) {
            debug_println("Expired: %s, Added links: %s", (((get_time() - last_LSU_send) > router->lsuint*1000)? "YES" : "NO"),
                          ((router->added_links)? "YES" : "NO"));
            send_LSU_packet(seq_no);
            last_LSU_send = get_time();
            seq_no++;
            router->added_links = FALSE;
        }
        sleep(1);
        debug_println("HELLO thread sleeping for 1s.");
    }
}

void generate_pending_ARP_thread() {
    router_t *router = get_router();
    unsigned i;
    while (TRUE) {
        pthread_mutex_lock(&router->pending_arp_lock);
        for (i = 0; i < router->num_pending_arp; i++) {
            pending_arp_entry_t *pending_arp_entry = &router->pending_arp[i];
            send_ARP_request(pending_arp_entry->ip, pending_arp_entry->num_sent++);
            if (pending_arp_entry->num_sent == 5) {
                debug_println("Not responding to ARP request!");
                handle_not_repsponding_to_arp(pending_arp_entry->payload, pending_arp_entry->len);
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
        sleep(1);
        debug_println("Pending ARP thread sleeping for 1s.");
    }
}

void handle_PWOSPF_packet(packet_info_t *pi) {
    struct ip_hdr *iphdr = (void *)pi->packet+IPV4_HEADER_OFFSET;
    struct pwospf_hdr *pwhdr = (void *)pi->packet+IPV4_HEADER_OFFSET+IPV4_HEADER_LENGTH;
    if (PWHDR_VER(pwhdr) != 2) {
        debug_println("Invalid PWOSPF packet version, dropping packet!");
        return;
    }
    
    if (pwhdr->_auth != 0) {
        debug_println("Authentication not zero, dropping packet!");
        return;
    }
    
    if (calc_checksum(pi->packet+IPV4_HEADER_OFFSET+IPV4_HEADER_LENGTH, pi->len-(IPV4_HEADER_OFFSET+IPV4_HEADER_LENGTH)) != 0) {
        debug_println("Invalid PWOSPF checksum, dropping packet!");
        return;
    }
    
    if (PWHDR_AREA_ID(pwhdr) != get_router()->area_id) {
        debug_println("Invalid area ID, dropping packet!");
        return;
    }
    
    //Do I check auth?
    
    //TODO: CHECK LENGTH!
    
    addr_ip_t src = IPH_SRC(iphdr);
    
    uint8_t type = PWHDR_TYPE(pwhdr);
    
    
    if (type == TYPE_HELLO) {
        debug_println("HELLO packet!");
        struct hello_hdr *hehdr = (void *)pi->packet+IPV4_HEADER_OFFSET+IPV4_HEADER_LENGTH+PWOSPF_HEADER_LENGTH;
        if (pi->interface->subnet_mask != HEHDR_SUB_MASK(hehdr) || pi->interface->helloint != ntohs(HEHDR_HELLO_INT(hehdr))) {
            debug_println("Subnet mask or helloint mismatch, dropping packet!");
            return;
        }
        bool updated = FALSE;
        if (pi->interface->neighbor_list_head == NULL) {
            debug_println("Adding new neighbor at start");
            neighbor_t *neighbor = malloc(sizeof(neighbor_t));
            neighbor->time_last = get_time();
            neighbor->ip = src;
            neighbor->id = PWHDR_ROUTER_ID(pwhdr);
            neighbor->next_neighbor = NULL;
            pi->interface->neighbor_list_head = neighbor;
        } else {
            neighbor_t *current_neighbor = pi->interface->neighbor_list_head;
            do {
                if (current_neighbor->ip == src) {
                    debug_println("Found neighbor, updating last recieved Hello packet time");
                    current_neighbor->time_last = get_time();
                    updated = TRUE;
                    break;
                }
                current_neighbor = current_neighbor->next_neighbor;
            } while (current_neighbor != NULL);
            
            if (current_neighbor == NULL) {
                debug_println("Adding new neighbor");
                neighbor_t *neighbor = malloc(sizeof(neighbor_t));
                neighbor->time_last = get_time();
                neighbor->ip = src;
                neighbor->id = PWHDR_ROUTER_ID(pwhdr);
                neighbor->next_neighbor = pi->interface->neighbor_list_head;
                pi->interface->neighbor_list_head = neighbor;
            }
        }
        if (!updated && PWHDR_ROUTER_ID(pwhdr) != 0) {
            char router_str[STRLEN_IP];
            ip_to_string(router_str, PWHDR_ROUTER_ID(pwhdr));
            debug_println("New neighbour %s says HELLO.\nAdding to database.", router_str);
            database_entry_t *database_entry = router_find_database_entry(get_router(), get_router()->router_id);
            link_t link[1];
            link->router_id = PWHDR_ROUTER_ID(pwhdr);
            link->mask = make_ip_addr("255.255.255.0"); //TODO: possibly not /24
            link->subnet_no = link->mask & iphdr->src.addr;
            
            router_add_link_to_database_entry(get_router(), database_entry, link);
            get_router()->added_links = TRUE;
            update_routing_table();
        }
        
        
        return;
    } else if (type == TYPE_LSU) {
        debug_println("Link State Update packet!");
        struct lsu_hdr *lshdr = (void *)pi->packet+IPV4_HEADER_OFFSET+IPV4_HEADER_LENGTH+PWOSPF_HEADER_LENGTH;

        if (PWHDR_ROUTER_ID(pwhdr) == get_router()->router_id) {
            debug_println("Source was self, dropping packet!");
            return;
        }
        database_entry_t *database_entry = router_find_database_entry(get_router(), PWHDR_ROUTER_ID(pwhdr));
        if (database_entry) {
            debug_println("Found matching router_id");
            if (database_entry->seq_no == LSHDR_SEQ_NO(lshdr)) {
                debug_println("Last packet from host has matching seq num, dropping packet!");
                return;
            }
            
            if (memcmp ( pwhdr, database_entry->last_packet , pi->len ) == 0) {
                //QUESTION: How much of the packet to check? If seq_no is equal then caught above?
                debug_println("Last packet from host is equivalent, dropping packet!");
                return;
            }
            
            unsigned num_adverts = ntohl(LSHDR_ADVERT_NO(lshdr));
            /*debug_println("Initial:\nRouter ID\tSubnet");
            unsigned i;
            for (i = 0; i < database_entry->num_links; i++) {
                link_t *link = &database_entry->link[i];
                char id_str[16], subnet_str[16];
                ip_to_string(id_str, link->router_id);
                ip_to_string(subnet_str, link->subnet_no);
                debug_println("%s \t%s/%d", id_str, subnet_str, ones(link->mask));
            }*/
            bool changed = FALSE;
            if (num_adverts != database_entry->num_links) {
                changed = TRUE;
            } else {
                unsigned i;
                for (i = 0; i < num_adverts; i++) {
                    struct lsu_ad *lsuad = (void *)pi->packet+IPV4_HEADER_OFFSET+IPV4_HEADER_LENGTH+PWOSPF_HEADER_LENGTH+LSU_HEADER_LENGTH+i*LSU_AD_LENGTH;
                    link_t *link = database_find_link(database_entry, LSUAD_ROUTER_ID(lsuad), LSUAD_SUBNET_NO(lsuad));
                    if (link == NULL) {
                        changed = TRUE;
                        break;
                    } else if (link->mask != LSUAD_MASK(lsuad)) {
                        changed = TRUE;
                        break;
                    }
                }
            }
            debug_println("Changed: %s", (changed) ? "True": "False");
            if (changed) {
                debug_println("Router ID\tSubnet");
                unsigned i;
                pthread_mutex_lock(&get_router()->database_lock);
                for (i = 0; i < num_adverts; i++) {
                    struct lsu_ad *lsuad = (void *)pi->packet+IPV4_HEADER_OFFSET+IPV4_HEADER_LENGTH+PWOSPF_HEADER_LENGTH+LSU_HEADER_LENGTH+i*LSU_AD_LENGTH;
                    link_t *link = &database_entry->link[i];
                    link->router_id = LSUAD_ROUTER_ID(lsuad);
                    link->subnet_no = LSUAD_SUBNET_NO(lsuad);
                    link->mask = LSUAD_MASK(lsuad);
                    link->time_last = get_time();
                    char id_str[STRLEN_IP], subnet_str[STRLEN_IP];
                    ip_to_string(id_str, link->router_id);
                    subnet_to_string(subnet_str, link->subnet_no, link->mask);
                    debug_println("%s \t%s", id_str, subnet_str);
                }
                database_entry->num_links = num_adverts;
                pthread_mutex_unlock(&get_router()->database_lock);
                get_router()->added_links = TRUE;
                update_routing_table();
            }
        } else {
            debug_println("Not found matching router_id");
            unsigned num_adverts = ntohl(LSHDR_ADVERT_NO(lshdr));
            if (num_adverts < 1 || num_adverts > 10) {
                debug_println("ERROR: number of adverts in packet is %d", num_adverts);
                return;
            }
            debug_println("Router ID\tSubnet");
            link_t link[ROUTER_MAX_LINKS];
            unsigned i;
            for (i = 0; i < num_adverts; i++) {
                struct lsu_ad *lsuad = (void *)pi->packet+IPV4_HEADER_OFFSET+IPV4_HEADER_LENGTH+PWOSPF_HEADER_LENGTH+LSU_HEADER_LENGTH+i*LSU_AD_LENGTH;
                link[i].router_id = LSUAD_ROUTER_ID(lsuad);
                link[i].subnet_no = LSUAD_SUBNET_NO(lsuad);
                link[i].mask = LSUAD_MASK(lsuad);
                link[i].time_last = get_time();
                char id_str[STRLEN_IP], subnet_str[STRLEN_IP];
                ip_to_string(id_str, link[i].router_id);
                subnet_to_string(subnet_str, link[i].subnet_no, link[i].mask);
                debug_println("%s \t%s", id_str, subnet_str);
                
            }
            router_add_database_entry(get_router(), PWHDR_ROUTER_ID(pwhdr), link, num_adverts, LSHDR_SEQ_NO(lshdr), pi->packet, pi->len);
            get_router()->added_links = TRUE;
            update_routing_table();
        }
        //Forward packet.
        if (ntohs(LSHDR_TTL(lshdr)) >= 1) {
            LSHDR_TTL_DEC(lshdr);
        } else {
            printf("PWOSF LSU packet exceeded TTL, not forwarding!\n");
            return;
    
        }
        unsigned len = pi->len-(IPV4_HEADER_OFFSET+IPV4_HEADER_LENGTH);
        PWHDR_CHKSUM_SET(pwhdr, 0);
        PWHDR_CHKSUM_SET(pwhdr, htons(calc_checksum(pi->packet+IPV4_HEADER_OFFSET+IPV4_HEADER_LENGTH, len)));
        unsigned i;
        router_t *router = get_router();
        byte *payload = malloc(len*sizeof(byte));
        memcpy(payload, pi->packet+IPV4_HEADER_OFFSET+IPV4_HEADER_LENGTH, len); //Copy PWOSPF packet.
        for (i = 0; i < router->num_interfaces; i++) {
            interface_t *intf = &router->interface[i];
            neighbor_t *neighbor = intf->neighbor_list_head;
            while (neighbor != NULL) {
                if (neighbor->ip != IPH_SRC(iphdr) && neighbor->id != 0) {
                    byte *new_payload = add_IPv4_header(payload, PWOSPF_PROTOCOL, intf->ip, neighbor->ip, len);
                    send_packet_intf(intf, new_payload, intf->ip, neighbor->ip, len+20, FALSE, FALSE);
                    
                }
                neighbor = neighbor->next_neighbor;
            }
        }
    } else {
        debug_println("Invalid PWOSPF packet type, dropping packet!");
        return;
    }
        
}

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
                generate_response_ICMP_packet(pi, 3, 2);
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

void router_handle_packet( packet_info_t* pi ) {
    char ip_str[16];
    ip_to_string(ip_str, pi->interface->ip);
    printf("-----------New Packet on %s(%s)---------\n", pi->interface->name, ip_str);
    
    uint16_t ether_type = (*(pi->packet+12) << 8) + *(pi->packet+13);
    
    switch (ether_type) {
        case ARP_ETHERTYPE:    handle_ARP_packet(pi); break;
        case IPV4_ETHERTYPE:    handle_IPv4_packet(pi); break;
    }
}

#ifdef _THREAD_PER_PACKET_
void* router_pthread_main( void* vpacket ) {
    static unsigned id = 0;
    char name[15];
    snprintf( name, 15, "PHandler %u", id++ );
    debug_pthread_init( name, "Packet Handler Thread" );
    pthread_detach( pthread_self() );
    router_handle_packet( (packet_info_t*)vpacket );
    debug_println( "Packet Handler Thread is shutting down" );
    return NULL;
}
#else
void router_handle_work( work_t* work ) {
    /* process the work */
    switch( work->type ) {
    case WORK_NEW_PACKET:
        router_handle_packet( (packet_info_t*)work->work );
        break;

    default:
        die( "Error: unknown work type %u", work->type );
    }
}
#endif


interface_t* router_lookup_interface_via_ip( router_t* router, addr_ip_t ip ) {
    unsigned i;
    for (i = 0; i < router->num_interfaces; i++) {
        if (router->interface[i].ip == ip) {
            return &router->interface[i];
        }
    }
    return NULL;
}

interface_t* router_lookup_interface_via_name( router_t* router,
                                               const char* name ) {
    unsigned i;
    for (i = 0; i < router->num_interfaces; i++) {
        if (strcmp(router->interface[i].name,name) == 0) {
            return &router->interface[i];
        }
    }
    return NULL;
}

#ifdef _CPUMODE_
void setup_interface_registers( router_t* router, int intf_num) {
    interface_t *intf = &router->interface[intf_num];
    uint32_t low = mac_lo(&intf->mac);
    uint32_t high = mac_hi(&intf->mac);
    debug_println("low=%08X high=%08X", low, high);
    uint32_t low_out, high_out;
    
    if (intf_num == 0) {
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_0_LOW, low);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_0_HIGH, high);
        
        readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_0_LOW, &low_out);
        readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_0_HIGH, &high_out);
    } else if (intf_num == 1) {
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_1_LOW, low);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_1_HIGH, high);
        
        readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_1_LOW, &low_out);
        readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_1_HIGH, &high_out);
    } else if (intf_num == 2) {
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_2_LOW, low);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_2_HIGH, high);
        
        readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_2_LOW, &low_out);
        readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_2_HIGH, &high_out);
    } else if (intf_num == 3) {
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_3_LOW, low);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_3_HIGH, high);
    
        readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_3_LOW, &low_out);
        readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_3_HIGH, &high_out);
    }
    
    assert(low_out == low);
    assert(high_out == high);
}
#endif

void router_add_interface( router_t* router,
                           const char* name,
                           addr_ip_t ip, addr_ip_t mask, addr_mac_t mac ) {
    interface_t* intf;

    debug_println("called router_add_interface");    // TODO remove debugging line

    intf = &router->interface[router->num_interfaces];

    strcpy( intf->name, name );
    intf->ip = ip;
    intf->subnet_mask = mask;
    intf->mac = mac;
    intf->enabled = TRUE;
    intf->neighbor_list_head = NULL;
    intf->helloint = 5;

#ifdef MININET_MODE
    // open a socket to talk to the hw on this interface
    debug_println("*******iface %s (check the name!)\n", name);
    intf->hw_fd = sr_mininet_init_intf_socket_withname(name);   // (router name isn't used in this version)

    // set pretty hw_id 
    if(      strcmp(name+PREFIX_LENGTH,"eth0")==0 ) intf->hw_id = INTF0;
    else if( strcmp(name+PREFIX_LENGTH,"eth1")==0 ) intf->hw_id = INTF1;
    else if( strcmp(name+PREFIX_LENGTH,"eth2")==0 ) intf->hw_id = INTF2;
    else if( strcmp(name+PREFIX_LENGTH,"eth3")==0 ) intf->hw_id = INTF3;
    else {
      debug_println( "Unknown interface name: %s. Setting hw_id to interface number.\n", name );
      intf->hw_id = router->num_interfaces;
    }

    // initialize the lock to ensure only one write per interface at a time
    pthread_mutex_init( &intf->hw_lock, NULL );
#endif
    
#ifdef _CPUMODE_
     // open a socket to talk to the hw on this interface
    debug_println("*******iface %s (check the name!)\n", name);
    
    int intf_num = -1;
    
    // set pretty hw_id
    if( strcmp(name+PREFIX_LENGTH,"eth0")==0 ) {
        intf->hw_id = INTF0;
        intf->hw_oq = OUT_INTF0;
        strcpy(intf->name,"nf0");
        intf_num = 0;
    } else if( strcmp(name+PREFIX_LENGTH,"eth1")==0 ) {
        intf->hw_id = INTF1;
        intf->hw_oq = OUT_INTF1;
        strcpy(intf->name,"nf1");
        intf_num = 1;
    } else if( strcmp(name+PREFIX_LENGTH,"eth2")==0 ) {
        intf->hw_id = INTF2;
        intf->hw_oq = OUT_INTF2;
        strcpy(intf->name,"nf2");
        intf_num = 2;
    } else if( strcmp(name+PREFIX_LENGTH,"eth3")==0 ) {
        intf->hw_id = INTF3;
        intf->hw_oq = OUT_INTF3;
        strcpy(intf->name,"nf3");
        intf_num = 3;
    } else {
        debug_println( "Unknown interface name: %s. Setting hw_id to interface number.\n", name );
        intf->hw_id = router->num_interfaces;
    }
    
    if (intf_num != -1) {
        intf->hw_fd = sr_cpu_init_intf_socket(intf_num);
        setup_interface_registers(router, intf_num);
    }

    
    // initialize the lock to ensure only one write per interface at a time
    pthread_mutex_init( &intf->hw_lock, NULL );
#endif

    router->num_interfaces += 1;

}

link_t *database_find_link(database_entry_t *database_entry, uint32_t router_id, uint32_t subnet_no) {
    //debug_println("called router_find_link");    // TODO remove debugging line
    
    
    unsigned i;
    for (i = 0; i < database_entry->num_links; i++) {
        link_t *link = &database_entry->link[i];
        if (link->router_id == router_id && link->subnet_no == subnet_no) {
            return link;
        }
    }
    
    return NULL;
}

database_entry_t *router_find_database_entry( router_t* router, uint32_t router_id) {
    //debug_println("called router_find_database_entry");    // TODO remove debugging line
    
    pthread_mutex_lock(&router->database_lock);
    
    unsigned i;
    for (i = 0; i < router->num_database; i++) {
        database_entry_t *database_entry = &router->database[i];
        if (database_entry->router_id == router_id) {
            pthread_mutex_unlock(&router->database_lock);
            return database_entry;
        }
    }
    
    pthread_mutex_unlock(&router->database_lock);
    
    return NULL;
}

void router_add_link_to_database_entry( router_t *router, database_entry_t *database_entry, link_t *link_to_add) {
    
    
    
    pthread_mutex_lock(&router->database_lock);
    unsigned i;
    for (i = 0; i < database_entry->num_links; i++) {
        link_t *link = &database_entry->link[i];
        if (link->router_id == link_to_add->router_id) {
            pthread_mutex_unlock(&router->database_lock);
            link->time_last = get_time();
            return;
        }
    }
    
    link_t *new_link = &database_entry->link[database_entry->num_links];
    new_link->router_id = link_to_add->router_id;
    new_link->subnet_no = link_to_add->subnet_no;
    new_link->mask = link_to_add->mask;
    new_link->time_last = get_time();
    
    database_entry->num_links += 1;
    
    pthread_mutex_unlock(&router->database_lock);
}

bool router_remove_link_from_database_entry( router_t *router, database_entry_t *database_entry, uint32_t router_id) {
    
    pthread_mutex_lock(&router->database_lock);
    
    bool found = FALSE;
    unsigned i;
    for (i = 0; i < database_entry->num_links; i++) {
        link_t *link = &database_entry->link[i];
        if (link->router_id == router_id) {
            pthread_mutex_unlock(&router->database_lock);
            found = TRUE;
            break;
        }
    }
    
    if (found) {
        unsigned pos = i;
        for (i = pos; i < database_entry->num_links-1; i++) {
            database_entry->link[i] = database_entry->link[i+1];
        }
        database_entry->num_links -= 1;
    }
    
    pthread_mutex_unlock(&router->database_lock);
    return found;
}

void router_add_database_entry( router_t* router, uint32_t router_id, link_t link[], unsigned num_links, uint16_t seq_no, byte *packet, unsigned len) {
    database_entry_t* database_entry;
    
    pthread_mutex_lock(&router->database_lock);
    
    
    //debug_println("called router_add_database_entry");    // TODO remove debugging line
    
    database_entry = &router->database[router->num_database];
    unsigned i;

    if (num_links > 10) {
        debug_println("ERROR: num_links exceeds 10!");
        pthread_mutex_unlock(&router->database_lock);
        return;
    }
    
    for (i = 0; i < num_links; i++) {
        database_entry->link[i] = link[i];
    }
    
    database_entry->router_id = router_id;
    database_entry->num_links = num_links;
    database_entry->seq_no = seq_no;
    database_entry->last_packet = packet;
    database_entry->len = len;
    
    router->num_database += 1;
    
    pthread_mutex_unlock(&router->database_lock);
}

void router_add_route( router_t* router, addr_ip_t prefix, addr_ip_t next_hop,
                      addr_ip_t subnet_mask, const char *intf_name, bool dynamic ) {
    route_t* route;
    
    pthread_mutex_lock(&router->route_table_lock);
    
    
    //debug_println("called router_add_route");    // TODO remove debugging line
    
    interface_t *interface_p = router_lookup_interface_via_name(router, intf_name);
    
    if (interface_p == NULL)
        die( "Error creating routing table, cannot convert interface name (%s) to valid interface", intf_name );
    
    
    unsigned i = 0;
    unsigned j;
    if (!dynamic) {
        for (i = 0; i < router->num_routes; i++) {
            if (!dynamic)
                break;
        }
    }
    bool ended = TRUE;
    for (j = i; j < router->num_routes; j++) {
        if (router->route[i].subnet_mask > subnet_mask || dynamic != router->route[i].dynamic) {
            ended = FALSE;
            break;
        }
    }
    if (!ended) {
        for (i = router->num_routes; i > j; j++) {
            router->route[i] = router->route[i-1];
#ifdef _CPUMODE_
            writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP, 0);
            writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP_MASK, 0);
            writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_NEXT_HOP_IP, 0);
            writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_OQ, 0);
            writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_WR_ADDR, router->num_interfaces+i-1);
            
            writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP, ntohl(router->route[i].prefix));
            writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP_MASK, ntohl(router->route[i].subnet_mask));
            writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_NEXT_HOP_IP, ntohl(router->route[i].next_hop));
            writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_OQ, router->route[i].interface.hw_oq);
            writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_WR_ADDR, router->num_interfaces+i);
#endif
        }
    }
    
    if (ended)
        j = router->num_routes;
    
    route = &router->route[j];
    char intf_str[10];
    intf_to_string(interface_p, intf_str, 10);
    route->prefix = prefix;
    route->next_hop = next_hop;
    route->subnet_mask = subnet_mask;
    route->interface = *interface_p;
    route->dynamic = dynamic;
    
#ifdef _CPUMODE_

    writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP, ntohl(prefix));
    writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP_MASK, ntohl(subnet_mask));
    writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_NEXT_HOP_IP, ntohl(next_hop));
    writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_OQ, interface_p->hw_oq);
    writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_WR_ADDR, router->num_interfaces+j);
    
    uint32_t *prefix_out = malloc(sizeof(uint32_t));
    uint32_t *subnet_mask_out = malloc(sizeof(uint32_t));
    uint32_t *next_hop_out = malloc(sizeof(uint32_t));
    uint32_t *oq_out = malloc(sizeof(uint32_t));
    
    writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_RD_ADDR, router->num_interfaces+j);
    readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP, prefix_out);
    readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP_MASK, subnet_mask_out);
    readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_NEXT_HOP_IP, next_hop_out);
    readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_OQ, oq_out);
    
    assert(*prefix_out == ntohl(prefix));
    assert(*subnet_mask_out == ntohl(subnet_mask));
    assert(*next_hop_out == ntohl(next_hop));
    assert(*oq_out == interface_p->hw_oq);
    
    free(prefix_out);
    free(subnet_mask_out);
    free(next_hop_out);
    free(oq_out);
    
#endif

    router->num_routes += 1;
    
    pthread_mutex_unlock(&router->route_table_lock);
}

route_t *router_find_route_entry( router_t *router, addr_ip_t dest, addr_ip_t gw, addr_ip_t mask, const char *intf_name) {
    //debug_println("called router_find_route_entry");    // TODO remove debugging line
    
    pthread_mutex_lock(&router->route_table_lock);
    
    unsigned i;
    printf("num_routes=%d\n", router->num_routes);
    for (i = 0; i < router->num_routes; i++) {
        route_t *route_entry = &router->route[i];
        if (route_entry->prefix == dest && route_entry->next_hop == gw && route_entry->subnet_mask == mask
                                        && route_entry->interface.name == intf_name) {
            pthread_mutex_unlock(&router->route_table_lock);
            return route_entry;
        }
    }
    
    pthread_mutex_unlock(&router->route_table_lock);
    
    return NULL;
}

bool router_delete_route_entry( router_t *router, addr_ip_t dest, addr_ip_t gw, addr_ip_t mask, const char *intf_name) {
    
    pthread_mutex_lock(&router->route_table_lock);
    
    //debug_println("called router_delete_route_entry");    // TODO remove debugging line
    unsigned i;
    for (i = 0; i < router->num_routes; i++) {
        route_t *route_entry = &router->route[i];
        if  (route_entry->prefix == dest && route_entry->next_hop == gw && route_entry->subnet_mask == mask
             && route_entry->interface.name == intf_name)  {
            break;
        }
    }
    unsigned j;
    for (j = i; j < router->num_routes-1; j++) {
        router->route[j] = router->route[j+1];
#ifdef _CPUMODE_
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP_MASK, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_NEXT_HOP_IP, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_OQ, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_WR_ADDR, router->num_interfaces+j+1);
       
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP, ntohl(router->route[j].prefix));
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP_MASK, ntohl(router->route[j].subnet_mask));
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_NEXT_HOP_IP, ntohl(router->route[j].next_hop));
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_OQ,router->route[j].interface.hw_oq);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_WR_ADDR, router->num_interfaces+j);
#endif
    }
    
#ifdef _CPUMODE_
    
    if (i == router->num_arp_cache -1) { //If not moving entries, just deleting last one.
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP_MASK, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_NEXT_HOP_IP, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_OQ, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_WR_ADDR, router->num_interfaces+i);
    }
    
#endif
    
    bool succeded = FALSE;
    if (i < router->num_routes) {
        succeded = TRUE;
    }
    router->num_routes -= 1;
    pthread_mutex_unlock(&router->route_table_lock);
    
    return succeded;
}

void router_delete_all_route_entries(router_t *router, bool dynamic) {
    
    pthread_mutex_lock(&router->route_table_lock);
    
    unsigned num_replace = 0;
    
    //debug_println("called router_delete_all_route_entries");    // TODO remove debugging line
    /*unsigned replace[router->num_routes];
    
    unsigned replaced = 0;
    unsigned move[router->num_routes];
    unsigned num_move = 0;
    unsigned moved = 0;
    unsigned i;
    for (i = 0; i < router->num_routes; i++) {
        if (router->route[i].dynamic == dynamic) {
            replace[num_replace++] = i;
        } else if (num_replace > replaced) {
            router->route[replace[replaced]] = router->route[i];
            move[num_move++] = i;
            if (num_move > moved && move[moved] < replace[replaced]) {
                router->route[move[moved++]] = router->route[replace[replaced]];
            } else {
                replaced++;
            }
        } else if (num_move > moved) {
            router->route[move[moved++]] = router->route[i];
            move[num_move++] = i;
        }
    }*/
    unsigned i, j;
    for (i = 0; i < router->num_routes; i++) {
        if (!dynamic)
            break;
    }
    if (dynamic) {
        if (i != 0) { //No dynamics so no need to move.
            num_replace = i;
#ifdef _CPUMODE_
            for (j = 0; j < i;  j++) {
                writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP, 0);
                writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP_MASK, 0);
                writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_NEXT_HOP_IP, 0);
                writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_OQ, 0);
                writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_WR_ADDR, router->num_interfaces+router->num_routes-j-1);
            }
#endif
            for (j = i; j < router->num_routes; j++) {
                router->route[j] = router->route[i+j];
                
#ifdef _CPUMODE_
                writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP, ntohl(router->route[j].prefix));
                writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP_MASK, ntohl(router->route[j].subnet_mask));
                writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_NEXT_HOP_IP, ntohl(router->route[j].next_hop));
                writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_OQ, router->route[j].interface.hw_oq);
                writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_WR_ADDR, router->num_interfaces+j);
#endif

            }
        }
    }
    

    if (!dynamic) {
        num_replace = router->num_routes - i;
#ifdef _CPUMODE_
        for (j = i; j < router->num_routes;  j++) {
            writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP, 0);
            writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP_MASK, 0);
            writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_NEXT_HOP_IP, 0);
            writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_OQ, 0);
            writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_WR_ADDR, router->num_interfaces+j);
        }
#endif
    }
    
    router->num_routes -= num_replace;
    
    
    pthread_mutex_unlock(&router->route_table_lock);
}

void sr_read_routes_from_file( router_t* router, const char* filename ) {
    FILE* fp;
    const char* err;
    char  line[512];
    char  str_prefix[32];
    char  str_next_hop[32];
    char  str_mask[32];
    char  str_intf_name[32];
    
    struct in_addr prefix, next_hop, subnet_mask;
    
    err = "Error loading routing table,";
    debug_println( "Loading routing table from %s", filename );
    
    assert(filename);
    fp = fopen(filename,"r");
    if( !fp )
        die( "Could  not access the routing file named %s", filename );
    
    while( fgets(line,512,fp) != 0) {
        sscanf( line, "%s %s %s %s",
               str_prefix,
               str_next_hop,
               str_mask,
               str_intf_name);
        
        if( inet_aton(str_prefix,&prefix) == 0 )
            die( "%s cannot convert prefix (%s) to valid IP", err, str_prefix );
        
        if( inet_aton(str_next_hop,&next_hop) == 0 )
            die( "%s cannot convert next hop (%s) to valid IP", err, str_next_hop );
        
        if( inet_aton(str_mask,&subnet_mask) == 0 )
            die( "%s cannot convert subnet mask (%s) to valid IP", err, str_mask );
        
        router_add_route(router, prefix.s_addr, next_hop.s_addr, subnet_mask.s_addr, str_intf_name, FALSE);
    }
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
    debug_println("Adding arp entry  to %d -----------------------------------------------------------------------------------------------------------", router->num_arp_cache-1);
    
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
        debug_println("Adding arp entry to %d -----------------------------------------------------------------------------------------------------------", j);
        
#endif
    }
    
#ifdef _CPUMODE_
    
    if (i == router->num_arp_cache -1) { //If not moving entries, just deleting last one.
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_IP, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_MAC_LOW, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_MAC_HIGH, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_WR_ADDR, i);
        debug_println("Adding arp entry to %d -----------------------------------------------------------------------------------------------------------", i);
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
        debug_println("Adding arp entry to %d -----------------------------------------------------------------------------------------------------------", i);
        
    }
    
#endif
    
    pthread_mutex_unlock(&router->arp_cache_lock);
}

ip_mac_t *router_find_arp_entry( router_t *router, addr_ip_t ip) {
    debug_println("Finding arp entry.");    // TODO remove debugging line
    
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