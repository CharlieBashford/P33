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
#include "lwtcp/lwip/icmp.h"
#include "cli/cli_ping.h"
#include "ip.h"
#include "routing.h"
#include "arp.h"
#include "icmp.h"

void sys_thread_new(void (* thread)(void *arg), void *arg);

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
    router->num_policies = 0;
    router->lsuint = 30;
    router->added_links = FALSE;

    router->use_ospf = FALSE;
    
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
            
            debug_println("Waiting to get lock");
            pthread_mutex_lock(&get_router()->pending_arp_lock);
            bool found = FALSE;
            unsigned i;
            for (i = 0; i < get_router()->num_pending_arp; i++) {
                if (get_router()->pending_arp[i].ip == dest) {
                    found = TRUE;
                    break;
                }
            }
            if (found == FALSE) {
                send_ARP_request(dest, 1);

                pending_arp_entry_t *pending_arp_entry = &get_router()->pending_arp[get_router()->num_pending_arp];
                pending_arp_entry->ip = dest;
                pending_arp_entry->src = src;
                pending_arp_entry->payload = payload;
                pending_arp_entry->len = len;
                pending_arp_entry->num_sent = 1;
                
                get_router()->num_pending_arp += 1;
            }
            
            pthread_mutex_unlock(&get_router()->pending_arp_lock);
            debug_println("Finished with lock");
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
    
    if (intf->enabled == FALSE) {
        debug_println("SENDING: DROPPING PACKET! Interface %s is disabled.", intf->name);
        return 0;
    }
    sr_integ_low_level_output(get_sr(), packet, len+14, intf);
    
    return 0;
}

void router_handle_packet( packet_info_t* pi ) {
    char ip_str[16];
    ip_to_string(ip_str, pi->interface->ip);
    printf("-----------New Packet on %s(%s)---------\n", pi->interface->name, ip_str);
    if (pi->interface->enabled == FALSE) {
        debug_println("RECIEVING: DROPPING PACKET! Interface %s is disabled.", pi->interface->name);
        return;
    }
    
    uint16_t ether_type = (*(pi->packet+12) << 8) + *(pi->packet+13);
    
    switch (ether_type) {
        case ARP_ETHERTYPE:    handle_ARP_packet(pi); break;
        case IPV4_ETHERTYPE:    handle_IPv4_packet(pi); break;
        default: debug_println("Dropped Packet: can't respond to ethertype %04X.", ether_type);
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