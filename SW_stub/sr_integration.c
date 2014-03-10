
/*-----------------------------------------------------------------------------
 * Filename: sr_integration.c
 * Purpose: Methods called by the lowest-level of the network system to talk
 * with the network subsystem.  This is the entry point of integration for the
 * network layer.
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "sr_base_internal.h"

#ifdef _CPUMODE_
#include "sr_cpu_extension_nf2.h"
#endif

#include "sr_common.h"
#include "sr_integration.h"
#include "sr_interface.h"
#include "sr_router.h"
#include "sr_thread.h"
#include "sr_work_queue.h"
#include "sr_dumper.h"
#include "lwtcp/lwip/ip.h"

#include <unistd.h>
void sys_thread_new(void (* thread)(void *arg), void *arg);


/**
 * First method called during router initialization.
 * Reading in hardware information etc.
 */
void sr_integ_init(struct sr_instance* sr) {
    debug_println( "Initializing the router subsystem" );
    
    router_t* subsystem = malloc_or_die( sizeof(router_t) );
    router_init( subsystem );
#ifdef MININET_MODE
    subsystem->name = sr->router_name;      // router name (e.g. r0), needed for
#endif                                      // interface initialisation
    sr_set_subsystem( sr_get_global_instance(0), subsystem );
}

/**
 * Called after all initial hardware information (interfaces) have been
 * received.  Can be used to start subprocesses (such as dynamic-routing
 * protocol) which require interface information during initialization.
 */
void sr_integ_hw_setup( struct sr_instance* sr ) {
    debug_println( "Performing post-hw setup initialization" );
    sr_read_routes_from_file( sr_get_subsystem(sr), sr->rtable);
    if (sr->interface_subsystem->num_interfaces >= 1) {
        sr->interface_subsystem->router_id = sr->interface_subsystem->interface[0].ip;
    }
    
    router_t *router = get_router();
    unsigned i;
    
#ifdef _CPUMODE_
    uint32_t *ip = malloc(sizeof(uint32_t));
    
    for (i = 0; i < router->num_interfaces; i++) {
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP, ntohl(router->interface[i].ip));
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP_MASK, ntohl(make_ip_addr("255.255.255.255")));
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_NEXT_HOP_IP, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_OQ, router->interface[i].hw_id);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_WR_ADDR, i);
        
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_FILTER_IP, ntohl(router->interface[i].ip));
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_FILTER_WR_ADDR, i);
        
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_FILTER_RD_ADDR, i);
        readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_FILTER_IP, ip);
        
        debug_println("ip=%08X, read_ip=%08X", router->interface[i].ip, *ip);
        assert(*ip == ntohl(router->interface[i].ip));
    }
    
    writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_FILTER_IP, ntohl(OSPF_IP));
    writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_FILTER_WR_ADDR, i);
    
    writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_FILTER_RD_ADDR, i);
    readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_FILTER_IP, ip);

    
    debug_println("ip=%08X, read_ip=%08X", OSPF_IP, *ip);
    assert(*ip == htonl(OSPF_IP));

    free(ip);
#endif
    
    link_t link[get_router()->num_interfaces];
    for (i = 0; i < router->num_interfaces; i++) {
        interface_t *intf = &router->interface[i];
        intf->helloint = 5;                                 //Find better place.
        /* Adding neighbor for interface */
        debug_println("Adding new neighbor for intf");
        neighbor_t *neighbor = malloc(sizeof(neighbor_t));
        neighbor->time_last = get_time();
        neighbor->ip = intf->ip;
        neighbor->id = 0;
        neighbor->next_neighbor = NULL;
        intf->neighbor_list_head = neighbor;
        
        link[i].router_id = 0;
        link[i].subnet_no = (intf->ip & intf->subnet_mask);
        link[i].mask = intf->subnet_mask;
        link[i].time_last = get_time();
    }
    router_add_database_entry(get_router(), get_router()->router_id, link, get_router()->num_interfaces, 0, NULL, 0);
    
    update_routing_table();
    sys_thread_new((void *)generate_HELLO_thread, NULL);
}

/**
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 */
void sr_integ_input(struct sr_instance* sr,
                    const uint8_t * packet/* borrowed */,
                    unsigned int len,
#if defined _CPUMODE_ || defined MININET_MODE
                    interface_t* intf )
#else
const char* interface )
#endif
{
    packet_info_t* pi;
    
    /* create a copy of the packet */
    pi = malloc_or_die( sizeof(*pi) ); /* freed by router_pthread_main */
    
    /* include info about the handling router and the packet's length */
    pi->router = sr->interface_subsystem;
    pi->len = len;
    pi->interface = intf;
    
    /* copy the (Ethernet) packet itself */
    pi->packet = malloc_or_die( len ); /* freed by router_pthread_main */
    memcpy( pi->packet, packet, len );
    
#ifdef _THREAD_PER_PACKET_
    pthread_t tid;
    /* handle the packet in a separate thread (it will detach itself) */
    make_thread( router_pthread_main, pi );
#else
    /* put the packet on the work queue */
    wq_enqueue( &pi->router->work_queue, WORK_NEW_PACKET, pi );
#endif
}


struct sr_instance* get_sr() {
    struct sr_instance* sr;
    
    sr = sr_get_global_instance( NULL );
    assert( sr );
    return sr;
}

router_t* get_router() {
    return get_sr()->interface_subsystem;
}


/**
 *
 * @return -1 on error and prints a message to stderr. Otherwise, 0 is returned.
 */
int sr_integ_low_level_output(struct sr_instance* sr /* borrowed */,
                              uint8_t* buf /* borrowed */ ,
                              unsigned int len,
                              interface_t* intf ) {
#ifdef _CPUMODE_
    return sr_cpu_output(buf /*lent*/, len, intf );
#else
# ifdef MININET_MODE
    return sr_mininet_output( buf /* lent*/, len, intf );
# else
#  ifdef _MANUAL_MODE_
    sr_log_packet(sr,buf,len);
    return sr_manual_send_packet( sr, buf /*lent*/, len, intf->name );
#  endif  /* _MANUAL_MODE_ */
# endif   /* MININET_MODE  */
#endif    /* _CPUMODE_     */
}

/** For memory deallocation pruposes on shutdown. */
void sr_integ_destroy(struct sr_instance* sr) {
    debug_println("Cleaning up the router for shutdown");
}

route_t *sr_integ_findsrcroute(uint32_t dest /* nbo */) {
    router_t *router = get_router();
    route_t *route_table = router->route;
    uint32_t match;
    uint32_t best = 0;
    bool best_dynamic = FALSE;
    unsigned i, best_i;
    for (i = 0; i < router->num_routes; i++) {
        match = ~(dest ^ route_table[i].prefix) & route_table[i].subnet_mask;
        //printf("match = %04X, best = %04X, best_dynamic = %d route_table.dynamic = %d\n", match, best, best_dynamic, route_table[i].dynamic );
        if (match == route_table[i].subnet_mask && (route_table[i].dynamic > best_dynamic || match > best)) {
            best = match;
            best_i = i;
            if (match == 0xFFFFFFFF && route_table[i].dynamic == TRUE) {
                return &route_table[i];
            }
        }
    }
    if (best != 0x00000000) {
        return &route_table[best_i];
    }
	return NULL;
}

/**
 * Called by the transport layer for outgoing packets generated by the
 * router.  Expects source address in network byte order.
 *
 * @return 0 on failure to find a route to dest.
 */
uint32_t sr_integ_findsrcip(uint32_t dest /* nbo */) {
    route_t *route = sr_integ_findsrcroute(dest);
    if (route) {
        return route->interface.ip;
    }
    return 0;
}

uint32_t sr_integ_findnextip(uint32_t dest /* nbo */) {
    route_t *route = sr_integ_findsrcroute(dest);
    if (route) {
        if (route->next_hop == 0) {
            return route->prefix | dest;
        } else {
            return route->next_hop;
        }
    }
    return 0;
}

interface_t *sr_integ_findsrcintf(uint32_t dest /* nbo */) {
    route_t *route = sr_integ_findsrcroute(dest);
    if (route) {
        return &route->interface;
    }
    return 0;
}



/**
 * Called by the transport layer for outgoing packets that need IP
 * encapsulation.
 *
 * @return 0 on success or waiting for MAC and then will try to send it,
 *         and 1 on failure.
 */
uint32_t sr_integ_ip_output(uint8_t* payload /* given */,
                            uint8_t  proto,
                            uint32_t src, /* nbo */
                            uint32_t dest, /* nbo */
                            int len) {
    
    payload = add_IPv4_header(payload, proto, src, dest, len);
    
    return send_packet(payload, src, dest, len+20, FALSE, FALSE);
}
