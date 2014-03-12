/*
 * Filename: sr_router.h
 * Purpose:
 *   1) Handle each incoming packet
 *      -- Spawn new thread
 *      -- Pass to Ethernet handler
 *   2) Store state of router
 *      -- ARP Cache
 *      -- Interface List
 *      -- Routing Table
 */

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

/* forward declarations */
struct router_t;

#include <netinet/in.h>
#include <pthread.h>
#include <sys/time.h>
#include "common/nf10util.h"
#include "common/nf_util.h"
#include "reg_defines.h"
#include "sr_common.h"
#include "sr_interface.h"
#include "sr_work_queue.h"

#define ARP_ETHERTYPE 0x0806
#define IPV4_ETHERTYPE 0x0800

#define OSPF_IP make_ip_addr("224.0.0.5")

/** holds info about a router's route */
typedef struct {
    addr_ip_t prefix;
    addr_ip_t next_hop;
    addr_ip_t subnet_mask;
    interface_t interface;
    bool dynamic;
} route_t;


typedef struct {
    addr_ip_t ip;
    addr_mac_t mac;
    double time;
    bool dynamic;
} ip_mac_t;

typedef struct link_t {
    uint32_t router_id;
    addr_ip_t subnet_no;
    addr_ip_t mask;
    double time_last;
} link_t;

#define ROUTER_MAX_LINKS 10

typedef struct database_entry_t {
    uint32_t router_id;
    link_t link[ROUTER_MAX_LINKS];
    unsigned num_links;
    pthread_mutex_t links_lock;
    uint16_t seq_no;
    byte *last_packet;
    unsigned len;
} database_entry_t;

typedef struct pending_arp_entry_t {
    addr_ip_t ip;
    addr_ip_t src;
    byte *payload;
    unsigned len;
    double last_sent;
    double num_sent;
} pending_arp_entry_t;

/** max number of interfaces the router max have */
#define ROUTER_MAX_INTERFACES 5
#define ROUTER_MAX_ROUTES 100
#define ROUTER_MAX_ARP_CACHE 100
#define ROUTER_MAX_DATABASE 100
#define ROUTER_MAX_PENDING_ARP 100


/** router data structure */
typedef struct router_t {
    
    interface_t interface[ROUTER_MAX_INTERFACES];
    unsigned num_interfaces;
    pthread_mutex_t intf_lock;
    route_t route[ROUTER_MAX_ROUTES];
    unsigned num_routes;
    pthread_mutex_t route_table_lock;
    ip_mac_t arp_cache[ROUTER_MAX_ARP_CACHE];
    unsigned num_arp_cache;
    pthread_mutex_t arp_cache_lock;
    pending_arp_entry_t pending_arp[ROUTER_MAX_PENDING_ARP];
    unsigned num_pending_arp;
    pthread_mutex_t pending_arp_lock;

    
    uint32_t router_id;
    uint32_t area_id;
    uint16_t lsuint;
    
    database_entry_t database[ROUTER_MAX_DATABASE];
    unsigned num_database;
    pthread_mutex_t database_lock;
    bool added_links;
    
    bool use_ospf;
    
#ifdef _CPUMODE_
    struct nf_device nf;
    int	netfpga_regs;
#endif
    
#ifdef MININET_MODE
    char* name;      // name of router (e.g. r0)
#endif               // needed for iface initialisation
    
#ifndef _THREAD_PER_PACKET_
    work_queue_t work_queue;
    
#   ifndef NUM_WORKER_THREADS
#    define NUM_WORKER_THREADS 2 /* in addition to the main thread, ARP queue
caretaker thread, and ARP cache GC thread */
#   endif
#endif
} router_t;

/** a packet along with the router and the interface it arrived on */
typedef struct packet_info_t {
    router_t* router;
    byte* packet;
    unsigned len;
    interface_t* interface;
} packet_info_t;

/** Initializes the router_t data structure. */
void router_init( router_t* router );

/** Destroys the router_t data structure. */
void router_destroy( router_t* router );

bool send_packet_intf(interface_t *intf, byte *payload, uint32_t src, uint32_t dest, int len, bool is_arp_packet, bool is_hello_packet);

bool send_packet(byte *payload, uint32_t src, uint32_t dest, int len, bool is_arp_packet, bool is_hello_packet);


/**
 * Main entry function for a thread which is to handle the packet_info_t
 * specified by vpacket.  The thread will process the packet and then free the
 * buffers associated with the packet, including vpacket itself, before
 * terminating.
 */
void router_handle_packet( packet_info_t* pi );

#ifdef _THREAD_PER_PACKET_
/** Detaches the thread and then calls router_handle_packet with vpacket. */
void* router_pthread_main( void* vpacket );
#else
/** defines the different types of work which may be put on the work queue */
typedef enum work_type_t {
    WORK_NEW_PACKET,
} work_type_t;

/**
 * Entry point for worker threads doing work on the work queue.  Calls
 * routeR_handle_packet with the work->work field.
 */
void router_handle_work( work_t* work /* borrowed */ );
#endif

/**
 * Determines the interface to use in order to reach ip.
 *
 * @return interface to route from, or NULL if a route does not exist
 */
interface_t* router_lookup_interface_via_ip( router_t* router, addr_ip_t ip );

/**
 * Returns a pointer to the interface described by the specified name.
 *
 * @return interface, or NULL if the name does not match any interface
 */
interface_t* router_lookup_interface_via_name( router_t* router,
                                              const char* name );


/**
 * Adds an interface to the router.  Not thread-safe.  Should only be used
 * during the initialization phase.  The interface will be enabled by default.
 */
void router_add_interface( router_t* router,
                          const char* name,
                          addr_ip_t ip, addr_ip_t mask, addr_mac_t mac );

#endif /* SR_ROUTER_H */
