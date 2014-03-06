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

/** max number of interfaces the router max have */
#define ROUTER_MAX_INTERFACES 5
#define ROUTER_MAX_ROUTES 100
#define ROUTER_MAX_ARP_CACHE 100
#define ROUTER_MAX_DATABASE 100


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

void sr_read_routes_from_file( router_t* router, const char* filename );

ip_mac_t *router_find_arp_entry( router_t *router, addr_ip_t ip);

bool send_packet(byte *payload, uint32_t src, uint32_t dest, int len, bool is_arp_packet, bool is_hello_packet);

void send_ping(router_t *router, addr_ip_t dest_ip, addr_ip_t src_ip, uint16_t id, uint16_t count);

void send_ARP_request(addr_ip_t ip);

void handle_not_repsponding_to_arp(packet_info_t *pi);

void handle_no_route_to_host(packet_info_t *pi);

uint8_t *add_IPv4_header(uint8_t* payload,
                         uint8_t  proto,
                         uint32_t src, /* nbo */
                         uint32_t dest, /* nbo */
                         int len);

void update_routing_table();

void generate_HELLO_thread();

link_t *database_find_link(database_entry_t *database_entry, uint32_t router_id, uint32_t subnet_no);

database_entry_t *router_find_database_entry( router_t* router, uint32_t router_id);

void router_add_link_to_database_entry( router_t *router, database_entry_t *database_entry, link_t *link_to_add);

bool router_remove_link_from_database_entry( router_t *router, database_entry_t *database_entry, uint32_t router_id);

void router_add_database_entry( router_t* router, uint32_t router_id, link_t link[], unsigned num_links, uint16_t seq_no, byte *packet, unsigned len);

void router_add_route( router_t* router,
                      addr_ip_t prefix,
                      addr_ip_t next_hop,
                      addr_ip_t subnet_mask,
                      const char *intf_name,
                      bool dynamic );

route_t *router_find_route_entry( router_t *router, addr_ip_t dest, addr_ip_t gw, addr_ip_t mask, const char *intf_name);

bool router_delete_route_entry( router_t *router, addr_ip_t dest, addr_ip_t gw, addr_ip_t mask, const char *intf_name);

void router_delete_all_route_entries(router_t *router, bool dynamic);

void router_add_arp_entry( router_t *router, addr_mac_t mac, addr_ip_t ip, bool dynamic);

bool router_delete_arp_entry( router_t *router, addr_ip_t ip);

void router_delete_all_arp_entries(router_t *router, bool dynamic);

uint16_t calc_checksum(byte *header, int len);

#endif /* SR_ROUTER_H */
