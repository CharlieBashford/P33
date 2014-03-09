/*
 * Filename: sr_interface.h
 * Purpose: Data structure containing information about an interface.
 */

#ifndef SR_INTERFACE_H
#define SR_INTERFACE_H

#include <pthread.h>
#include "sr_common.h"
#define SR_NAMELEN 32

#ifndef XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BASEADDR

#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BASEADDR XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR0_BASEADDR
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_HIGHADDR XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR0_HIGHADDR
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_RESET_CNTRS XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR0_RESET_CNTRS
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_0_LOW XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR0_MAC_0_LOW
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_0_HIGH XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR0_MAC_0_HIGH
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_1_LOW XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR0_MAC_1_LOW
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_1_HIGH XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR0_MAC_1_HIGH
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_2_LOW XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR0_MAC_2_LOW
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_2_HIGH XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR0_MAC_2_HIGH
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_3_LOW XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR0_MAC_3_LOW
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_3_HIGH XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR0_MAC_3_HIGH
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_PKT_DROPPED_WRONG_DST_MAC XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR0_PKT_DROPPED_WRONG_DST_MAC
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_PKT_SENT_CPU_LPM_MISS XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR0_PKT_SENT_CPU_LPM_MISS
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_PKT_SENT_CPU_ARP_MISS XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR0_PKT_SENT_CPU_ARP_MISS
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_PKT_SENT_CPU_NON_IP XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR0_PKT_SENT_CPU_NON_IP
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_PKT_DROPPED_CHECKSUM XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR0_PKT_DROPPED_CHECKSUM
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_PKT_FORWARDED XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR0_PKT_FORWARDED
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR0_SENT_CPU_DEST_IP_HIT XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR0_PKT_SENT_CPU_DEST_IP_HIT
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_PKT_SENT_TO_CPU_BAD_TTL XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR0_PKT_SENT_TO_CPU_BAD_TTL
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_PKT_SENT_CPU_OPTION_VER XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR0_PKT_SENT_CPU_OPTION_VER
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_PKT_SENT_FROM_CPU XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR0_PKT_SENT_FROM_CPU
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR1_LPM_IP
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP_MASK XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR1_LPM_IP_MASK
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_NEXT_HOP_IP XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR1_LPM_NEXT_HOP_IP
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_OQ XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR1_LPM_OQ
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_WR_ADDR XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR1_LPM_WR_ADDR
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_RD_ADDR XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR1_LPM_RD_ADDR
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_IP XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR1_ARP_IP
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_MAC_LOW XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR1_ARP_MAC_LOW
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_MAC_HIGH XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR1_ARP_MAC_HIGH
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_WR_ADDR XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR1_ARP_WR_ADDR
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_RD_ADDR XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR1_ARP_RD_ADDR
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_FILTER_IP XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR1_FILTER_IP
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_FILTER_WR_ADDR XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR1_FILTER_WR_ADDR
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_FILTER_RD_ADDR XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_BAR1_FILTER_RD_ADDR

#endif

/* forward declaration */
struct neighbor_t;
struct router_t;

/** holds info about a router's interface */
typedef struct {
    char name[SR_NAMELEN]; /* name of the interface        */
    addr_mac_t mac;        /* MAC address of the interface */
    addr_ip_t ip;          /* IP address of the interface  */
    bool enabled;          /* whether the interface is on  */
    addr_ip_t subnet_mask; /* subnet mask of the link */
    uint16_t helloint;
    
    
#if defined _CPUMODE_
#   define PREFIX_LENGTH 3   /* length of "rx-" prefix in bytes */
#   define INTF0 0x02
#   define INTF1 0x08
#   define INTF2 0x20
#   define INTF3 0x80
#   define OUT_INTF0 0x01
#   define OUT_INTF1 0x04
#   define OUT_INTF2 0x10
#   define OUT_INTF3 0x40
#endif /* _CPUMODE_ */
#if defined MININET_MODE
#   define PREFIX_LENGTH 3   /* length of "rx-" prefix in bytes */
#   define INTF0 0x00
#   define INTF1 0x01
#   define INTF2 0x02
#   define INTF3 0x03
#endif
#if defined MININET_MODE || defined _CPUMODE_
    byte hw_id;            /* hardware id of the interface */
    int  hw_fd;            /* socket file descriptor to talk to the hw */
    pthread_mutex_t hw_lock; /* lock to prevent issues w/ multiple writers */
#endif /* MININET_MODE || _CPU_MODE_ */
    
    struct neighbor_t* neighbor_list_head; /* neighboring nodes */
} interface_t;


typedef struct neighbor_t {
    uint32_t id;
    addr_ip_t ip;
    double time_last;
    struct neighbor_t *next_neighbor;
} neighbor_t;



/**
 * Reads in a list of interfaces from filename and adds them to the router
 * subsystem in sr.
 *
 * Line Format: name ip mac
 * Example Line: eth0 192.168.0.1 AB:CD:EF:01:23:45
 */
void sr_read_intf_from_file( struct router_t* router, const char* filename );

#define STR_INTF_HDR_MAX_LEN 55
#define STR_INTF_MAX_LEN     (46+SR_NAMELEN)

/**
 * Fills buf with a string header for an interface representation.  It takes up to
 * STR_INTF_HDR_MAX_LEN characters (including the terminating NUL).
 *
 * @param buf  buffer to place the string in
 * @param len  length of the buffer
 *
 * @return number of bytes written to create the header string, or 0 if there
 *         was not enough space in buf to write it
 */
int intf_header_to_string( char* buf, int len );

/**
 * Fills buf with a string representation of an interface.  It takes up to
 * STR_INTF_MAX_LEN characters.
 *
 * @param buf  buffer to place the string in
 * @param len  length of the buffer
 *
 * @return number of bytes written to create the interface string, or 0 if there
 *         was not enough space in buf to write it
 */
int intf_to_string( interface_t* intf, char* buf, int len );

#define STR_MAX_NEIGHBORS     32
#define STR_INTF_NEIGHBOR_MAX_LEN  (82*(STR_MAX_NEIGHBORS+1))
int intf_neighbor_header_to_string( char* buf, int len );

/** intf_to_string along with the neighors */
int intf_neighbor_to_string( interface_t* intf, char* buf, int len );

#ifdef _CPUMODE_
#define STR_INTF_HW_MAX_LEN 1024 /* actual max is 775; this provides some slop */

/**
 * Fills buf with a string representation of a hardware interface.  It takes up
 * to STR_INTF_HW_MAX_LEN characters.
 *
 * @param buf  buffer to place the string in
 * @param len  length of the buffer
 *
 * @return number of bytes written to create the interface string, or 0 if there
 *         was not enough space in buf to write it
 */
int intf_hw_to_string( struct router_t* router,
                      interface_t* intf, char* buf, int len );
#endif /* _CPUMODE_ */

#endif /* SR_INTERFACE_H */
