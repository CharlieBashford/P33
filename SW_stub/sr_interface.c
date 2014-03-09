/* Filename: sr_interface.c */

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include "common/nf10util.h"
#include "reg_defines.h"
#include "sr_common.h"
#include "sr_interface.h"
#include "sr_router.h"

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

void sr_read_intf_from_file( router_t* router, const char* filename ) {
    FILE* fp;
    const char* err;
    char  line[512];
    char  str_name[32];
    char  str_mask[32];
    char  str_ip[32];
    unsigned mac_octet[6];

    struct in_addr ip, mask;
    addr_mac_t mac;

    err = "Error loading interface table,";
    debug_println( "Loading interface table from %s", filename );

    assert(filename);
    fp = fopen(filename,"r");
    if( !fp )
        die( "Could  not access the interface file named %s", filename );

    while( fgets(line,512,fp) != 0) {
        sscanf( line, "%s %s %s %X:%X:%X:%X:%X:%X",
                str_name,
                str_ip,
                str_mask,
                &mac_octet[0], &mac_octet[1], &mac_octet[2],
                &mac_octet[3], &mac_octet[4], &mac_octet[5] );

        if( inet_aton(str_ip,&ip) == 0 )
            die( "%s cannot convert ip (%s) to valid IP", err, str_ip );

        if( inet_aton(str_mask,&mask) == 0 )
            die( "%s cannot convert mask (%s) to valid IP", err, str_mask );

        mac.octet[0] = mac_octet[0];
        mac.octet[1] = mac_octet[1];
        mac.octet[2] = mac_octet[2];
        mac.octet[3] = mac_octet[3];
        mac.octet[4] = mac_octet[4];
        mac.octet[5] = mac_octet[5];

        router_add_interface( router,
                              str_name,
                              ip.s_addr,
                              mask.s_addr,
                              mac );
    }
}

#define STR_INTF_FORMAT "%-9s  %-17s  %-15s  %-6s\n"

int intf_header_to_string( char* buf, int len ) {
    return my_snprintf( buf, len, STR_INTF_FORMAT,
                        "Interface", "MAC", "IP", "Status" );
}

int intf_to_string( interface_t* intf, char* buf, int len ) {
    const char* name;
    char mac[STRLEN_MAC];
    char ip[STRLEN_IP];
    const char* status;

    /* get the string representation of the interface */
    name = intf->name;
    mac_to_string( mac, &intf->mac );
    ip_to_string( ip, intf->ip );
    status = ( intf->enabled ? "Up" : "Down" );

    /* put the str rep into buf */
    return my_snprintf( buf, len, STR_INTF_FORMAT, name, mac, ip, status );
}

/* 82 bytes */
#define STR_NEIGHBOR_FORMAT "  %-15s  %-15s  %-18s  %-24s\n"

int intf_neighbor_header_to_string( char* buf, int len ) {
    return my_snprintf( buf, len, STR_NEIGHBOR_FORMAT,
                        "Neighbor IP", "Neighbor Rtr ID", "Subnet",
                        "Last Hello Time" );
}

int intf_neighbor_to_string( interface_t* intf, char* buf, int len ) {
        return 0;
}

#ifdef _CPUMODE_

int intf_hw_to_string( router_t* router, interface_t* intf, char* buf, int len ) {
    char str_mac[STRLEN_MAC];
    addr_mac_t mac;
    uint16_t val16;
    unsigned i;
    char* b[9];
    uint32_t n[12];
    uint32_t base;
    uint32_t val;

    /* determine the base address for this interface */
    switch( intf->hw_id ) {
    case INTF0:
        readReg( router->netfpga_regs, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_0_HIGH, &val ); val16 = val;
        readReg( router->netfpga_regs, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_0_LOW, &val );
        break;

    case INTF1:
        readReg( router->netfpga_regs, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_1_HIGH, &val ); val16 = val;
        readReg( router->netfpga_regs, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_1_LOW, &val );
        break;

    case INTF2:
        readReg( router->netfpga_regs, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_2_HIGH, &val ); val16 = val;
        readReg( router->netfpga_regs, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_2_LOW, &val );
        break;

    case INTF3:
        readReg( router->netfpga_regs, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_3_HIGH, &val ); val16 = val;
        readReg( router->netfpga_regs, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_3_LOW, &val );
        break;

    default: die( "bad case in intf_hw_to_string: %u", intf->hw_id );
    }
    mac_set_hi( &mac, val16 );
    mac_set_lo( &mac, val );
    mac_to_string( str_mac, &mac );

    /* get the string representation of the interface */
    return my_snprintf( buf, len, "Interface: %s (%s)\n",intf->name, str_mac);
}

#endif /* _CPUMODE_ */
