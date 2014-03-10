/* Filename: cli.c */

#include <signal.h>
#include <stdio.h>               /* snprintf()                        */
#include <stdlib.h>              /* malloc()                          */
#include <string.h>              /* strncpy()                         */
#include <sys/time.h>            /* struct timeval                    */
#include <unistd.h>              /* sleep()                           */
#include "cli.h"
#include "cli_network.h"         /* make_thread()                     */
#include "cli_ping.h"            /* cli_ping_init(), cli_ping_request() */
#include "socket_helper.h"       /* writenstr()                       */
#include "../sr_base_internal.h" /* struct sr_instance                */
#include "../sr_common.h"        /* ...                               */
#include "../sr_router.h"        /* router_*()                        */

/** whether to shutdown the server or not */
static bool router_shutdown;

/** socket file descriptor where responses should be sent */
static int fd;

/** whether the fd is was terminated */
static bool fd_alive;

/** whether the client is in verbose mode */
static bool* pverbose;

/** whether to skip next prompt call */
static bool skip_next_prompt;

#ifdef _STANDALONE_CLI_
struct sr_instance* my_get_sr() {
    static struct sr_instance* sr = NULL;
    if( ! sr ) {
        sr = malloc( sizeof(*sr) );
        true_or_die( sr!=NULL, "malloc falied in my_get_sr" );
        
        router_t* subsystem = malloc( sizeof(router_t) );
        true_or_die( subsystem!=NULL, "Error: malloc failed in sr_integ_init" );
        /* router_init( subsystem ); */
        sr->interface_subsystem = subsystem;
        
        sr->topo_id = 0;
        strncpy( sr->vhost, "cli", SR_NAMELEN );
        strncpy( sr->server, "cli mode (no server)", SR_NAMELEN );
        strncpy( sr->user, "cli mode (no client)", SR_NAMELEN );
        if( gethostname(sr->lhost,  SR_NAMELEN) == -1 )
            strncpy( sr->lhost, "cli mode (unknown localhost)", SR_NAMELEN );
        
        sr_manual_read_intf_from_file( sr, "../config/interfaces" );
        sr->hw_init = 1;
        router_read_rtable_from_file( sr->interface_subsystem,
                                     "../config/rtable.test_arp_icmp" );
    }
    
    return sr;
}
#   define SR my_get_sr()
#else
#   include "../sr_integration.h" /* sr_get() */
#   define SR get_sr()
#endif
#define ROUTER SR->interface_subsystem

/**
 * Wrapper for writenstr.  Tries to send the specified string with the
 * file-scope fd.  If it fails, fd_alive is set to FALSE.  Does nothing if
 * fd_alive is already FALSE.
 */
static void cli_send_str( const char* str ) {
    if( fd_alive )
        if( 0 != writenstr( fd, str ) )
            fd_alive = FALSE;
}

/**
 * Wrapper for writenstrs.  Tries to send the specified string(s) with the
 * file-scope fd.  If it fails, fd_alive is set to FALSE.  Does nothing if
 * fd_alive is already FALSE.
 */
static void cli_send_strs( int num_args, ... ) {
    const char* str;
    int ret;
    va_list args;
    
    if( !fd_alive ) return;
    va_start( args, num_args );
    
    ret = 0;
    while( ret==0 && num_args-- > 0 ) {
        str = va_arg(args, const char*);
        ret = writenstr( fd, str );
    }
    
    va_end( args );
    if( ret != 0 )
        fd_alive = FALSE;
}

void cli_init() {
    router_shutdown = FALSE;
    skip_next_prompt = FALSE;
    cli_ping_init();
}

bool cli_is_time_to_shutdown() {
    return router_shutdown;
}

bool cli_focus_is_alive() {
    return fd_alive;
}

void cli_focus_set( const int sfd, bool* verbose ) {
    fd_alive = TRUE;
    fd = sfd;
    pverbose = verbose;
}

void cli_send_help( cli_help_t help_type ) {
    if( fd_alive )
        if( !cli_send_help_to( fd, help_type ) )
            fd_alive = FALSE;
}

void cli_send_parse_error( int num_args, ... ) {
    const char* str;
    int ret;
    va_list args;
    
    if( fd_alive ) {
        va_start( args, num_args );
        
        ret = 0;
        while( ret==0 && num_args-- > 0 ) {
            str = va_arg(args, const char*);
            ret = writenstr( fd, str );
        }
        
        va_end( args );
        if( ret != 0 )
            fd_alive = FALSE;
    }
}

void cli_send_welcome() {
    cli_send_str( "You are now logged into the router CLI.\n" );
}

void cli_send_prompt() {
    if( !skip_next_prompt )
        cli_send_str( PROMPT );
    
    skip_next_prompt = FALSE;
}

void cli_show_all() {
#ifdef _CPUMODE_
    cli_show_hw();
    cli_send_str( "\n" );
#endif
    cli_show_ip();
#ifndef _CPUMODE_
#ifndef _MANUAL_MODE_
#ifndef MININET_MODE
    cli_send_str( "\n" );
    cli_show_vns();
#endif
#endif
#endif
}

#ifndef _CPUMODE_
void cli_send_no_hw_str() {
    cli_send_str( "HW information is not available when not in CPU mode\n" );
}
#else
void cli_show_hw() {
    cli_send_str( "HW State:\n" );
    cli_show_hw_about();
    cli_show_hw_arp();
    cli_show_hw_intf();
    cli_show_hw_route();
}

void cli_show_hw_about() {
    //char buf[STR_ARP_CACHE_MAX_LEN];
    //router_hw_info_to_string( ROUTER, buf, STR_HW_INFO_MAX_LEN );
    //cli_send_str( buf );
}

addr_mac_t mac_lo_and_hi(uint32_t lo, uint32_t hi) {
    return make_mac_addr(lo & 0xFF, (lo & 0xFF00) >> 8, (lo & 0xFF0000) >> 16, (lo & 0xFF000000) >> 24, hi & 0x00FF, (hi & 0xFF00) >> 8);
}

void cli_show_hw_arp() {
    cli_send_str("ARP Table:\nEntry Num\tIP  \t\tMac\n");
    router_t *router = get_router();
    
    unsigned i;
    for (i = 0; i < 32; i++) {
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_RD_ADDR, i);
        uint32_t ip, low, high;
        readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_IP, &ip);
        readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_MAC_LOW, &low);
        readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_ARP_MAC_HIGH, &high);
        if (ip != 0 || low != 0 || high != 0) {
            char ip_str[STRLEN_IP], mac_str[STRLEN_MAC];
            ip_to_string(ip_str, htonl(ip));
            addr_mac_t mac = mac_lo_and_hi(low, high);
            mac_to_string(mac_str, &mac);
            char buf[100];
            sprintf(buf, "%d \t\t%s  \t%s\n", i, ip_str, mac_str);
            cli_send_str(buf);
        }
    }
}

void cli_show_hw_intf() {
    cli_send_str("Interface Table:\nNum\tMac\n");
    router_t *router = get_router();
    
    char mac_str[STRLEN_MAC];
    char buf[100];
    addr_mac_t mac;
    uint32_t low, high;
    
    readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_0_LOW, &low);
    readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_0_HIGH, &high);
    mac = mac_lo_and_hi(low, high);
    mac_to_string(mac_str, &mac);
    sprintf(buf, "%d  \t%s\n", 0, mac_str);
    cli_send_str(buf);
    
    readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_1_LOW, &low);
    readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_1_HIGH, &high);
    mac = mac_lo_and_hi(low, high);
    mac_to_string(mac_str, &mac);
    sprintf(buf, "%d  \t%s\n", 1, mac_str);
    cli_send_str(buf);
    
    readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_2_LOW, &low);
    readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_2_HIGH, &high);
    mac = mac_lo_and_hi(low, high);
    mac_to_string(mac_str, &mac);
    sprintf(buf, "%d  \t%s\n", 2, mac_str);
    cli_send_str(buf);
    
    readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_3_LOW, &low);
    readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_3_HIGH, &high);
    mac = mac_lo_and_hi(low, high);
    mac_to_string(mac_str, &mac);
    sprintf(buf, "%d  \t%s\n", 3, mac_str);
    cli_send_str(buf);
}

void cli_show_hw_route() {
    cli_send_str("HW routing table:\nIP \t\tGateway \tMask \t\t\tOutput Queue\n");
    router_t *router = get_router();
    
    unsigned j;
    for (j = 0; j < 32; j++) {
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_RD_ADDR, j);
        uint32_t ip, mask, next_hop, oq;

        readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP, &ip);
        readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP_MASK, &mask);
        readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_NEXT_HOP_IP, &next_hop);
        readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_OQ, &oq);

        if (ip != 0 || mask != 0 || next_hop != 0 || oq != 0) {
            char ip_str[STRLEN_IP], mask_str[STRLEN_IP], next_hop_str[STRLEN_IP];

            ip_to_string(ip_str, htonl(ip));
            ip_to_string(next_hop_str, htonl(next_hop));
            ip_to_string(mask_str, htonl(mask));
            
            char buf[200];
            sprintf(buf, "%s \t%s \t%s   \t%02X\n", ip_str, next_hop_str, mask_str, oq);
            cli_send_str(buf);
        }
    }
    
    
}
#endif

void cli_show_ip() {
    cli_send_str( "IP State:\n" );
    cli_show_ip_arp();
    cli_show_ip_intf();
    cli_show_ip_route();
}

void cli_show_ip_arp() {
    cli_send_str("ARP Table:\nIP  \t\tMac\t\tDynamic\t\tTime Since(s)\n");
    router_t *router = get_router();
    
    unsigned i;
    for (i = 0; i < router->num_arp_cache; i++) {
        char ip_str[STRLEN_IP], mac_str[STRLEN_MAC];
        ip_to_string(ip_str, router->arp_cache[i].ip);
        mac_to_string(mac_str, &router->arp_cache[i].mac);
        char buf[100];
        sprintf(buf, "%d \t\t%s  \t%s\t%s\t%s\t%d\n", ip_str, mac_str, router->arp_cache[i].dynamic? "Yes" : "No", (int)(router->arp_cache[i].time - get_time()));
        cli_send_str(buf);
    }
}

void cli_show_ip_intf() {
}

void cli_show_ip_route() {
}

void cli_show_opt() {
    cli_show_opt_verbose();
}

void cli_show_opt_verbose() {
    if( *pverbose )
        cli_send_str( "Verbose: Enabled\n" );
    else
        cli_send_str( "Verbose: Disabled\n" );
}

void cli_show_ospf() {
    cli_send_str( "Neighbor Information:\n" );
    cli_show_ospf_neighbors();
    
    cli_send_str( "Topology:\n" );
    cli_show_ospf_topo();
}

void cli_show_ospf_neighbors() {
    cli_send_str("Interface\tMAC\t\t\tIP\t\tStatus\n");
    router_t *router = get_router();
    
    unsigned i;
    for (i = 0; i < router->num_interfaces; i++) {
        interface_t *intf = &router->interface[i];
        char buf[200];
        char mac_str[STRLEN_MAC], ip_str[STRLEN_IP];
        mac_to_string(mac_str, &intf->mac);
        ip_to_string(ip_str, intf->ip);
        sprintf(buf, "%s\t\t%s  \t%s \t%s\n", intf->name, mac_str, ip_str, (intf->enabled? "Up" : "Down"));
        cli_send_str(buf);
        if (intf->neighbor_list_head != NULL) {
            cli_send_str("  Neighbor IP\tNeighbor Rtr ID\tSubnet\t\t\tLast Hello Time\n");
            
            neighbor_t *neighbor = intf->neighbor_list_head;
            while (neighbor != NULL) {
                char ip_str[STRLEN_IP], router_id_str[STRLEN_IP];
                ip_to_string(ip_str, neighbor->ip);
                ip_to_string(router_id_str, neighbor->id);
                sprintf(buf, "%s\t\t%s  \t \t%f\n", ip_str, router_id_str, neighbor->time_last);
                cli_send_str(buf);
                neighbor = neighbor->next_neighbor;
            }
            
            
        }
    }
}

void cli_show_ospf_topo() {
    router_t *router = get_router();
    database_entry_t *database_entry;
    if (router->num_database > 0)
        cli_send_str("Router ID\tLinks\n");
    unsigned i,j;
    for (i = 0; i < router->num_database; i++) {
        database_entry = &router->database[i];
        char buf[200];
        char router_str[16];
        ip_to_string(router_str, database_entry->router_id);
        sprintf(buf, "%s \t%d\n", router_str, database_entry->num_links);
        cli_send_str(buf);
        cli_send_str(" Router ID\tSubnet\n");
        for (j = 0; j < database_entry->num_links; j++) {
            char id_str[16], subnet_str[16];
            link_t *link = &database_entry->link[j];
            ip_to_string(id_str, link->router_id);
            subnet_to_string(subnet_str, link->subnet_no, link->mask);
            sprintf(buf, " %s \t%s\n", id_str, subnet_str);
            cli_send_str(buf);
        }
    }
}

#ifndef _VNS_MODE_
void cli_send_no_vns_str() {
#ifdef _CPUMODE_
    cli_send_str( "VNS information is not available when in CPU mode\n" );
#else
    cli_send_str( "VNS information is not available when in Manual mode\n" );
#endif
}
#else
void cli_show_vns() {
    cli_send_str( "VNS State:\n  Localhost: " );
    cli_show_vns_lhost();
    cli_send_str( "  Server: " );
    cli_show_vns_server();
    cli_send_str( "  Topology: " );
    cli_show_vns_topo();
    cli_send_str( "  User: " );
    cli_show_vns_user();
    cli_send_str( "  Virtual Host: " );
    cli_show_vns_vhost();
}

void cli_show_vns_lhost() {
    cli_send_strln( SR->lhost );
}

void cli_show_vns_server() {
    cli_send_strln( SR->server );
}

void cli_show_vns_topo() {
    char buf[7];
    snprintf( buf, 7, "%u\n", SR->topo_id );
    cli_send_str( buf );
}

void cli_show_vns_user() {
    cli_send_strln( SR->user );
}

void cli_show_vns_vhost() {
    cli_send_strln( SR->vhost );
}
#endif

void cli_manip_ip_arp_add( gross_arp_t* data ) {
    ip_mac_t *entry = router_find_arp_entry(get_router(), data->ip);
    if (entry == NULL) {
        router_add_arp_entry(get_router(), data->mac, data->ip, FALSE);
    } else
        cli_send_str("ARP entry already exists.");
}

void cli_manip_ip_arp_del( gross_arp_t* data ) {
    if (!router_delete_arp_entry(get_router(), data->ip))
        cli_send_str("ARP entry doesn't exist.");
}

void cli_manip_ip_arp_purge_all() {
    get_router()->num_arp_cache = 0;
}

void cli_manip_ip_arp_purge_dyn() {
    router_delete_all_arp_entries(get_router(), TRUE);
}

void cli_manip_ip_arp_purge_sta() {
    router_delete_all_arp_entries(get_router(), FALSE);
}

void cli_manip_ip_intf_set( gross_intf_t* data ) {
    interface_t* intf;
    intf = router_lookup_interface_via_name( ROUTER, data->intf_name );
    if( intf ) {
        pthread_mutex_lock( &ROUTER->intf_lock );
        intf->ip = data->ip;
        intf->subnet_mask = data->subnet_mask;
        pthread_mutex_unlock( &ROUTER->intf_lock );
    }
    else
        cli_send_strs( 2, data->intf_name, " is not a valid interface\n" );
}

void cli_manip_ip_intf_set_enabled( const char* intf_name, bool enabled ) {
    interface_t *intf = router_lookup_interface_via_name(get_router(), intf_name);
    if (intf) {
        pthread_mutex_lock( &ROUTER->intf_lock );
        intf->enabled = enabled;
        pthread_mutex_unlock( &ROUTER->intf_lock );
    } else
        cli_send_strs( 2, intf_name, " is not a valid interface\n" );}

void cli_manip_ip_intf_down( gross_intf_t* data ) {
    cli_manip_ip_intf_set_enabled( data->intf_name, FALSE );
}

void cli_manip_ip_intf_up( gross_intf_t* data ) {
    cli_manip_ip_intf_set_enabled( data->intf_name, TRUE );
}

void cli_manip_ip_ospf_down() {
}

void cli_manip_ip_ospf_up() {
}

void cli_manip_ip_route_add( gross_route_t* data ) { //Could be wrong!!!
    route_t *route_entry = router_find_route_entry(get_router(), data->dest, data->gw, data->mask, data->intf_name);
    if (route_entry == NULL) {
        router_add_route(get_router(), data->dest, data->gw, data->mask, data->intf_name, FALSE);
    } else
        cli_send_str("Route entry already exists.");
}

void cli_manip_ip_route_del( gross_route_t* data ) {
    if (!router_delete_route_entry(get_router(), data->dest, data->gw, data->mask, data->intf_name))
        cli_send_str("Route entry doesn't exist.");
}

void cli_manip_ip_route_purge_all() {
    get_router()->num_routes = 0; //BAD!
}

void cli_manip_ip_route_purge_dyn() {
    router_delete_all_route_entries(get_router(), TRUE);
    
}

void cli_manip_ip_route_purge_sta() {
    router_delete_all_route_entries(get_router(), FALSE);
    
}

void cli_date() {
    char str_time[STRLEN_TIME];
    struct timeval now;
    
    gettimeofday( &now, NULL );
    time_to_string( str_time, now.tv_sec );
    cli_send_str( str_time );
}

void cli_exit() {
    cli_send_str( "Goodbye!\n" );
    fd_alive = FALSE;
}

bool cli_ping_handle_self( addr_ip_t ip ) {
    unsigned i;
    for( i=0; i<ROUTER->num_interfaces; i++ ) {
        if( ip == ROUTER->interface[i].ip ) {
            if( ROUTER->interface[i].enabled )
                cli_send_str( "Your interface is up.\n" );
            else
                cli_send_str( "Your interface is down.\n" );
            
            return TRUE;
        }
    }
    
    return FALSE;
}


void cli_ping( gross_ip_t* data ) {
    if( cli_ping_handle_self( data->ip ) )
        return;
    
    cli_ping_request( ROUTER, fd, data->ip );
    skip_next_prompt = TRUE;
}

void cli_ping_flood( gross_ip_int_t* data ) {
    int i;
    char str_ip[STRLEN_IP];
    
    if( cli_ping_handle_self( data->ip ) )
        return;
    
    ip_to_string( str_ip, data->ip );
    if( 0 != writenf( fd, "Will ping %s %u times ...\n", str_ip, data->count ) )
        fd_alive = FALSE;
    
    for( i=0; i<data->count; i++ )
        cli_ping_request( ROUTER, fd, data->ip );
    skip_next_prompt = TRUE;
}

void cli_shutdown() {
    cli_send_str( "Shutting down the router ...\n" );
    router_shutdown = TRUE;
    cli_ping_destroy();
    raise( SIGINT ); /* wake up cli_main thread blocked on accept() */
}

void cli_traceroute( gross_ip_t* data ) {
    cli_send_str( "traceroute is not yet operational.\n" );
}

void cli_opt_verbose( gross_option_t* data ) {
    if( data->on ) {
        if( *pverbose )
            cli_send_str( "Verbose mode is already enabled.\n" );
        else {
            *pverbose = TRUE;
            cli_send_str( "Verbose mode is now enabled.\n" );
        }
    }
    else {
        if( *pverbose ) {
            *pverbose = FALSE;
            cli_send_str( "Verbose mode is now disabled.\n" );
        }
        else
            cli_send_str( "Verbose mode is already disabled.\n" );
    }
}
