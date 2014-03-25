//
//  routing.c
//  P33
//
//  Created by Charlie Bashford on 12/03/2014.
//  Copyright (c) 2014 Charlie Bashford. All rights reserved.
//

#include <stdio.h>
#include <unistd.h>
#include "routing.h"
#include "sr_router.h"
#include "sr_integration.h"
#include "lwtcp/lwip/ip.h"
#include "ip.h"

void handle_PWOSPF_packet(packet_info_t *pi) {
    if (!get_router()->use_ospf) {
        return;
    }
    
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
    
    char src_str[STRLEN_IP];
    ip_to_string(src_str, src);
    if (type == TYPE_HELLO) {
        debug_println("HELLO packet from %s!", src_str);
        struct hello_hdr *hehdr = (void *)pi->packet+IPV4_HEADER_OFFSET+IPV4_HEADER_LENGTH+PWOSPF_HEADER_LENGTH;
        if (pi->interface->subnet_mask != HEHDR_SUB_MASK(hehdr) || pi->interface->helloint != ntohs(HEHDR_HELLO_INT(hehdr))) {
            debug_println("Subnet mask or helloint mismatch, dropping packet!");
            return;
        }
        bool updated = FALSE;
        if (pi->interface->neighbor_list_head == NULL) {
            debug_println("Adding new neighbor at start");
            neighbor_t *neighbor = malloc_or_die(sizeof(neighbor_t)); //Free'd (in generate_HELLO_thread).
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
                    database_entry_t *database_entry = router_find_database_entry(get_router(), get_router()->router_id);
                    unsigned i;
                    for (i = 0; i < database_entry->num_links; i++) {
                        if (database_entry->link[i].router_id == PWHDR_ROUTER_ID(pwhdr)) {
                            database_entry->link[i].time_last = get_time();
                            break;
                        }
                    }
                    current_neighbor->time_last = get_time();
                    updated = TRUE;
                    break;
                }
                current_neighbor = current_neighbor->next_neighbor;
            } while (current_neighbor != NULL);
            
            if (current_neighbor == NULL) {
                debug_println("Adding new neighbor");
                neighbor_t *neighbor = malloc_or_die(sizeof(neighbor_t)); //Free'd (in generate_HELLO_thread).
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
        debug_println("Link State Update packet from %s!", src_str);
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
                    } else {
                        link->time_last = get_time();
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
            debug_println("PWOSF LSU packet exceeded TTL, not forwarding!");
            return;
            
        }
        unsigned len = pi->len-(IPV4_HEADER_OFFSET+IPV4_HEADER_LENGTH);
        PWHDR_CHKSUM_SET(pwhdr, 0);
        PWHDR_CHKSUM_SET(pwhdr, htons(calc_checksum(pi->packet+IPV4_HEADER_OFFSET+IPV4_HEADER_LENGTH, len)));
        unsigned i;
        router_t *router = get_router();
        byte *payload = malloc_or_die(len*sizeof(byte)); //Free'd (below).
        memcpy(payload, pi->packet+IPV4_HEADER_OFFSET+IPV4_HEADER_LENGTH, len); //Copy PWOSPF packet.
        for (i = 0; i < router->num_interfaces; i++) {
            interface_t *intf = &router->interface[i];
            neighbor_t *neighbor = intf->neighbor_list_head;
            while (neighbor != NULL) {
                if (neighbor->ip != IPH_SRC(iphdr) && neighbor->id != 0) {
                    debug_println("Forwarind on LSU packet!");
                    byte *new_payload = add_IPv4_header(payload, 0, PWOSPF_PROTOCOL, intf->ip, neighbor->ip, len); //Free'd (below).
                    send_packet_intf(intf, new_payload, intf->ip, neighbor->ip, len+20, FALSE, FALSE);
                    free(new_payload);
                }
                neighbor = neighbor->next_neighbor;
            }
        }
        free(payload);
    } else {
        debug_println("Invalid PWOSPF packet type, dropping packet!");
        return;
    }
    
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
                debug_println("isn't 0, and pos=%d, visited=%d, time=%f", pos, ((pos >= 0)? visited[pos] : 0), (get_time() - current_entry->link[i].time_last));
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
    
    
    debug_println("Router ID\tDistance\tFirst Router");
    for (i = 0; i < router->num_database; i++) {
        char router_id_str[STRLEN_IP], first_router_str[STRLEN_IP];
        ip_to_string(router_id_str, router->database[i].router_id);
        
        if (first_router[i] != NULL)
            ip_to_string(first_router_str, *first_router[i]);
        else
            sprintf(first_router_str, "-------");
        debug_println("%s \t%d\t%s", router_id_str, distance[i], first_router_str);
    }
    
    
    
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
                char subnet_no_str[STRLEN_IP];
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
        char subnet_no_str[STRLEN_IP], router_id_str[STRLEN_IP];
        ip_to_string(subnet_no_str, routes[i]->subnet_no);
        if (first_router_for_routes[i] != NULL)
            ip_to_string(router_id_str, *first_router_for_routes[i]);
        else
            sprintf(router_id_str, "-------");
        debug_println("%s \t%s \t%d", subnet_no_str, router_id_str, distance_to_routes[i]);
    }
    
    router_delete_all_route_entries(router, TRUE);
    for (i = 0; i < routes_added; i++) {
        char subnet_no_str[STRLEN_IP];
        ip_to_string(subnet_no_str, routes[i]->subnet_no);
        debug_println("%d subnet_no=%s",i, subnet_no_str);
        if (first_router_for_routes[i]) {
            char router_id_str[STRLEN_IP];
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

void send_HELLO_packet(interface_t *intf) {
    unsigned len = PWOSPF_HEADER_LENGTH+HELLO_HEADER_LENGTH;
    byte *payload = malloc_or_die(len*sizeof(byte)); //Free'd (below).

    struct pwospf_hdr *pwhdr = (void *)payload;
    PWHDR_VER_TYPE_SET(pwhdr, 2, TYPE_HELLO);
    PWHDR_LEN_SET(pwhdr, htons(len));
    PWHDR_ROUTER_ID_SET(pwhdr, get_router()->router_id);
    PWHDR_AREA_ID_SET(pwhdr, get_router()->area_id);
    PWHDR_AU_TYPE_SET(pwhdr, 0);
    PWHDR_AUTH_SET(pwhdr, 0);
    
    struct hello_hdr *hehdr = (void *)payload+PWOSPF_HEADER_LENGTH;
    HEHDR_SUB_MASK_SET(hehdr, intf->subnet_mask);
    HEHDR_HELLO_INT_SET(hehdr, htons(intf->helloint));
    HEHDR_PADDING_SET(hehdr);
    
    PWHDR_CHKSUM_SET(pwhdr, 0);
    PWHDR_CHKSUM_SET(pwhdr, htons(calc_checksum(payload, len)));
    
    if (intf->neighbor_list_head != NULL) {
        uint8_t *new_payload = add_IPv4_header(payload, 0, PWOSPF_PROTOCOL, intf->ip, OSPF_IP, len); //Free'd below.
        send_packet_intf(intf, new_payload, intf->ip, OSPF_IP, len+20, FALSE, TRUE);
        free(new_payload);
    }
    free(payload);
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
    byte *payload = malloc_or_die(len*sizeof(byte));            //Free'd (below).
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
                byte *new_payload = add_IPv4_header(payload, 0, PWOSPF_PROTOCOL, intf->ip, neighbor->ip, len); //Free'd (below).
                send_packet_intf(intf, new_payload, intf->ip, neighbor->ip, len+20, FALSE, FALSE);
                free(new_payload);
            }
            neighbor = neighbor->next_neighbor;
        }
    }
    free(payload);
}

void generate_HELLO_thread() {
    router_t *router = get_router();
    debug_println("Using ospf=%d", router->use_ospf);
    if (!router->use_ospf) {
        return;
    }
    
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
                debug_println("Sending HELLO on interface %d.", i);
                send_HELLO_packet(intf);
                last_sent[i] = get_time();
            }
            
            neighbor_t *neighbor = intf->neighbor_list_head;
            neighbor_t *previous = NULL;
            while (neighbor != NULL) {
                if ((get_time() - neighbor->time_last) > 3*intf->helloint*1000 && neighbor->id != 0) {
                    debug_println("====================================================================================Neighbor timeout, exceeds %ds.", 3*intf->helloint);
                    if (previous) {
                        previous->next_neighbor = neighbor->next_neighbor;
                    } else {
                        intf->neighbor_list_head = neighbor->next_neighbor;
                    }
                    database_entry_t *database_entry = router_find_database_entry(router, router->router_id);
                    if (neighbor->id == 0 || !router_remove_link_from_database_entry(router, database_entry, neighbor->id)) {
                        debug_println("ERROR: removing link failed!");
                        
                    }
                    free(neighbor);
                    neighbor = previous;
                    update_routing_table();
                    send_LSU_packet(seq_no);
                    last_LSU_send = get_time();
                    seq_no++;
                }
                previous = neighbor;
                if (neighbor != NULL) {
                    neighbor = neighbor->next_neighbor;
                } else {
                    neighbor = intf->neighbor_list_head;
                }
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
    
    uint32_t prefix_out;
    uint32_t subnet_mask_out;
    uint32_t next_hop_out;
    uint32_t oq_out;
    
    writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_RD_ADDR, router->num_interfaces+j);
    readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP, &prefix_out);
    readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP_MASK, &subnet_mask_out);
    readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_NEXT_HOP_IP, &next_hop_out);
    readReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_OQ, &oq_out);
    
    assert(prefix_out == ntohl(prefix));
    assert(subnet_mask_out == ntohl(subnet_mask));
    assert(next_hop_out == ntohl(next_hop));
    assert(oq_out == interface_p->hw_oq);
    
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
    debug_println("num_routes=%d", router->num_routes);
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
