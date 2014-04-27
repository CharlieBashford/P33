//
//  policy.c
//  P33
//
//  Created by Charlie Bashford on 20/03/2014.
//  Copyright (c) 2014 Charlie Bashford. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include "policy.h"
#include <string.h>
#include "sr_router.h"
#include "ip.h"
#include "lwtcp/lwip/ip.h"
#include "sr_integration.h"
#include "sha256.h"
#include "routing.h"


void handle_IP_ENCAP_packet(packet_info_t *pi) {
    debug_println("Packet has IP encapsulation!");
    struct ip_hdr *iphdr = (void *)pi->packet+IPV4_HEADER_OFFSET;
    /*unsigned offset = 0;
    if (IPH_PROTO(iphdr) == ESP_PROTOCOL) {
        offset = ESP_HEADER_LENGTH;
    }
    
    struct ip_hdr *seciphdr = (void *)pi->packet+IPV4_HEADER_OFFSET+IPV4_HEADER_LENGTH+offset;*/
    policy_t *policy = router_find_matching_policy_receiving(get_router(), /*IPH_SRC(seciphdr), IPH_DEST(seciphdr),*/ IPH_SRC(iphdr), IPH_DEST(iphdr));
    if (policy != NULL) {
        
        unsigned protocol = IPH_PROTO(iphdr);
        memmove(pi->packet+IPV4_HEADER_OFFSET, pi->packet+IPV4_HEADER_OFFSET+IPV4_HEADER_LENGTH, pi->len-IPV4_HEADER_OFFSET-IPV4_HEADER_LENGTH);
        pi->len -= IPV4_HEADER_LENGTH;
        iphdr = (void *)pi->packet+IPV4_HEADER_OFFSET;

        debug_println("Found matching policy! (recieving)");
        if ((policy->secret == NULL || strlen(policy->secret) == 0) && policy->encrypt_rot == 0) {
            if (policy->secret == NULL || strlen(policy->secret) == 0) {
                debug_println("No secret found.");
            }
            if (policy->encrypt_rot == 0) {
                debug_println("No encryption found.");
            }
            if (protocol != IP_ENCAP_PROTOCOL) {
                debug_println("Protocol on IP header is not IP encap protocol.");
                return;
            }
        } else {
            if (policy->secret != NULL && strlen(policy->secret) != 0) {
                debug_println("A secret found in policy.");
            }
            if (policy->encrypt_rot != 0) {
                debug_println("Encryption found in policy.");
            }
            if (protocol != ESP_PROTOCOL) {
                debug_println("Protocol on IP header is not ESP protocol.");
                return;
            }
            
            
            //struct esp_hdr *esphdr = (void *)pi->packet+IPV4_HEADER_OFFSET+IPV4_HEADER_LENGTH;
            struct esp_tail *esptail = (void *)pi->packet+IPV4_HEADER_OFFSET+ESP_HEADER_LENGTH+(pi->len-(IPV4_HEADER_OFFSET+ESP_HEADER_LENGTH+ESP_TAIL_LENGTH));
            if (policy->secret != NULL && strlen(policy->secret) != 0) {
                uint8_t hash[16];
                calc_sha256(hash, pi->packet, IPV4_HEADER_OFFSET, pi->len, policy->secret);
                
                if (memcmp(esptail->icv, hash, 16) != 0) {
                    debug_println("Failed authentication.");
                    return;
                }
            }
            
            if (policy->encrypt_rot != 0) {
                unsigned i;
                for (i = 0; i < pi->len-IPV4_HEADER_OFFSET-ICV_LENGTH; i++) {
                    *(pi->packet+IPV4_HEADER_OFFSET+ESP_HEADER_LENGTH+i) = (*(pi->packet+IPV4_HEADER_OFFSET+ESP_HEADER_LENGTH+i) + 256 - policy->encrypt_rot) % 256;
                }
            }
            
            memmove(pi->packet+IPV4_HEADER_OFFSET, pi->packet+IPV4_HEADER_OFFSET+ESP_HEADER_LENGTH, pi->len-(IPV4_HEADER_OFFSET+ESP_HEADER_LENGTH+ESP_TAIL_LENGTH));
            pi->len -= ESP_HEADER_LENGTH + ESP_TAIL_LENGTH;
        }
        handle_IPv4_packet(pi);
        free_policy(policy);
    }
}

uint8_t *add_ESP_packet(uint8_t *payload, unsigned offset, uint32_t spi, uint32_t seq_no, uint8_t pad_len, uint8_t next_hdr, char *secret, uint8_t encrypt_rot, int len) {
    debug_println("Adding ESP packet.");
    
    uint8_t *esp_packet = malloc((ESP_PACKET_LENGTH(len)+pad_len)*sizeof(uint8_t)); //Needs to be Free'd outside call.
    struct esp_hdr *esphdr = (void *)esp_packet+offset;
    
    ESP_SPI_SET(esphdr,spi);
    ESP_SEQ_NO_SET(esphdr, seq_no);
    
    struct esp_tail *esptail = (void *)esp_packet+ESP_HEADER_LENGTH+len;
    
    memcpy(esp_packet, payload, offset);
    memcpy(esp_packet+offset+ESP_HEADER_LENGTH, payload+offset, len-offset);
    
    ESP_PAD_LEN_SET(esptail, pad_len);
    ESP_NEXT_HDR_SET(esptail, next_hdr);
    
    if (encrypt_rot != 0) {
        unsigned i;
        for (i = 0; i < len-offset+pad_len+ESP_TAIL_LENGTH-ICV_LENGTH; i++) {
            *(esp_packet+offset+ESP_HEADER_LENGTH+i) = (*(esp_packet+offset+ESP_HEADER_LENGTH+i) + encrypt_rot) % 256;
        }
    }
    
    if (secret != NULL && strlen(secret) != 0) {
        uint8_t hash[ICV_LENGTH];
        calc_sha256(hash, esp_packet, offset, ESP_PACKET_LENGTH(len)+pad_len, secret);
        memcpy(esptail->icv, hash, ICV_LENGTH);
    } else {
        memset(esptail->icv, 0, ICV_LENGTH);
    }

    return esp_packet;
    
}

void calc_sha256(uint8_t answer[16], uint8_t *payload, unsigned offset, unsigned len, char *secret) {
    unsigned char digest[32];
    SHA256_CTX ctx;
    
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, secret, strlen(secret));
    SHA256_Update(&ctx, payload+offset, len-offset-16); //2 for the ICV field.
    SHA256_Final(digest, &ctx);
    
    memcpy(answer, digest, 16);
}

policy_t *copy_policy(policy_t *policy) {
    policy_t *new_policy = malloc_or_die(sizeof(policy_t)); //Needs to be free'd with free_policy().
    *new_policy = *policy;
    if (policy->secret != NULL)
        new_policy->secret = strdup(policy->secret);
    return new_policy;
}

void free_policy(policy_t *policy) {
    if (policy == NULL)
        return;
    if (policy->secret != NULL) {
        free(policy->secret);
    }
    free(policy);
}

policy_t *router_find_matching_policy_sending( router_t* router, addr_ip_t matching_src_ip, addr_ip_t matching_dest_ip) {
    pthread_mutex_lock(&router->policy_lock);

    unsigned i;
    debug_println("num_policies=%d", router->num_policies);
    for (i = 0; i < router->num_policies; i++) {
        policy_t *policy = &router->policy[i];
        if ((policy->src_ip == (matching_src_ip & policy->src_mask)) && (policy->dest_ip == (matching_dest_ip & policy->dest_mask)) && router_lookup_interface_via_ip(router, policy->local_end) != NULL) {
            policy_t *new_policy = copy_policy(policy);
            pthread_mutex_unlock(&router->policy_lock);
            debug_println("returning policy at %d", i);
            return new_policy;
        }
    }
    
    pthread_mutex_unlock(&router->policy_lock);
    
    return NULL;
}

policy_t *router_find_matching_policy_receiving( router_t* router, /*addr_ip_t matching_src_ip, addr_ip_t matching_dest_ip,*/ addr_ip_t matching_local_end, addr_ip_t matching_remote_end) {
    pthread_mutex_lock(&router->policy_lock);
    
    
    unsigned i;
    debug_println("num_policies=%d", router->num_policies);
    for (i = 0; i < router->num_policies; i++) {
        policy_t *policy = &router->policy[i];
        if (/*(policy->src_ip == (matching_src_ip & policy->src_mask)) && (policy->dest_ip == (matching_dest_ip & policy->dest_mask)) &&*/ router_lookup_interface_via_ip(router, policy->remote_end) != NULL) {
            if (policy->local_end == matching_local_end && policy->remote_end == matching_remote_end) {
                policy_t *new_policy = copy_policy(policy);
                pthread_mutex_unlock(&router->policy_lock);
                debug_println("returning policy at %d", i);
                return new_policy;
            }
        }
    }
    
    pthread_mutex_unlock(&router->policy_lock);
    
    return NULL;
}

void router_add_policy( router_t* router, addr_ip_t src_ip, addr_ip_t src_mask, addr_ip_t dest_ip, addr_ip_t dest_mask, addr_ip_t local_end, addr_ip_t remote_end, const char *secret, uint8_t encrypt_rot, uint32_t spi) {
    policy_t* policy;
    
    pthread_mutex_lock(&router->policy_lock);
    
    
    //debug_println("called router_add_policy");    // TODO remove debugging line
    
    
    policy = &router->policy[router->num_policies];
    policy->src_ip = (src_ip & src_mask);
    policy->src_mask = src_mask;
    policy->dest_ip = (dest_ip & dest_mask);
    policy->dest_mask = dest_mask;
    policy->local_end = local_end;
    policy->remote_end = remote_end;
    policy->secret = strdup(secret);
    policy->encrypt_rot = encrypt_rot;
    policy->spi = spi;
    
#ifdef _CPUMODE_
    int i;
    for (i = router->num_routes-1; i >= 0; i--) { //Shift routes in hardware.
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP_MASK, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_NEXT_HOP_IP, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_OQ, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_WR_ADDR, router->num_interfaces+router->num_policies+i);
        
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP, ntohl(router->route[i].prefix));
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP_MASK, ntohl(router->route[i].subnet_mask));
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_NEXT_HOP_IP, ntohl(router->route[i].next_hop));
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_OQ, router->route[i].interface.hw_oq);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_WR_ADDR, router->num_interfaces+router->num_policies+i+1);
    }
    
    writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP, ntohl(dest_ip));
    writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP_MASK, ntohl(dest_mask));
    writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_NEXT_HOP_IP, ntohl(remote_end));
    writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_OQ, router->interface[0].hw_id);
    writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_WR_ADDR, router->num_interfaces + router->num_policies);
#endif
    
    router->num_policies += 1;
    
    pthread_mutex_unlock(&router->policy_lock);
}

policy_t *router_find_policy_entry( router_t *router, addr_ip_t src_ip, addr_ip_t src_mask, addr_ip_t dest_ip, addr_ip_t dest_mask, addr_ip_t local_end, addr_ip_t remote_end) {
    //debug_println("called router_find_policy_entry");    // TODO remove debugging line
    
    pthread_mutex_lock(&router->policy_lock);
    
    unsigned i;
    debug_println("num_policies=%d", router->num_policies);
    for (i = 0; i < router->num_policies; i++) {
        policy_t *policy = &router->policy[i];
        if (policy->src_ip == (src_ip & policy->src_mask) && policy->src_mask == src_mask &&
            policy->dest_ip == (dest_ip & policy->dest_mask) && policy->dest_mask == dest_mask &&
            policy->local_end == local_end && policy->remote_end == remote_end) {
            pthread_mutex_unlock(&router->policy_lock);
            return policy;
        }
    }
    
    pthread_mutex_unlock(&router->policy_lock);
    
    return NULL;
}

bool router_delete_policy_entry( router_t *router, addr_ip_t src_ip, addr_ip_t src_mask, addr_ip_t dest_ip, addr_ip_t dest_mask, addr_ip_t local_end, addr_ip_t remote_end) {
    
    pthread_mutex_lock(&router->policy_lock);
    
    debug_println("called router_delete_policy_entry");    // TODO remove debugging line
    unsigned i;
    for (i = 0; i < router->num_policies; i++) {
        policy_t *policy = &router->policy[i];
        if  (policy->src_ip == (src_ip & policy->src_mask) && policy->src_mask == src_mask &&
             policy->dest_ip == (dest_ip & policy->dest_mask) && policy->dest_mask == dest_mask &&
             policy->local_end == local_end && policy->remote_end == remote_end)  {
            debug_println("exiting at entry %d", i);
            break;
        }
    }
    if (i < router->num_policies) {
        if (router->policy[i].secret != NULL)
            free(router->policy[i].secret);
    }

    unsigned j;
    
#ifdef _CPUMODE_
    
    for (j = i; j < router->num_policies; j++) { //Shift policies down by one
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP_MASK, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_NEXT_HOP_IP, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_OQ, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_WR_ADDR, router->num_interfaces+j+1);
        
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP, ntohl(router->policy[j].dest_ip));
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP_MASK, ntohl(router->policy[j].dest_mask));
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_NEXT_HOP_IP, ntohl(router->policy[j].remote_end));
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_OQ, router->interface[0].hw_id);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_WR_ADDR, router->num_interfaces+j);
    }
    
    for (j = 0; j < router->num_routes; j++) { //Shift routes down by one.
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP_MASK, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_NEXT_HOP_IP, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_OQ, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_WR_ADDR, router->num_interfaces+router->num_policies+j);
        
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP, ntohl(router->route[j].prefix));
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP_MASK, ntohl(router->route[j].subnet_mask));
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_NEXT_HOP_IP, ntohl(router->route[j].next_hop));
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_OQ, router->route[j].interface.hw_oq);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_WR_ADDR, router->num_interfaces+router->num_policies+j-1);
    }
#endif

    for (j = i; j < router->num_policies-1; j++) {
        router->policy[j] = router->policy[j+1];
    }
    
    
    bool succeded = FALSE;
    if (i < router->num_policies) {
        succeded = TRUE;
    }
    router->num_policies -= 1;
    pthread_mutex_unlock(&router->policy_lock);
    
    return succeded;
}

void router_delete_all_policy( router_t *router) {
    
    pthread_mutex_lock(&router->policy_lock);
    
    //debug_println("called router_delete_all_policy");    // TODO remove debugging line
    
    unsigned i;
    for (i = 0; i < router->num_policies; i++) {
        if (router->policy[i].secret != NULL)
            free(router->policy[i].secret);
        
#ifdef _CPUMODE_
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP_MASK, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_NEXT_HOP_IP, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_OQ, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_WR_ADDR, router->num_interfaces+i);
#endif
        
    }

#ifdef _CPUMODE_
    int j;
    for (j = router->num_routes-1; j >= 0; j--) { //Shift routes in hardware.
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP_MASK, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_NEXT_HOP_IP, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_OQ, 0);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_WR_ADDR, router->num_interfaces+router->num_policies+j);
        
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP, ntohl(router->route[j].prefix));
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP_MASK, ntohl(router->route[j].subnet_mask));
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_NEXT_HOP_IP, ntohl(router->route[j].next_hop));
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_OQ, router->route[j].interface.hw_oq);
        writeReg(router->nf.fd, XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_WR_ADDR, router->num_interfaces+j);
    }
#endif
    
    router->num_policies = 0;
    
    pthread_mutex_unlock(&router->policy_lock);
}
