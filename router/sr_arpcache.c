#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <sys/types.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_protocol.h"



/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Fill this in */
  struct sr_arpcache* cache = &(sr->cache);
  struct sr_arpreq* arpreq = cache->requests;
  while (arpreq != NULL) {
    handle_arpreq(sr, arpreq);
    arpreq = arpreq->next;
  }
}

void handle_arpreq(struct sr_instance* sr, struct sr_arpreq* req) {
  time_t current_time = time(NULL);

  /* If the request is new, initialize its time and send the first arp request. */
  if (req->times_sent == 0) {
    printf("Times sent is ZERO ----------------------\n");
    req->sent = current_time;
    send_arp_request(sr, req);
    req->times_sent++;
  }

  if (difftime(current_time, req->sent) > 1) {
    
    if (req->times_sent >= 5) {
      /* send icmp_host_unreachable to all packets*/
      /* Assume that host and destination Eth addrs are correct. */
      printf("Send ICMP Host Unreachable\n");
      send_icmp_host_unreachable(sr, req);
      sr_arpreq_destroy(&(sr->cache), req);
    } else {
      printf("Sent ARP request\n");
      send_arp_request(sr, req);
      req->sent = current_time;
      req->times_sent++;
    }  
  }
}

void send_icmp_host_unreachable(struct sr_instance* sr, struct sr_arpreq* req) {
  struct sr_packet* packet = req->packets;
  unsigned int icmp_packet_len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t);
  enum icmp_responses response = DESTINATION_HOST_UNREACHABLE;
  while (packet != NULL) {
    uint8_t icmp_packet[icmp_packet_len];
    printf("In send_icmp_host_unreachable. Incoming interface: %s\n", packet->incoming_iface);
    struct sr_if* interface = sr_get_interface(sr, packet->incoming_iface);
    make_icmp_packet(packet->buf, icmp_packet, interface, response);
    sr_send_packet(sr, icmp_packet, icmp_packet_len, packet->incoming_iface);  
    packet = packet->next;
  }
}

void send_arp_request(struct sr_instance* sr, struct sr_arpreq* req) {
  unsigned int len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t);
  uint8_t packet[len];
  sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
  sr_arp_hdr_t* arp_hdr = (uint8_t*)packet+sizeof(sr_ethernet_hdr_t);
  struct sr_if* my_iface = sr_get_interface(sr, req->packets->iface);
  struct sr_rt* rt_match = NULL;
  lpm_found_match(req->ip, sr, &rt_match);
  uint32_t next_hop_ip = rt_match->gw.s_addr;
  printf("Sending ARP request. Interface: %s\n", my_iface->name); 
  /* Fill in Ethernet header. */
  memcpy(eth_hdr->ether_shost, my_iface->addr, ETHER_ADDR_LEN);
  int i = 0;
  for (i; i < ETHER_ADDR_LEN; i++) eth_hdr->ether_dhost[i] = 0xff; /* Broadcast request. */
  enum sr_ethertype ether_type = ethertype_arp;
  eth_hdr->ether_type = htons(ether_type);

  /* Fill in ARP header. */
  enum sr_ethertype arp_pro = ethertype_ip;
  arp_hdr->ar_hrd = htons(0x0001); /* Ethernet */
  arp_hdr->ar_pro = htons(arp_pro); 
  arp_hdr->ar_hln = 0x06; /* Length of Ethernet address: 6 bytes. */
  arp_hdr->ar_pln = 0x04; /* Length of IP address: 4 bytes. */
  arp_hdr->ar_op = htons(0x0001); /* Opcode = 1 (ARP request). */
  memcpy(arp_hdr->ar_sha, my_iface->addr, ETHER_ADDR_LEN);  
  arp_hdr->ar_sip = my_iface->ip; 
  arp_hdr->ar_tip = next_hop_ip;
  /*struct sr_if* send_iface = sr_get_interface(sr, req->packets->incoming_iface);*/
  sr_send_packet(sr, packet, len, my_iface->name);
}
/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface,
				       char *incoming_iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface && incoming_iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
	new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        new_pkt->incoming_iface = (char*)malloc(sr_IFACE_NAMELEN);
	strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
	strncpy(new_pkt->incoming_iface, incoming_iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
	    if (pkt->incoming_iface)
		free(pkt->incoming_iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        pthread_mutex_lock(&(cache->lock));
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);
        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

