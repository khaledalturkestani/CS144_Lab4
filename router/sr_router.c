/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#define IP_PROTOCOL_ICMP	0x01
#define IP_PROTOCOL_TCP		0x06
#define IP_PROTOCOL_UDP		0x11
#define TTL			0x40
#define BYTES_PER_WORD		4
#define MIN_PACKET_LEN		14 	/* Size of Ethernet header. */

bool checksum_matches(sr_ip_hdr_t *hdr);
bool packet_length_is_valid(uint8_t* packet, enum sr_ethertype ether_type, unsigned int len);
bool packet_is_for_me(uint32_t ip_dst, struct sr_instance *sr, struct sr_if** match);
bool lpm_found_match(uint32_t hdr_ip_addr, struct sr_instance *sr, struct sr_rt** match);
bool external_mapping_exists(struct sr_instance* sr, uint8_t* packet, struct sr_nat_mapping** match);
bool internal_mapping_exists(struct sr_instance* sr, uint8_t* packet, struct sr_nat_mapping** match);
void make_icmp_packet(uint8_t * rcvd_packet, uint8_t * packet, struct sr_if* iface, enum icmp_responses response);
void send_arp_reply(struct sr_instance* sr, uint8_t* packet, struct sr_if* if_match, char* interface);
void handle_nat_ip_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
void handle_ip_pkt_for_router(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface, struct sr_if* if_match);
void forward_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface);
uint16_t tcp_cksum(sr_tcp_hdr_t* tcp_hdr, sr_ip_hdr_t* ip_hdr);
uint16_t icmp_cksum(sr_icmp_hdr_t* icmp_hdr, sr_ip_hdr_t* ip_hdr);

/* Globals: */
uint16_t global_ip_id = 0x0000;
char* internal_iface = "eth1";

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */
    if (sr->in_nat_mode) {
      sr_nat_init(&(sr->nat));
      sr->nat.icmp_timeout = sr->icmp_timeout;
      sr->nat.tcp_idle_timeout = sr->tcp_idle_timeout;
      sr->nat.tcp_transit_timeout = sr->tcp_transit_timeout;
    }
} /* -- sr_init -- */


/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/
void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  print_hdrs(packet, len);

  sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)packet;
  enum sr_ethertype ether_type = ntohs(ethernet_hdr->ether_type); 

  if (!packet_length_is_valid(packet, ether_type, len)) {
    return;
  }

  /* Handling ARP packets. */
  if (ether_type == ethertype_arp) { /* Packet is ARP. */
    handle_arp_packet(sr, packet, len, interface);
    return;   	
  } 

  /* Handling IP packets. */
  if (ether_type == ethertype_ip) { /* Packet is IP. */
    unsigned int eth_hdr_len = sizeof(sr_ethernet_hdr_t);
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet+eth_hdr_len);
 
    /* If IP header's checksum doesn't match --> Drop packet. */
    if (!checksum_matches(ip_hdr)) {
      return;
    }

    /* If we're in NAT mode, handle IP packets through the function handle_nat_packet(). */ 
    if (sr->in_nat_mode) {
      handle_nat_ip_packet(sr, packet, len, interface);
      return;
    }

    /* We're not in NAT mode --> Handle IP packet normally (i.e. like in lab1). */
    struct sr_if* iface = sr_get_interface(sr, interface);
    unsigned int icmp_packet_len;
    enum icmp_responses response;
    struct sr_if* if_match = NULL; /* A match in the routing table will be assigned to this. */
    if (packet_is_for_me(ip_hdr->ip_dst, sr, &if_match)) { /* Packet is IP and for me. */
      handle_ip_pkt_for_router(sr, packet, len, interface, if_match);
      return;
    } else { /* Packet is IP but not for me --> forward packet. */
      forward_packet(sr, packet, len, interface);  
    }
  }     
} /* end of sr_handlepacket() */

void
forward_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface)
{
  struct sr_if* iface = sr_get_interface(sr, interface);
  unsigned int icmp_packet_len;
  enum icmp_responses response;
  sr_ip_hdr_t* ip_hdr = packet + sizeof(sr_ethernet_hdr_t);
  if (ip_hdr->ip_ttl == 0x01) { /* TTL expired --> drop packet & send ICMP net unreachable. */ 
    icmp_packet_len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t);
    uint8_t icmp_packet[icmp_packet_len];
    response = TIME_EXCEEDED;
    make_icmp_packet(packet, icmp_packet, iface, response);
    sr_send_packet(sr, icmp_packet, icmp_packet_len, interface);  
    return;
  } else { /* Forward to next hop. */
    /* Recompute IP header checksum. */
    ip_hdr->ip_ttl--;
    ip_hdr->ip_sum = 0x0000;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    struct sr_rt* rt_match = NULL;
    if (lpm_found_match(ip_hdr->ip_dst, sr, &rt_match)) { /* Found a match in the routing table to forward packet. */
      struct sr_arpentry* cache_entry = sr_arpcache_lookup(&(sr->cache), rt_match->gw.s_addr);
      if (cache_entry != NULL) { /* Found a match in the ARP cache to forward packet. */
        sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
        struct sr_if* if_match = sr_get_interface(sr, rt_match->interface);
        memcpy(eth_hdr->ether_dhost, cache_entry->mac, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost, if_match->addr, ETHER_ADDR_LEN);
        sr_send_packet(sr, packet, len, rt_match->interface);
        free(cache_entry);
      } else { /* No match in ARP cache --> queue packet. */
        sr_arpcache_queuereq(&(sr->cache), rt_match->gw.s_addr, packet, len, rt_match->interface, interface);
      }
    } else { /* No match in routing table --> send ICMP net unreachable. */
      icmp_packet_len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t);
      uint8_t icmp_packet[icmp_packet_len];
      response = DESTINATION_NET_UNREACHABLE;
      make_icmp_packet(packet, icmp_packet, iface, response);
      sr_send_packet(sr, icmp_packet, icmp_packet_len, interface);
    }
  }
}

void
handle_arp_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface)
{
  sr_arp_hdr_t* arp_hdr = (uint8_t*)packet+sizeof(sr_ethernet_hdr_t);	
  enum sr_arp_opcode opcode = arp_hdr->ar_op;
  struct sr_if* if_match = NULL;
  /* Packet is for me & is an ARP request --> reply. */
  if (ntohs(opcode) == arp_op_request && packet_is_for_me(arp_hdr->ar_tip, sr, &if_match)) {
    send_arp_reply(sr, packet, if_match, interface);
  } else if (ntohs(opcode) == arp_op_reply && packet_is_for_me(arp_hdr->ar_tip, sr, &if_match)) {
    /* Packet is for me & is an ARP reply --> cache it & send outstanding packets, if any. */	
    struct sr_arpreq* arpreq = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
    if (arpreq != NULL) { /* Send packets waiting on this ARP reply. */
      send_outstanding_packets(sr, arpreq->packets, arp_hdr->ar_sha);
      sr_arpreq_destroy(&(sr->cache), arpreq);
    } else { /* No pending requests for this ARP reply --> return. */
      return;
    }
  } else { /* ARP packet but not a request or a reply --> drop it. */
    return;
  } 
}

/* Handles the router's response when an IP packet's final destination is the router (or NAT). */
void
handle_ip_pkt_for_router(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface, struct sr_if* if_match) 
{
  struct sr_if* iface = sr_get_interface(sr, interface); /* Incoming interface. */
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
  unsigned int icmp_packet_len;
  enum icmp_responses response;

  if (ip_hdr->ip_p == IP_PROTOCOL_ICMP) { 
    /* Packet is ICMP. */   
    sr_icmp_hdr_t* icmp_hdr = (uint8_t*)ip_hdr+sizeof(sr_ip_hdr_t);
    if (icmp_hdr->icmp_type != 0x08) { /* ICMP is not an echo request -> drop packet. */
      return;
    }
    icmp_packet_len = ntohs(ip_hdr->ip_len)+(sizeof(sr_ethernet_hdr_t));
    uint8_t icmp_packet[icmp_packet_len];
    response = ECHO_REPLY;
    make_icmp_packet(packet, icmp_packet, iface, response);
    sr_send_packet(sr, icmp_packet, icmp_packet_len, interface);
  } else if (ip_hdr->ip_p == IP_PROTOCOL_TCP || ip_hdr->ip_p == IP_PROTOCOL_UDP) {
    /* TCP/UDP packet --> send ICMP port unreachable. */
    icmp_packet_len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t);
    uint8_t icmp_packet[icmp_packet_len];
    response = PORT_UNREACHABLE;
    make_icmp_packet(packet, icmp_packet, iface, response);
    sr_send_packet(sr, icmp_packet, icmp_packet_len, interface);  
  } else { /* Packet is for me but not an echo request or a UDP/TCP packet --> drop packet. */
    return;
  }
}

/* Returns true if an external (IP, port) or (IP, icmp id) pair have a mapping to an internal address. 
   Saves a pointer to the corresponding sr_nat_mapping struct in "match". MUST FREE match. */
bool
external_mapping_exists(struct sr_instance* sr, uint8_t* packet, struct sr_nat_mapping** match) {
  
  /* First figure out the type of mapping. */ 
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
  uint32_t pkt_ip = ntohl(ip_hdr->ip_dst);
  uint32_t pkt_aux;
  sr_nat_mapping_type mapping_type;
  
  if (ip_hdr->ip_p == IP_PROTOCOL_ICMP){
    sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)((uint8_t*)ip_hdr + sizeof(sr_ip_hdr_t));
    /* If ICMP is not echo or reply --> return false. */
    if (icmp_hdr->icmp_type != 0x08 && icmp_hdr->icmp_type != 0x00)
      return false;
    pkt_aux = ntohs((uint8_t*)icmp_hdr + sizeof(sr_icmp_hdr_t));
    mapping_type = nat_mapping_icmp;
  } else if (ip_hdr->ip_p == IP_PROTOCOL_TCP) {
    sr_tcp_hdr_t* tcp_hdr = (sr_tcp_hdr_t*)((uint8_t*)ip_hdr + sizeof(sr_ip_hdr_t));
    pkt_aux = ntohs(tcp_hdr->tcp_dst_port);
    mapping_type = nat_mapping_tcp; 
  } else {
    return false;
  }

  *match = sr_nat_lookup_external(&(sr->nat), pkt_aux, mapping_type);

  if (*match == NULL) {
    return false;
  }  
  return true;
}

/* Returns true if an internal (IP, port) or (IP, icmp id) pair have a mapping to an external address. 
   Saves a pointer to the corresponding sr_nat_mapping struct in "match". MUST FREE match*/
bool
internal_mapping_exists(struct sr_instance* sr, uint8_t* packet, struct sr_nat_mapping** match) {
  
  /* First figure out the type of mapping. */ 
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
  uint32_t pkt_ip = ntohl(ip_hdr->ip_src);
  uint32_t pkt_aux;
  sr_nat_mapping_type mapping_type;
  
  if (ip_hdr->ip_p == IP_PROTOCOL_ICMP){
    sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)((uint8_t*)ip_hdr + sizeof(sr_ip_hdr_t));
    /* If ICMP is not echo or reply --> return false. */
    if (icmp_hdr->icmp_type != 0x08 && icmp_hdr->icmp_type != 0x00)
      return false;
    pkt_aux = ntohs((uint8_t*)icmp_hdr + sizeof(sr_icmp_hdr_t));
    mapping_type = nat_mapping_icmp;
  } else if (ip_hdr->ip_p == IP_PROTOCOL_TCP) {
    sr_tcp_hdr_t* tcp_hdr = (sr_tcp_hdr_t*)((uint8_t*)ip_hdr + sizeof(sr_ip_hdr_t));
    pkt_aux = ntohs(tcp_hdr->tcp_src_port);
    mapping_type = nat_mapping_tcp; 
  } else {
    return false;
  }

  *match = sr_nat_lookup_internal(&(sr->nat), pkt_ip, pkt_aux, mapping_type);

  if (*match == NULL) {
    return false;
  }  
  return true;
}

void 
handle_nat_ip_packet (struct sr_instance* sr,
        	      uint8_t * packet/* lent */,
        	      unsigned int len,
        	      char* interface/* lent */)
{
  /* Note that we've already established that the packet is an IP packet and that it passed 
     the length & checksum checks. */
  
  unsigned int eth_hdr_len = sizeof(sr_ethernet_hdr_t);
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet+eth_hdr_len);
  
  /* Case: packet's destination IP is one of the router's. */ 
  struct sr_if* incoming_iface = NULL; 
  if (packet_is_for_me(ip_hdr->ip_dst, sr, &incoming_iface)) {

    /* Case: no mapping for the (ip_dst, port) pair --> packet is addressed to the NAT. */
    struct sr_nat_mapping* mapping_match = NULL;
    if (!external_mapping_exists(sr, packet, &mapping_match)) {
      handle_ip_pkt_for_router(sr, packet, len, interface, incoming_iface);
      return;
    }

    /* Case: found a mapping for the (ip_dst, port) pair: */
    /* Drop packet if it's not ICMP of TCP. */
    if (ip_hdr->ip_p != IP_PROTOCOL_ICMP && ip_hdr->ip_p != IP_PROTOCOL_TCP) {
      return;
    }
 
    /* Rewrite packet. */
    ip_hdr->ip_dst = htonl(mapping_match->ip_int);
    ip_hdr->ip_sum = 0x0000;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    if (mapping_match->type == nat_mapping_tcp) {
      sr_tcp_hdr_t* tcp_hdr = (sr_tcp_hdr_t*) ((uint8_t*)ip_hdr + sizeof(sr_ip_hdr_t));
      tcp_hdr->tcp_dst_port = htons(mapping_match->aux_int);

      /* Unsolicited SYN packet --> drop. */
      if ( (tcp_hdr->tcp_flags & TCP_SYN) && !(tcp_hdr->tcp_flags & TCP_ACK) ) {
	// TODO: Save it for 6 seconds.
	free(mapping_match);
	return;
      }
      tcp_hdr->tcp_cksum = tcp_cksum(tcp_hdr, ip_hdr);
    } else if (mapping_match->type == nat_mapping_icmp) {
      sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*) ((uint8_t*)ip_hdr + sizeof(sr_ip_hdr_t));
      uint8_t* new_aux_ptr =  (uint8_t*)icmp_hdr+sizeof(sr_icmp_hdr_t);
      *(uint16_t*)new_aux_ptr = htons(mapping_match->aux_int);
      icmp_hdr->icmp_sum = icmp_cksum(icmp_hdr, ip_hdr);
    }

    /* Forward packet, or queue it if no ARP entry is returned. */
    struct sr_if* if_match; 
    struct sr_arpentry* cache_entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);
    if (cache_entry != NULL) { /* Found a match in the ARP cache to forward packet. */
      sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
      struct sr_if* if_match = sr_get_interface(sr, internal_iface);
      memcpy(eth_hdr->ether_dhost, cache_entry->mac, ETHER_ADDR_LEN);
      memcpy(eth_hdr->ether_shost, if_match->addr, ETHER_ADDR_LEN);
      sr_send_packet(sr, packet, len, internal_iface);
      free(cache_entry);
    } else { /* No match in ARP cache --> queue packet. */
      sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_dst, packet, len, internal_iface, interface);
    }
    free(mapping_match);
    return;
  } /* End of case when the packet's destination IP is one of the router's IP's. */

  /* Case: packet's destination IP is not one of the router's IP's. */
  struct sr_rt* rt_match = NULL;  

  /* Case: no matching entry in our routing table --> send ICMP NET UNREACHABLE */
  if (!lpm_found_match(ip_hdr->ip_dst, sr, &rt_match)) {
    struct sr_if* iface = sr_get_interface(sr, interface);
    enum icmp_responses response;
    unsigned int icmp_packet_len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t);
    uint8_t icmp_packet[icmp_packet_len];
    response = DESTINATION_NET_UNREACHABLE;
    make_icmp_packet(packet, icmp_packet, iface, response);
    sr_send_packet(sr, icmp_packet, icmp_packet_len, interface);
    return;
  }

  /* Case: found a match in our routing table. */
  /* Now check that the packet came from an internal source. */
  if (strcmp(interface, internal_iface) == 0) {
   
    /* Just to be safe, don't forward (i.e. drop)the packet if the outgoing interface is also the internal
       interface. Shouldn't happen though. */
    if (strcmp(rt_match->interface, internal_iface) == 0) {
      return;
    }
    /* Now we know that the packet is originating from an internal source and destined for an external
       destination. */
    struct sr_nat_mapping* i_mapping_match = NULL;
    sr_tcp_hdr_t* tcp_hdr = (sr_tcp_hdr_t*) ((uint8_t*)ip_hdr + sizeof(sr_ip_hdr_t));
    sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*) ((uint8_t*)ip_hdr + sizeof(sr_ip_hdr_t));
    if (!internal_mapping_exists(sr, packet, &i_mapping_match)) { /* No mapping --> create one. */
      sr_nat_mapping_type type;
      uint16_t aux_int;
      if (ip_hdr->ip_p == IP_PROTOCOL_ICMP) {
 	type = nat_mapping_icmp;
	aux_int = ntohs(tcp_hdr->tcp_src_port);
      } else if (ip_hdr->ip_p == IP_PROTOCOL_TCP) {
	type = nat_mapping_tcp;
	aux_int = ntohs(*(uint16_t*)((uint8_t*)icmp_hdr+sizeof(sr_icmp_hdr_t)));
      }
      i_mapping_match = sr_nat_insert_mapping(&(sr->nat), ntohl(ip_hdr->ip_src), aux_int, type); 
    }
    /* Rewrite headers: */
    struct sr_if* ext_iface = sr_get_interface(sr, "eth2"); /* Always use eth2's IP regardless of actual outgoing iface. */
    ip_hdr->ip_src = htonl(ext_iface->ip);
    ip_hdr->ip_sum = 0x0000;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    if (i_mapping_match->type == nat_mapping_tcp) {
      tcp_hdr->tcp_src_port = htons(i_mapping_match->aux_ext);
      tcp_hdr->tcp_cksum = tcp_cksum(tcp_hdr, ip_hdr);
    } else if (i_mapping_match->type == nat_mapping_icmp) {
      uint8_t* new_aux_ptr =  (uint8_t*)icmp_hdr+sizeof(sr_icmp_hdr_t);
      *(uint16_t*)new_aux_ptr = htons(i_mapping_match->aux_ext);
      icmp_hdr->icmp_sum = icmp_cksum(icmp_hdr, ip_hdr);
    }
    /* Forward packet, or queue it if no ARP entry is returned. */
    struct sr_arpentry* cache_entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);
    struct sr_if* if_match = sr_get_interface(sr, rt_match->interface);;
    if (cache_entry != NULL) { /* Found a match in the ARP cache to forward packet. */
      sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
      memcpy(eth_hdr->ether_dhost, cache_entry->mac, ETHER_ADDR_LEN);
      memcpy(eth_hdr->ether_shost, if_match->addr, ETHER_ADDR_LEN);
      sr_send_packet(sr, packet, len, if_match->name);
      free(cache_entry);
    } else { /* No match in ARP cache --> queue packet. */
      sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_dst, packet, len, if_match->name, interface);
    }
    free(i_mapping_match);
    return;
  } /* End of case when incoming interface is the internal interface. */
  
  /* Case: Incoming iface is NOT "eth1" (note that it's also the case that dst IP is not the router's). */
    // If outgoing iface is "eth1" --> drop
    // Else --> forward like router.
  forward_packet(sr, packet, len, interface);
} /* end of handle_nat_ip_packet(). */ 

/* Zeros the tcp header's checksum field and computes the checksum and returns it. */ 
uint16_t
tcp_cksum(sr_tcp_hdr_t* tcp_hdr, sr_ip_hdr_t* ip_hdr) {
  tcp_hdr->tcp_cksum = 0x0000;
  struct tcp_pseudo_hdr pseudo_hdr;
  pseudo_hdr.ip_src = ip_hdr->ip_src;
  pseudo_hdr.ip_dst = ip_hdr->ip_dst;
  pseudo_hdr.zero = 0x00;
  pseudo_hdr.ptcl = 0x06;
  pseudo_hdr.len = htons(ntohs(ip_hdr->ip_len)-sizeof(sr_ip_hdr_t));
  void* concat_hdrs = malloc(ntohs(pseudo_hdr.len) + sizeof(struct tcp_pseudo_hdr));
  memcpy(concat_hdrs, &pseudo_hdr, sizeof(struct tcp_pseudo_hdr));
  memcpy((uint8_t*)concat_hdrs+sizeof(struct tcp_pseudo_hdr), tcp_hdr, ntohs(pseudo_hdr.len));
  uint16_t checksum = cksum(concat_hdrs, ntohs(pseudo_hdr.len)+sizeof(struct tcp_pseudo_hdr));
  free(concat_hdrs);
  return checksum;
}

/* Zerso the ICMP header's checksum field and computes the checksum and returns it. */
uint16_t
icmp_cksum(sr_icmp_hdr_t* icmp_hdr, sr_ip_hdr_t* ip_hdr) {
  icmp_hdr->icmp_sum = 0x0000;
  uint16_t icmp_total_length = ntohs(ip_hdr->ip_len)-sizeof(sr_ip_hdr_t);
  uint16_t checksum = cksum(icmp_hdr, icmp_total_length);
  return checksum;
}

/* Returns true if the length of the packet is valid. Returns false if it's not 
   an IP or ARP packet. */
bool packet_length_is_valid(uint8_t* packet, enum sr_ethertype ether_type, unsigned int len) {
  if (ether_type == ethertype_arp) 
    return (len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  if (ether_type == ethertype_ip ) {
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
    return (len > ntohs(ip_hdr->ip_len));
  }
  return false;
}

/* Sends packets that are waiting on an ARP reply once the reply arrives. */
void send_outstanding_packets(struct sr_instance* sr, struct sr_packet* packets, char* mac) {
  while (packets != NULL) {
    sr_ethernet_hdr_t* packet = (sr_ethernet_hdr_t*)(packets->buf);
    struct sr_if* if_match = sr_get_interface(sr, packets->iface);
    memcpy(packet->ether_dhost, mac, ETHER_ADDR_LEN);
    memcpy(packet->ether_shost, if_match->addr, ETHER_ADDR_LEN);
    sr_send_packet(sr, packets->buf, packets->len, packets->iface);
    packets = packets->next;
  }
}

void send_arp_reply(struct sr_instance* sr, uint8_t* packet, struct sr_if* if_match, char* interface) {
  enum sr_arp_opcode reply_opcode = arp_op_reply;
  struct sr_if* incoming_iface = sr_get_interface(sr, interface);
  sr_arp_hdr_t* arp_req_hdr = packet+sizeof(sr_ethernet_hdr_t);
  unsigned int res_packet_len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t);
  uint8_t res_packet[res_packet_len];

  /* Fill in Ethernet header. */
  sr_ethernet_hdr_t* incoming_eth_hdr = (sr_ethernet_hdr_t*)packet;
  sr_ethernet_hdr_t* res_eth_hdr = (sr_ethernet_hdr_t*)res_packet;
  sr_arp_hdr_t* arp_res_hdr = res_packet+sizeof(sr_ethernet_hdr_t);
  memcpy(res_eth_hdr->ether_shost, incoming_iface->addr, ETHER_ADDR_LEN);
  memcpy(res_eth_hdr->ether_dhost, incoming_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  res_eth_hdr->ether_type = incoming_eth_hdr->ether_type;
  
  /* Fill in ARP header. */ 
  arp_res_hdr->ar_hrd = arp_req_hdr->ar_hrd;
  arp_res_hdr->ar_pro = arp_req_hdr->ar_pro;
  arp_res_hdr->ar_hln = arp_req_hdr->ar_hln;
  arp_res_hdr->ar_pln = arp_req_hdr->ar_pln;
  arp_res_hdr->ar_op = htons(reply_opcode);
  memcpy(arp_res_hdr->ar_sha, if_match->addr, ETHER_ADDR_LEN);
  arp_res_hdr->ar_sip = arp_req_hdr->ar_tip;
  memcpy(arp_res_hdr->ar_tha, arp_req_hdr->ar_sha, ETHER_ADDR_LEN);
  arp_res_hdr->ar_tip = arp_req_hdr->ar_sip;
  sr_send_packet(sr, res_packet, res_packet_len, interface);
}

/* Returns true in the checksum matches.
   Copies back the checksum value to the header. */
bool checksum_matches(sr_ip_hdr_t *hdr) {
  uint16_t received_checksum = hdr->ip_sum;
  hdr->ip_sum = 0x0000;
  uint16_t computed_checksum = cksum(hdr, sizeof(sr_ip_hdr_t));
  hdr->ip_sum = received_checksum;
  return (received_checksum == computed_checksum);
}

/* Constructs an ICMP packet (including Ethernet and IP headers) and saves it in "packet". */
void make_icmp_packet(uint8_t * rcvd_packet, uint8_t * packet, struct sr_if* iface, enum icmp_responses response) {
  uint8_t type;
  uint8_t code;
  uint16_t icmp_total_len;
  uint16_t ip_total_len;
  sr_ethernet_hdr_t* rcvd_eth_hdr = (sr_ethernet_hdr_t*)rcvd_packet;
  sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
  sr_ip_hdr_t* rcvd_ip_hdr = (sr_ip_hdr_t*)(rcvd_packet+sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t* rcvd_icmp_hdr = (sr_icmp_hdr_t*)((uint8_t*)rcvd_ip_hdr+sizeof(sr_ip_hdr_t));
  sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)((uint8_t*)ip_hdr+sizeof(sr_ip_hdr_t));;
  if (response == ECHO_REPLY) {
    type = 0x00;
    code = 0x00;
    icmp_total_len = ntohs(rcvd_ip_hdr->ip_len)-sizeof(sr_ip_hdr_t);
    ip_total_len = rcvd_ip_hdr->ip_len;
    icmp_hdr = (sr_icmp_hdr_t*)((uint8_t*)ip_hdr+sizeof(sr_ip_hdr_t));
  } else if (response == PORT_UNREACHABLE) {
    type = 0x03;
    code = 0x03;
    icmp_total_len = sizeof(sr_icmp_t3_hdr_t);
    ip_total_len = htons(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
    icmp_hdr = (uint8_t*)ip_hdr+sizeof(sr_ip_hdr_t);
  } else if (response == TIME_EXCEEDED) {
    printf("TIME EXCEEDED\n");
    type = 0x0B;
    code = 0x00;
    icmp_total_len = sizeof(sr_icmp_t3_hdr_t);
    ip_total_len = htons(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
    icmp_hdr = (uint8_t*)ip_hdr+sizeof(sr_ip_hdr_t);
  } else if (response == DESTINATION_HOST_UNREACHABLE) {
    printf("DESTINATION HOST UNREACHABLE\n");
    type = 0x03;
    code = 0x01;
    icmp_total_len = sizeof(sr_icmp_t3_hdr_t);
    ip_total_len = htons(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t)); 
  } else if (response == DESTINATION_NET_UNREACHABLE) {
    printf("DESTINATION NET UNREACHABLE\n");
    type = 0x03;
    code = 0x00;
    icmp_total_len = sizeof(sr_icmp_t3_hdr_t);
    ip_total_len = htons(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t)); 
  }

  /* Fill in Ethernet header: */
  memcpy(eth_hdr->ether_dhost, rcvd_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  eth_hdr->ether_type = rcvd_eth_hdr->ether_type;
  
  /* Fill in IP header: */
  ip_hdr->ip_v = rcvd_ip_hdr->ip_v;
  ip_hdr->ip_hl = rcvd_ip_hdr->ip_hl;
  ip_hdr->ip_tos = rcvd_ip_hdr->ip_tos;
  ip_hdr->ip_len = ip_total_len;
  ip_hdr->ip_id = htons(global_ip_id);
  global_ip_id++;
  ip_hdr->ip_off = 0x0000;
  ip_hdr->ip_ttl = TTL;
  ip_hdr->ip_p = 0x01;
  ip_hdr->ip_sum = 0x0000;
  if (response == TIME_EXCEEDED || response == DESTINATION_HOST_UNREACHABLE || response == DESTINATION_NET_UNREACHABLE) {
    ip_hdr->ip_src = iface->ip;
  } else {
    ip_hdr->ip_src = rcvd_ip_hdr->ip_dst;
  }
  ip_hdr->ip_dst = rcvd_ip_hdr->ip_src;
  uint16_t ip_checksum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
  ip_hdr->ip_sum = ip_checksum;
  
  /* Fill in ICMP header: */
  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  icmp_hdr->icmp_sum = 0x0000;
  if (response == ECHO_REPLY) { /* Copy entire payload of received IP packet. */
    memcpy((uint8_t*)icmp_hdr+sizeof(sr_icmp_hdr_t), 
           (uint8_t*)rcvd_icmp_hdr+sizeof(sr_icmp_hdr_t), 
           icmp_total_len-sizeof(sr_icmp_hdr_t));
  } else { /* Only copy the IP header of the received packet and first 8 bytes of payload. */
    memcpy(((sr_icmp_t3_hdr_t*)icmp_hdr)->data, 
          (uint8_t*)rcvd_ip_hdr,
          ICMP_DATA_SIZE);
  }
  uint16_t icmp_checksum = cksum(icmp_hdr, icmp_total_len);
  icmp_hdr->icmp_sum = icmp_checksum;
}

/* Checks all the routers' interfaces and returns true if dst_ip matches the IP address of one of them. 
   Returns true if there's a match. Stores a pointer to the matching sr_if struct. */
bool packet_is_for_me(uint32_t dst_ip, struct sr_instance *sr, struct sr_if** match) {
  struct sr_if* iface = sr->if_list;
  while (iface != NULL) {
    if (iface->ip == dst_ip) {
      *match = iface;
      return true;
    }
    iface = iface->next;
  }
  return false;
}

/* Implements LPM. Returns true if there's a match and points the variable "match" to it. 
   Note: takes hdr_ip_addr in network endianness. */
bool lpm_found_match(uint32_t hdr_ip_addr, struct sr_instance *sr, struct sr_rt** match) {
  uint32_t length = 0;
  struct sr_rt* rt_crawler = sr->routing_table;
  uint32_t crawler_mask;
  uint32_t crawler_dest;
  hdr_ip_addr = ntohl(hdr_ip_addr);
  while (rt_crawler != NULL) {
    crawler_mask = ntohl(rt_crawler->mask.s_addr);
    crawler_dest = ntohl(rt_crawler->dest.s_addr);
    uint32_t val1 = crawler_dest & crawler_mask;
    uint32_t val2 = hdr_ip_addr & crawler_mask;
    if (val1 == val2 && crawler_mask >= length) {
      *match = rt_crawler;
      length = crawler_mask; 
    }
    rt_crawler = rt_crawler->next;
  }
  if (*match == NULL) return false;
  return true; 
}

