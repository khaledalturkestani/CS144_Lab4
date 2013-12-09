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
void make_icmp_packet(uint8_t * rcvd_packet, uint8_t * packet, struct sr_if* iface, enum icmp_responses response);
void send_arp_reply(struct sr_instance* sr, uint8_t* packet, struct sr_if* if_match, char* interface);

/* Globals: */
uint16_t global_ip_id = 0x0000;

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
  sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)packet;
  enum sr_ethertype ether_type = ntohs(ethernet_hdr->ether_type); 
  if (!packet_length_is_valid(packet, ether_type, len)) {
    return;
  }
  if (ether_type == ethertype_ip) { /* Packet is IP. */
    unsigned int eth_hdr_len = sizeof(sr_ethernet_hdr_t);
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet+eth_hdr_len);
    if (checksum_matches(ip_hdr)) { /* IP header's checksum matches. Continue. */
      struct sr_if* iface = sr_get_interface(sr, interface);
      unsigned int icmp_packet_len;
      enum icmp_responses response;
      struct sr_if* if_match = NULL; /* A match in the routing table will be assigned to this. */
      if (packet_is_for_me(ip_hdr->ip_dst, sr, &if_match)) { /* Packet is IP and for me. */
	if (ip_hdr->ip_p == IP_PROTOCOL_ICMP) { /* echo request --> send echo reply. */
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
      } else { /* Packet is IP but not for me --> forward packet. */
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
	    printf("------------------- NOT MATCH IN ROUTING TABLE -------------------\n");
	    icmp_packet_len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t);
            uint8_t icmp_packet[icmp_packet_len];
            response = DESTINATION_NET_UNREACHABLE;
            make_icmp_packet(packet, icmp_packet, iface, response);
            sr_send_packet(sr, icmp_packet, icmp_packet_len, interface);
	  }
	}
      }
    } else { /* Checksum didn't match --> drop packet. */
      return;
    }  
  } else if (ether_type == ethertype_arp) { /* Packet is ARP. */
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
  } else { /* Not an IP or ARP packet --> drop packet. */
    return;
  }  
} /* end sr_ForwardPacket */


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

/* Implements LPM. Needs to be cleaned up and changed so that it also saves a pointer
   to the correct routing table entry to be used. */
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

