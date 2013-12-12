
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>


int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */

  /* Global values: */
  nat->port = 0x0400; 
  nat->identifier = 0x0000;
  
  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */
    struct sr_nat_mapping* prev = nat->mappings;
    struct sr_nat_mapping* mapping = nat->mappings;
    int end_of_mappings = 0;
    while (mapping != NULL) {
      mapping = mapping->next;
      if (mapping == NULL) {
	mapping = prev;
	end_of_mappings = 1;
      }
      if (mapping->type == nat_mapping_icmp) {
	if (difftime(curtime, mapping->last_updated) > nat->icmp_timeout) {
	  struct sr_nat_mapping* to_free = mapping;
	  mapping = mapping->next;
	  free(to_free);
	  prev->next = mapping;
	  continue;
	} 
      } else {
	struct sr_nat_connection* prev_conn = mapping->conns;
	struct sr_nat_connection* conn = mapping->conns;
	while (conn != NULL) {
	  conn = conn->next;
	  if (conn == NULL) {
	    conn = prev_conn;
	  }
	  time_t timeout_value;
	  if (conn->conn_established) {
	    timeout_value = nat->tcp_idle_timeout;
	  } else {
	    timeout_value = nat->tcp_transit_timeout;
	  }
	  if (difftime(curtime, conn->last_updated) > timeout_value) {
	    struct sr_nat_connection* to_free = conn;
	    conn = conn->next;
	    free(to_free);
	    prev_conn->next = conn;
	    continue;
	  }
	  prev_conn = prev_conn->next;
	}
	if (mapping->conns == NULL) { /* Cleared out all connections for mapping. */
	  struct sr_nat_mapping* to_free = mapping;
          mapping = mapping->next;
          free(to_free);
          prev->next = mapping;
          continue;
	}
      }
      if (end_of_mappings) mapping = NULL; // End the loop
      prev = prev->next;
    }

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;

  /* Search through all mappings. */
  struct sr_nat_mapping* mapping = nat->mappings;
  while (mapping != NULL) {
    if (mapping->type != type) {
      continue;
    }
    if (aux_ext == mapping->aux_ext) {
      copy = (struct sr_nat_mapping*)malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
      /* Note: For a TCP connection, the function doesn't update the last_updated field. */
      if (type == nat_mapping_icmp) {
        mapping->last_updated = time(NULL);
      } 
      break;
    }
    mapping = mapping->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;

  /* Search through all mappings. */
  struct sr_nat_mapping* mapping = nat->mappings;
  while (mapping != NULL) {
    if (mapping->type != type) {
      continue;
    }
    if (aux_int == mapping->aux_int && ip_int == mapping->ip_int) {
      copy = (struct sr_nat_mapping*)malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
      /* Note: For a TCP connection, the function doesn't update the last_updated field. */
      if (type == nat_mapping_icmp) {
        mapping->last_updated = time(NULL);
      }
      break;
    }
    mapping = mapping->next;
  }
 
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping* mapping = (struct sr_nat_mapping*) malloc(sizeof(struct sr_nat_mapping));;
  mapping->type = type;
  mapping->ip_int = ip_int; /* internal ip addr */
  mapping->aux_int = aux_int; /* external ip addr */
  mapping->last_updated = time(NULL); /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
  if (type == nat_mapping_tcp) {
    mapping->conns = (struct sr_nat_connection*) malloc(sizeof(struct sr_nat_connection));
    mapping->aux_ext = nat->port;
    nat->port++;  
  } else if (type == nat_mapping_icmp) {
    mapping->conns = NULL;
    mapping->aux_ext = nat->identifier;
    nat->identifier++;
  }
  //struct sr_nat_mapping* old = nat->mappings;
  mapping->next = nat->mappings;
  nat->mappings = mapping;
  //mapping->next = old;
  struct sr_nat_mapping* copy = malloc(sizeof(struct sr_nat_mapping));
  memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}
