#ifndef SR_HANDLE_H
#define SR_HANDLE_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_router.h"
uint8_t* build_icmp(struct sr_instance* sr,
		    uint8_t* packet, // borrow
		    int packet_len,
		    int type,
		    int code,
		    char* interface,
		    int* size,
		    uint32_t ip
		    );
int send_ip_packet(struct sr_instance* sr,
		   sr_ip_hdr_t* ip_hdr, 
		   uint8_t* packet,
		   int packet_len,
		   char* interface
		   );

int handle_arp(struct sr_instance* sr,
	    sr_arp_hdr_t* arp_hdr,
	    char* interface
	    );

int handle_ip(struct sr_instance* sr,
	    sr_ip_hdr_t* ip_hdr,
	    char* interface,
	    uint8_t* packet,
	    int packet_len
	    );
#endif
