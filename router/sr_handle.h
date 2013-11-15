#ifndef SR_HANDLE_H
#define SR_HANDLE_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_router.h"

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
