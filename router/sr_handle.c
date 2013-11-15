

#include <stdio.h>
#include <assert.h>
#include <memory.h>
#include <malloc.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

uint8_t* build_arp_reply(struct sr_instance* sr, 
		      sr_arp_hdr_t* arp_hdr, 
		      char* interface,
		      int* size)
{
    *size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);

    uint8_t* buf = malloc(*size);

    struct sr_if* my_if;
    my_if = sr_get_interface(sr, interface);
    
    /* build ethernet header */
    sr_ethernet_hdr_t* r_eth_hdr;
    r_eth_hdr = (sr_ethernet_hdr_t*) buf;

    memcpy(r_eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    memcpy(r_eth_hdr->ether_shost, my_if->addr, ETHER_ADDR_LEN);
    r_eth_hdr->ether_type = ntohs((uint16_t)ethertype_arp);


    /* build arp header */
    sr_arp_hdr_t* r_arp_hdr = (sr_arp_hdr_t*)
			      (buf + sizeof(sr_ethernet_hdr_t));

    //init it 
    memcpy(r_arp_hdr, arp_hdr, sizeof(sr_arp_hdr_t));

    //This is a reply
    r_arp_hdr->ar_op = ntohs((uint16_t)arp_op_reply);

    //set the source MAC and IP
    memcpy(r_arp_hdr->ar_sha, my_if->addr, ETHER_ADDR_LEN);
    r_arp_hdr->ar_sip = my_if->ip;

    //set the target MAC and IP
    memcpy(r_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    r_arp_hdr->ar_tip = arp_hdr->ar_sip;

    
    return buf;
}
int handle_arp(struct sr_instance* sr,
	    sr_arp_hdr_t* arp_hdr,
	    char* interface
	    )
{
    struct sr_if* my_if;
    my_if = sr_get_interface(sr, interface);
    //print_addr_ip_int(ntohl(arp_hdr->ar_sip));
    uint8_t* reply;
    int reply_size;

    if (ntohs(arp_hdr->ar_op) == arp_op_request)
    {
	printf("request\n");
	//build a reply
	//check for the ip is myself or not
	print_addr_ip_int(ntohl(my_if->ip));

	
	if (!memcmp(&(arp_hdr->ar_tip), &(my_if->ip), 4))
	{
	    printf("Who is me,\n");
	    reply = build_arp_reply(sr, arp_hdr, interface, &reply_size);

	    print_hdrs(reply, reply_size);
	    
	    sr_send_packet(sr, reply, reply_size, interface);
	    free(reply);
	}
	else
	{
	    return 0; // don't reply
	}
    }
    if (ntohs(arp_hdr->ar_op) == arp_op_reply)
    {
	printf("reply\n");
	//insert into buffer...
    }

    
    return 0;
}
