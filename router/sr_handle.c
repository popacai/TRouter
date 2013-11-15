

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
#include "sr_handle.h"


uint8_t* build_arp_request(struct sr_instance* sr, 
		      sr_ip_hdr_t* ip_hdr,
		      char* interface,
		      int* size)
{
    *size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);

    uint8_t* buf = malloc(*size);

    struct sr_if* my_if;
    my_if = sr_get_interface(sr, interface);
    
    /* int ethernet header */
    sr_ethernet_hdr_t* eth_hdr;
    eth_hdr = (sr_ethernet_hdr_t*) buf;

    /* build the eth header */
    memset(eth_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, my_if->addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = ntohs(ethertype_arp);

    /* init arp header */
    sr_arp_hdr_t* arp_hdr;
    arp_hdr = (sr_arp_hdr_t*) (buf + sizeof(sr_ethernet_hdr_t));

    /* build the arp header*/
    arp_hdr->ar_hrd = ntohs(arp_hrd_ethernet);
    arp_hdr->ar_pro = ntohs(0x0800);
    arp_hdr->ar_hln = 6;
    arp_hdr->ar_pln = 4;
    arp_hdr->ar_op = ntohs(arp_op_request);
    memcpy(arp_hdr->ar_sha, my_if->addr, ETHER_ADDR_LEN);
    arp_hdr->ar_sip = my_if->ip;

    memset(arp_hdr->ar_tha, 0x00, ETHER_ADDR_LEN);
    arp_hdr->ar_tip = ip_hdr->ip_dst;

    printf("------------------------------\n");
    printf("build a arp request to send out\n");
    print_hdrs(buf, *size);
    
    return buf;
}


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
    struct sr_arpreq* arp_entry;
    if (ntohs(arp_hdr->ar_op) == arp_op_request)
    {
	//build a reply
	//check for the ip is myself or not
	print_addr_ip_int(ntohl(my_if->ip));

	
	if (!memcmp(&(arp_hdr->ar_tip), &(my_if->ip), 4))
	{
	    printf("arp_boardcast_request\n");
	    printf("Who is me,\n");
	    reply = build_arp_reply(sr, arp_hdr, interface, &reply_size);

	    print_hdrs(reply, reply_size);
	    
	    sr_send_packet(sr, reply, reply_size, interface);
	    free(reply);
	}

    }
    if (ntohs(arp_hdr->ar_op) == arp_op_reply)
    {
	printf("reply\n");
	
	arp_entry = sr_arpcache_insert(&(sr->cache),
				       arp_hdr->ar_sha,
				       arp_hdr->ar_sip);
	if (!arp_entry) // it already exist
	{
	    printf("destory the cache\n");

	    //call for immediately send out the pending IP packets

	    /*
	    sr_arpreq_destroy(&(sr->cache),
			      arp_entry);
	    */
	}
	sr_arpcache_dump(&(sr->cache));

    }

    return 0;
}

int handle_ip(struct sr_instance* sr,
	    sr_ip_hdr_t* ip_hdr,
	    char* interface,
	    uint8_t* packet,
	    int packet_len
	    )
{
    struct sr_if* my_if;
    my_if = sr_get_interface(sr, interface);
    char* next_interface;
    int size;
    uint8_t* buf;
    // check checksum
    if (!cksum(ip_hdr, sizeof(sr_ip_hdr_t)))
    {
	printf("chksum error\n");
	return 0;
    }

    // TTL
    ip_hdr->ip_ttl--;
    //print_hdr_ip_int(ip_hdr->ip_dst);
    
    if (--(ip_hdr->ip_ttl) == 0)
    {
	//return ICMP unreachable
    }

    if (ip_hdr->ip_dst == my_if->ip) //This is for me
    {
	//deal with the ICMP only
    }
    else
    {
	next_interface = sr_find_next_hop(sr, ip_hdr->ip_dst);
	//perform a read from cache first
	struct sr_arpentry * arp_entry;
	time_t now;
	now = time(0);
	arp_entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);
	if (!arp_entry)
	{
	    buf = build_arp_request(sr, ip_hdr, next_interface, &size);
	    
	    sr_arpcache_queuereq(&(sr->cache),
				ip_hdr->ip_dst,
				buf,
				size,
				next_interface);

	    free(buf);

	    sr_ethernet_hdr_t* eth_hdr;
	    eth_hdr = (sr_ethernet_hdr_t*) packet;
	    memset(eth_hdr->ether_dhost,0, ETHER_ADDR_LEN);
	    sr_arpcache_queuereq(&(sr->cache),
				ip_hdr->ip_dst,
				packet,
				packet_len,
				next_interface);

	    //sr_send_packet(sr, buf, size, next_interface);
	    //perform a arp request
	}
	else
	{
	    //check it
	    
	    //if valid
		    //forward to next_interface
	    //else
		    //send arp
	}
		
    }
    
    return 0;
}
