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
#include <memory.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_handle.h"

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
    struct sr_if* my_if;

    my_if = sr_get_interface(sr, interface);
    //print_addr_eth(my_if->addr);
    //print_addr_ip_int(ntohl(my_if->ip));

    //resolve the packet here
    int minlength = sizeof(sr_ethernet_hdr_t);

    if (len < minlength)
    {
	fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
	return;
    }

    //print_hdr_eth(packet);

    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;

    uint8_t boardcast[ETHER_ADDR_LEN];
    memset((void*)boardcast, 0xff, ETHER_ADDR_LEN);

    //if boardcast
    if (!memcmp(boardcast, eth_hdr->ether_dhost, ETHER_ADDR_LEN))
    {
	printf("boardcast\n");
	fprintf(stderr, "ETHERNET header:\n");
	fprintf(stderr, "\tsource: ");
	print_addr_eth(eth_hdr->ether_shost);
    }
    //my interface
    else if(!memcmp(my_if->addr, eth_hdr->ether_dhost, ETHER_ADDR_LEN))
    {
	printf("sent to my interface\n");
    }
    else
    {
	printf("not my packet, ignore\n");
	return;
    }
    
    
    uint16_t ethtype = ethertype(packet);
    //print_hdr_eth(packet);
    
    //ARP
    sr_arp_hdr_t* arp_hdr;
    sr_ip_hdr_t* ip_hdr;
    if (ethtype == ethertype_arp) 
    {
	minlength += sizeof(sr_arp_hdr_t);
	if (len < minlength)
	{
	    fprintf(stderr, "Failed to print ARP header, insufficient length\n");
	    return;
	}
	else
	{
	    arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
	    handle_arp(sr,arp_hdr,interface);
	    //doing sth with ARP
	    //1. if opcode 
	    //TODO: Do the ar_hrd check
	}
    }

    if (ethtype == ethertype_ip)
    {
	minlength += sizeof(sr_ip_hdr_t);
	if (len < minlength)
	{
	    fprintf(stderr, "Failed to print IP header, insufficient length\n");
	    return;
	}
	
	ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
	handle_ip(sr, ip_hdr, interface, packet, len);


    }



    /* fill in code here */

}/* end sr_ForwardPacket */

