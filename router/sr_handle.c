

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

uint8_t* build_icmp(struct sr_instance* sr,
		    uint8_t* packet, // borrow
		    int packet_len,
		    int type,
		    int code,
		    char* interface,
		    int* size,
		    uint32_t ip)
{
    struct sr_if* my_if;

    uint8_t* buf;
    sr_ethernet_hdr_t* eth_hdr;
    sr_ip_hdr_t* ip_hdr;
    sr_ip_hdr_t* old_ip_hdr;
    sr_icmp_t3_hdr_t* icmp_hdr;

    my_if = sr_get_interface(sr, interface);

    *size = sizeof(sr_ethernet_hdr_t) + 
	    sizeof(sr_ip_hdr_t) + 
	    sizeof(sr_icmp_t3_hdr_t);

    printf("before *size\n");
    buf = malloc(*size);
    printf("buf_addr=%d\n", buf);
    printf("done on *size\n");

    memcpy(buf, packet, *size);
    //////////////////////////////////////////
    //Ethernet
    eth_hdr = (sr_ethernet_hdr_t*) buf;
    //The send_ip_packet will fill the ethernet.
    eth_hdr->ether_type = ntohs(ethertype_ip);

    /////////////////////////////////////
    //ICMP
    old_ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    old_ip_hdr->ip_ttl++;
    old_ip_hdr->ip_sum = 0;
    old_ip_hdr->ip_sum = cksum(old_ip_hdr, sizeof(sr_ip_hdr_t));
    
    icmp_hdr = (sr_icmp_t3_hdr_t*) (buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;

    icmp_hdr->unused = 0;
    icmp_hdr->next_mtu = 0;
    memcpy(icmp_hdr->data,old_ip_hdr, ICMP_DATA_SIZE); 

    ////////////////////////////////////////////////
    //IP
    ip_hdr = (sr_ip_hdr_t*) (buf + sizeof(sr_ethernet_hdr_t));
    //IP address
    //ip_hdr->ip_dst = ip_hdr->ip_src;
    ip_hdr->ip_dst = ip;
    //ip_hdr->ip_id = 0xcfe9;
    ip_hdr->ip_id = 0;
    ip_hdr->ip_src = my_if->ip;
    ip_hdr->ip_off = 0;
    ip_hdr->ip_len = ntohs(*size - sizeof(sr_ethernet_hdr_t));

    //IP protocol
    ip_hdr->ip_p = ip_protocol_icmp;
    ip_hdr->ip_ttl = 22;

    //checksum
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, 
			   sizeof(sr_ip_hdr_t));

   
    //Checksum
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));


    return buf;
}

uint8_t* build_icmp_reply(struct sr_instance* sr,
		         uint8_t* buf,
			 int len
			 )
{
    uint8_t tmp [ETHER_ADDR_LEN];
    uint32_t tmp2;
    sr_ethernet_hdr_t* tmp_eth_hdr;
    sr_ip_hdr_t* tmp_ip_hdr;
    sr_icmp_hdr_t* tmp_icmp_hdr;

    tmp_eth_hdr = malloc(len);
    memcpy(tmp_eth_hdr, buf, len);
    buf = tmp_eth_hdr;
    tmp_eth_hdr = (sr_ethernet_hdr_t*) (buf);

    // swap the ethernet
    memcpy(tmp, tmp_eth_hdr->ether_dhost, ETHER_ADDR_LEN);
    memcpy(tmp_eth_hdr->ether_dhost, tmp_eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(tmp_eth_hdr->ether_shost, tmp, ETHER_ADDR_LEN);

    // swap the IP
    tmp_ip_hdr = (sr_ip_hdr_t*) (buf + 
				 sizeof(sr_ethernet_hdr_t));
    tmp2 = tmp_ip_hdr->ip_dst;
    tmp_ip_hdr->ip_dst = tmp_ip_hdr->ip_src;
    tmp_ip_hdr->ip_src = tmp2;

    // change ip protocol
    tmp_ip_hdr->ip_p = ip_protocol_icmp;

    //change the checksum
    tmp_ip_hdr->ip_sum = 0;
    tmp_ip_hdr->ip_sum = cksum(tmp_ip_hdr, 
				sizeof(sr_ip_hdr_t));

    //change the ICMP
    tmp_icmp_hdr = (sr_icmp_hdr_t*) (buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    tmp_icmp_hdr->icmp_type = icmp_reply;
    tmp_icmp_hdr->icmp_code = 0;
    //tmp_icmp_hdr->icmp_sum = cksum(tmp_icmp_hdr, sizeof(sr_icmp_hdr_t));
    //tmp_icmp_hdr->icmp_sum = cksum(tmp_icmp_hdr, len - sizeof(sr_ip_hdr_t) - sizeof(sr_ethernet_hdr_t));
    //tmp_icmp_hdr->icmp_sum = cksum(tmp_ip_hdr, len - sizeof(sr_ethernet_hdr_t));
    tmp_icmp_hdr->icmp_sum = 0;
    tmp_icmp_hdr->icmp_sum = cksum(tmp_icmp_hdr, len - sizeof(sr_ip_hdr_t) - sizeof(sr_ethernet_hdr_t));
    return buf;

    //*size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
}


uint8_t* build_ip_packet(struct sr_instance* sr,
			 uint8_t* buf,
			 int len,
			 unsigned char* mac,
			 struct sr_if* my_if
			 )
{		
    sr_ethernet_hdr_t* tmp_eth_hdr;
    sr_ip_hdr_t* tmp_ip_hdr;

    tmp_eth_hdr = (sr_ethernet_hdr_t*) (buf);
    memcpy(tmp_eth_hdr->ether_dhost, mac, ETHER_ADDR_LEN);
    memcpy(tmp_eth_hdr->ether_shost, my_if->addr, ETHER_ADDR_LEN);

    //change checksum;
    tmp_ip_hdr = (sr_ip_hdr_t*) (buf + 
				 sizeof(sr_ethernet_hdr_t));
    tmp_ip_hdr->ip_sum = 0;
    tmp_ip_hdr->ip_sum = cksum(tmp_ip_hdr, 
				sizeof(sr_ip_hdr_t));
		/*
			       len - 
			       sizeof(sr_ethernet_hdr_t));
		*/
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

int send_ip_packet(struct sr_instance* sr,
		   sr_ip_hdr_t* ip_hdr, 
		   uint8_t* _packet,
		   int packet_len,
		   char* interface
		   )
{
    struct sr_if* my_if;
    my_if = sr_get_interface(sr, interface);
    char* next_interface;
    int size;
    uint8_t* buf;
    struct sr_arpentry * arp_entry;
    sr_ethernet_hdr_t* eth_hdr;
    sr_ip_hdr_t* new_ip_hdr;
    uint8_t* packet; // TODO: to free it
    printf("send_ip_packet_before\n");
    printf("size=%d\n",packet_len);
    packet = malloc(packet_len);
    printf("send_ip_packet_done\n");
    memcpy(packet, _packet, packet_len);
    next_interface = sr_find_next_hop(sr, ip_hdr->ip_dst);

    sr_icmp_hdr_t* icmp_hdr;
    if (!next_interface)
    {
	printf("not found\n");
	//ip_hdr->ip_dst = my_if->ip; // My reply
	if (ip_hdr->ip_p == ip_protocol_icmp)
	{
	    printf("build_icmp\n");
	    icmp_hdr = (sr_icmp_hdr_t*) packet;
	    if (cksum(icmp_hdr, sizeof(sr_icmp_hdr_t)))
	    {
		printf("ICMP error\n");
		free(packet);
		return 1;
	    }
	    buf = build_icmp(sr, packet, packet_len, icmp_unreachable, 0, interface, &size, ip_hdr->ip_src);
	    printf("check\n");
	    new_ip_hdr = (sr_ip_hdr_t*) (buf + sizeof(sr_ethernet_hdr_t));
	    printf("done_building_icmp\n");
	    send_ip_packet(sr, new_ip_hdr, buf, size, interface);
	    free(buf);
	    free(packet);
	    return 1;
	}
	else
	{
	    //port unaccessable

	    buf = build_icmp(sr, packet, packet_len, icmp_unreachable, 3, interface, &size, ip_hdr->ip_src);
	    new_ip_hdr = (sr_ip_hdr_t*) (buf + sizeof(sr_ethernet_hdr_t));
	    send_ip_packet(sr, new_ip_hdr, buf, size, interface);
	    printf("1\n");
	    free(buf);
	    printf("2\n");
	    free(packet);
	    return 1;
	}
    //    sr_send_packet(sr, buf, packet_len, my_if->name);
	free(packet);
	return 1;
    }


    //look for arp cache
    arp_entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);
    if (!arp_entry || (!arp_entry->valid))
    {
	buf = build_arp_request(sr, ip_hdr->ip_dst, next_interface, &size);

	printf("@@insert ip\n");
	sr_arpcache_queuereq(&(sr->cache),
			    ip_hdr->ip_dst,
			    packet,
			    packet_len,
			    next_interface);

	//send arp immediatelly
	sr_send_packet(sr, buf, size, next_interface);
	free(buf);
	free(packet);
	return 0;
    }
    else
    {
	if (arp_entry->valid)
	{	
	    my_if = sr_get_interface(sr, next_interface);
	    packet = build_ip_packet(sr, packet, packet_len, arp_entry->mac, my_if);
	    sr_send_packet(sr, packet, packet_len, my_if->name);
	    free(packet);
	    return 0;
	}
    }

    return 2;
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
    struct sr_arpreq* arp_req;
    struct sr_packet * packet;
    uint16_t ethtype;
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
	
	arp_req = sr_arpcache_insert(&(sr->cache),
				       arp_hdr->ar_sha,
				       arp_hdr->ar_sip);
	
	if (arp_req) // it already exist
	{
	    printf("quick_send\n");

	    //call for immediately send out the pending IP packets
	    
	    packet = arp_req->packets;

	    //packet = packet->next;
	    while (packet)
	    {
		ethtype = ethertype(packet->buf);

		if (ethtype == ethertype_ip)
		{
		    packet->buf = build_ip_packet(sr, packet->buf, packet->len,
						  arp_hdr->ar_sha, my_if);
		    sr_send_packet(sr, packet->buf, packet->len, packet->iface);
		}
		packet = packet->next;
	    }
	    sr_arpreq_destroy(&(sr->cache),
			      arp_req);
	}
	printf("dump to cache\n");
	//sr_arpcache_dump(&(sr->cache));
	print_addr_ip_int(ntohl(arp_hdr->ar_sip));

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
    struct sr_if* it_if;
    my_if = sr_get_interface(sr, interface);
    uint8_t* buf;
    // check checksum
    if (ip_hdr->ip_v != 4)
    {
	printf("IPv6 drop\n");
	return 0;
    }
    if (cksum(ip_hdr, sizeof(sr_ip_hdr_t)))
    {
	printf("chksum error\n");
	return 0;
    }

    // TTL
    ip_hdr->ip_ttl--;
    //print_hdr_ip_int(ip_hdr->ip_dst);
    
    sr_ip_hdr_t* new_ip_hdr;
    int size;

    if ((ip_hdr->ip_ttl) == 0)
    {
	printf("TTL = 0; return icmp time out\n");
	//ip_hdr->ip_dst = my_if->ip;
	buf = build_icmp(sr, packet, packet_len, icmp_timeout, 0, interface, &size, ip_hdr->ip_src);
	new_ip_hdr = (sr_ip_hdr_t*) (buf + sizeof(sr_ethernet_hdr_t));
	send_ip_packet(sr, new_ip_hdr, buf, size, interface);
	free(buf);
	//buf = build_icmp_reply(sr, packet, packet_len, icmp_timeout, 0);
	//sr_send_packet(sr, buf, packet_len, my_if->name);
	return 1;
	//return ICMP unreachable
    }

    
    //if (ip_hdr->ip_dst == my_if->ip) //This is for me
    //TODO: check for all the interface
    it_if = sr->if_list;
    sr_icmp_hdr_t* icmp_hdr;
    while (it_if)
    {
	if (it_if->ip == ip_hdr->ip_dst)
	{
	    if (ip_hdr->ip_p == ip_protocol_icmp)
	    {
		icmp_hdr = packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t);
		if (!cksum(icmp_hdr, sizeof(sr_icmp_hdr_t)))
		{
		    printf("ICMP error\n");
		    return 1;
		}
		
		printf("This is another IP in the router\n");
		buf = build_icmp_reply(sr, packet, packet_len);
		//sr_ethernet_hdr_t* eth_hdr = buf;
		//memcpy(eth_hdr->ether_shost, it_if->addr, ETHER_ADDR_LEN);
		sr_send_packet(sr, buf, packet_len, my_if->name);
		print_hdrs(buf, packet_len);
		printf("1\n");
		free(buf);
		printf("2\n");
		return 1;
	    }
	    if (ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp)
	    {
		buf = build_icmp(sr, packet, packet_len, icmp_unreachable, 3, interface, &size, ip_hdr->ip_src);
		ip_hdr = (sr_ip_hdr_t*) (buf + sizeof(sr_ethernet_hdr_t));
		send_ip_packet(sr, ip_hdr, buf, size, interface);
		free(buf);
		return 0;
	    }
	}
	it_if = it_if->next;
    }


    send_ip_packet(sr, ip_hdr, packet, packet_len, interface);
    
    return 0;
}
