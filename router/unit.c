#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "sr_rt.h"
#include "sr_rt.c"
#include "sr_utils.c"


int main()
{
    uint32_t ip1;
    uint32_t ip2;
    uint32_t mask;

    unsigned char* p;
    int i;
    p = &ip1;
    for (i = 0; i < 4; i++)
    {
	*(p++) = i;
    }

    p = &ip2;
    for (i = 0; i < 4; i++)
    {
	*(p++) = i;
    }


    p = &mask;
    p++;
    *(p++) = 128;
    for (i = 2; i < 4; i++)
    {
	*(p++) = 255;
    }
    
    
    print_addr_ip_int(ip1 & mask);
    print_addr_ip_int(ip2 & mask);
    print_addr_ip_int(mask);
    

    printf("%d\n", prefix_match(ip1, ip2, mask));
    return 0;
}
