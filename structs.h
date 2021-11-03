#include <stdio.h>

#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include<stdbool.h>	//Provides declarations for ip header
#include<netinet/icmp6.h>	//Provides declarations for icmp header





struct my_packet {
    uint8_t type;      /// 2 types ----> welcoming and ending
    uint16_t file_size;             
    char file_name[40];  
};


struct icmp_pckt2
{
    struct icmphdr hdr;
    struct my_packet pckt;
};

struct ipv6_header
{
    unsigned int
        version : 4,
        traffic_class : 8,
        flow_label : 20;
    uint16_t length;
    uint8_t  next_header;
    uint8_t  hop_limit;
    struct in6_addr src;
    struct in6_addr dst;
};

struct my_icmp_pckt6
{
    struct icmp6_hdr hdr;
    struct my_packet pckt;
};


// 60 - 
struct icmp_pckt
{
    struct icmphdr hdr;
    char data[1424];
};

struct icmp_pckt6
{
    struct icmp6_hdr hdr;
    char data[1424];
};




struct my_icmp_pckt
{
    struct icmphdr hdr;
    struct my_packet pckt;
};





