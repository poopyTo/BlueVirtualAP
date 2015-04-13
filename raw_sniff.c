#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
 
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define IPSTRLEN 16
#define BUFLEN 65536
 
void process_packet(unsigned char* , int);
void print_ip_header(unsigned char* , int);
void process_ip_header(unsigned char*, int, char*, char*);
void print_tcp_packet(unsigned char * , int);
void print_udp_packet(unsigned char * , int);
void print_icmp_packet(unsigned char* , int);
void print_plaintext_data(char*, char*, char*, unsigned char* , int);
 
FILE *asciifile;
struct sockaddr_in source, dest;
int tcp=0, udp=0, icmp=0, others=0, igmp=0, total=0;
 
int main(int argc, char* argv[])
{

    if (argc < 2) {
        fprintf(stderr, "must provide interface to listen on!");
        exit(1);
    }

    int saddr_size, data_size;
    struct sockaddr saddr;
         
    unsigned char *buffer = (unsigned char *) malloc(BUFLEN);

    asciifile=fopen("sniffed.txt","w");
    if(asciifile==NULL)
    {
        printf("Unable to create sniffed.txt");
    }
    printf("Starting...\n");
    
    // sniff at ethernet layer
    int sock_raw = socket(AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
    setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , argv[1] , strlen(argv[1])+ 1);
     
    if(sock_raw < 0)
    {
        //Print the error with proper message
        perror("Socket Error");
        return 1;
    }
    while(1)
    {
        saddr_size = sizeof saddr;
        //Receive a packet
        data_size = recvfrom(sock_raw, buffer, BUFLEN, 0, &saddr, (socklen_t*)&saddr_size);
        if(data_size < 0)
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        //Now process the packet
        process_packet(buffer, data_size);
    }
    close(sock_raw);
    printf("Finished");
    return 0;
}
 
void process_packet(unsigned char* buffer, int size)
{
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            ++icmp;
            print_icmp_packet(buffer, size);
            break;
         
        case 2:  //IGMP Protocol
            ++igmp;
            break;
         
        case 6:  //TCP Protocol
            ++tcp;
            print_tcp_packet(buffer, size);
            break;
         
        case 17: //UDP Protocol
            ++udp;
            print_udp_packet(buffer, size);
            break;
         
        default: //Some Other Protocol like ARP etc.
            ++others;
            break;
    }
    printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp , others , total);
}

void process_ip_header(unsigned char* buffer, int psize, char* src_ip, char* dst_ip)
{
    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    
    snprintf(src_ip, IPSTRLEN, "%s", inet_ntoa(source.sin_addr));
    snprintf(dst_ip, IPSTRLEN, "%s", inet_ntoa(dest.sin_addr));
}
 
void print_tcp_packet(unsigned char* buffer, int psize)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
             
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

    char src_ip[IPSTRLEN];
    char dst_ip[IPSTRLEN];    
    process_ip_header(buffer , psize, src_ip, dst_ip);
    print_plaintext_data("TCP", src_ip, dst_ip, buffer + header_size , psize - header_size);
}
 
void print_udp_packet(unsigned char *buffer , int psize)
{
     
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

    char src_ip[IPSTRLEN];
    char dst_ip[IPSTRLEN];    
    process_ip_header(buffer , psize, src_ip, dst_ip);
    print_plaintext_data("UDP", src_ip, dst_ip, buffer + header_size , psize - header_size);
}
 
void print_icmp_packet(unsigned char* buffer , int psize)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
     
    struct icmphdr *icmph = (struct icmphdr *)(buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
     
    char src_ip[IPSTRLEN];
    char dst_ip[IPSTRLEN];    
    process_ip_header(buffer , psize, src_ip, dst_ip);
    print_plaintext_data("ICMP", src_ip, dst_ip, buffer + header_size , psize - header_size);
}

void print_plaintext_data(char* tr_proto, char* src_ip, char* dst_ip,
                    unsigned char* data , int psize)
{
    int i, j;
    fprintf(asciifile, "%s: %s > %s ", tr_proto, src_ip, dst_ip);
    int divstrlen = strlen(tr_proto) + strlen(src_ip) + strlen(dst_ip) + 6;
    for (j = 0; j < 80-divstrlen; j++) fprintf(asciifile, "~");
    fprintf(asciifile, "\n");

    if (psize == 0) {
        fprintf(asciifile, "[empty payload]\n\n");
    } else {
        for(i=0; i < psize; i++)
        {        
            if(data[i]>=32 && data[i]<=128)
                fprintf(asciifile , "%c",(unsigned char)data[i]); //if its a number or alphabet         
            else fprintf(asciifile , "."); //otherwise print a dot
            if(i!=0 && i%79==0) fprintf(asciifile , "\n");
        }
        fprintf(asciifile, "\n\n");
    }
}