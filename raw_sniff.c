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
#include <net/if.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define IPSTRLEN 16
#define BUFLEN 65536

void usage(); 
void process_packet(unsigned char*, int);
void process_ip_header(unsigned char*, int);
void print_tcp_packet(unsigned char*, int);
void print_udp_packet(unsigned char*, int);
void print_icmp_packet(unsigned char*, int);
void print_plaintext_data(char*, unsigned char*, int);
 
FILE *asciifile;
struct sockaddr_in source, dest;
char* progname;
char filter_addr[IPSTRLEN] = "";
int tcp=0, udp=0, icmp=0, others=0, igmp=0, total=0;
 
int main(int argc, char* argv[])
{
    int option;
    char if_name[IFNAMSIZ] = "";
    progname = argv[0];

    /* Check command line options */
    while((option = getopt(argc, argv, "i:f:h")) > 0) {
        switch(option) {
            case 'h':
                usage();
                break;
            case 'i':
                strncpy(if_name, optarg, IFNAMSIZ-1);
                break;
            case 'f':
                strncpy(filter_addr, optarg, IPSTRLEN-1);
                break;
              default:
                fprintf(stderr, "Unknown option %c\n", option);
                usage();
            }
      }
    
    int saddr_size, data_size;
    struct sockaddr saddr;
         
    unsigned char *buffer = (unsigned char *) malloc(BUFLEN);

    asciifile=fopen("sniffed.txt","w");
    if(asciifile==NULL)
    {
        printf("Unable to create file for writing traffic");
        return 1;
    }
    printf("Starting...\n");
    
    // sniff at ethernet layer
    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) ;
    setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, if_name, strlen(if_name)+ 1);
     
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
            printf("Recvfrom error, failed to get packets\n");
            return 1;
        }
        //Now process the packet
        process_packet(buffer, data_size);
    }
    close(sock_raw);
    printf("Finished");
    return 0;
}

void usage() {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "%s -i <ifacename> [-a <filterIP>]\n", progname);
    fprintf(stderr, "%s -h\n", progname);
    fprintf(stderr, "\n");
    fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
    fprintf(stderr, "-f <filterIP>: IP address whose traffic (both incoming and outgoing) to sniff (optional)\n");    
    fprintf(stderr, "-h: prints this help text\n");
    exit(1);
}
 
void process_packet(unsigned char* buffer, int psize)
{

    process_ip_header(buffer, psize);

    // check against filter IP
    if (strncmp("", filter_addr, IPSTRLEN) == 0 ||
        strncmp(inet_ntoa(source.sin_addr), filter_addr, IPSTRLEN) == 0 ||
        strncmp(inet_ntoa(dest.sin_addr), filter_addr, IPSTRLEN) == 0) {

        //Get the IP Header part of this packet, excluding the ethernet header
        struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
        ++total;
        switch (iph->protocol) //Check the Protocol and do accordingly...
        {
            case 1:  //ICMP Protocol
                ++icmp;
                print_icmp_packet(buffer, psize);
                break;
             
            case 2:  //IGMP Protocol
                ++igmp;
                break;
             
            case 6:  //TCP Protocol
                ++tcp;
                print_tcp_packet(buffer, psize);
                break;
             
            case 17: //UDP Protocol
                ++udp;
                print_udp_packet(buffer, psize);
                break;
             
            default: //Some Other Protocol like ARP etc.
                ++others;
                break;
        }
        printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp, udp, icmp, igmp, others, total);
    }
}


void process_ip_header(unsigned char* buffer, int psize)
{         
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr)); 
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;    
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
}
 
void print_tcp_packet(unsigned char* buffer, int psize)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
             
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

    print_plaintext_data("TCP", buffer + header_size, psize - header_size);
}
 
void print_udp_packet(unsigned char *buffer, int psize)
{
     
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof udph;

    print_plaintext_data("UDP", buffer + header_size, psize - header_size);
}
 
void print_icmp_packet(unsigned char* buffer, int psize)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
     
    struct icmphdr *icmph = (struct icmphdr *)(buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;    
    
    print_plaintext_data("ICMP", buffer + header_size, psize - header_size);
}

void print_plaintext_data(char* tr_proto, unsigned char* data, int psize)
{
    int i, j;
    char src_ip[IPSTRLEN];
    char dst_ip[IPSTRLEN];
    strncpy(src_ip, inet_ntoa(source.sin_addr), IPSTRLEN);
    strncpy(dst_ip, inet_ntoa(dest.sin_addr), IPSTRLEN);
    
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
                fprintf(asciifile, "%c",(unsigned char)data[i]); //if its a number or alphabet         
            else fprintf(asciifile, "."); //otherwise print a dot
            if(i!=0 && i%79==0) fprintf(asciifile, "\n");
        }
        fprintf(asciifile, "\n\n");
    }
}