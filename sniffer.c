#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

struct ethheader {
    u_char  ether_dhost[6]; 
    u_char  ether_shost[6];
    u_short ether_type;  
};

struct ipheader {
    unsigned char      iph_ihl:4, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3, iph_offset:13;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    struct  in_addr    iph_sourceip;
    struct  in_addr    iph_destip;
};

struct tcpheader {
    u_short tcp_sport;
    u_short tcp_dport;
    u_int   tcp_seq;
    u_int   tcp_ack;
    u_char  tcp_offx2;
    u_char  tcp_flags;
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

void print_mac(u_char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl * 4));

            printf(" Src MAC: "); print_mac(eth->ether_shost); printf("\n");
            printf(" Dst MAC: "); print_mac(eth->ether_dhost); printf("\n");
            printf(" From: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("   To: %s\n", inet_ntoa(ip->iph_destip));
            printf(" Protocol: TCP\n");
            printf(" Src Port: %d\n", ntohs(tcp->tcp_sport));
            printf(" Dst Port: %d\n", ntohs(tcp->tcp_dport));

            int ip_header_size = ip->iph_ihl * 4;
            int tcp_header_size = (tcp->tcp_offx2 >> 4) * 4;
            int payload_offset = sizeof(struct ethheader) + ip_header_size + tcp_header_size;
            int payload_size = header->caplen - payload_offset;

            printf(" Payload (%d bytes): ", payload_size > 30 ? 30 : payload_size);
            for (int i = 0; i < payload_size && i < 30; i++) {
                printf("%02x ", packet[payload_offset + i]);
            }
            printf("\n=====================================\n");
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1 || pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Failed to set filter: %s\n", pcap_geterr(handle));
        return EXIT_FAILURE;
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
