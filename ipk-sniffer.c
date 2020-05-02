#include <stdio.h>
#include "string.h"
#include "netdb.h"
#include "netinet/ip.h"
#include "netinet/tcp.h"
#include "netinet/udp.h"
#include "netinet/if_ether.h"
#include "sys/socket.h"
#include "arpa/inet.h"
#include "pcap.h"
#include <stdlib.h>
#include <time.h>
#include "getopt.h"

/**
 * Struktura Params pro ulozeni a pouziti parametru programu
 *
 */
typedef struct parameters {
    int interface;
    char *interfaceId;
    int port;
    int tcp;
    int udp;
    int num;
} Params;

// globalni promenne
Params params;          //parametry programu
int totalPackets = 0;   //celkovy pocet odchycenych paketu

// prototypy funkci
int parseArgs(int argc, char *argv[]);
void printHeader(const u_char *buffer, unsigned short sourcePort, unsigned short destPort);
void printPacket(const u_char *buffer, int len);
void tcpPacket(const u_char *buffer, int len);
void udpPacket(const u_char *buffer, int len);


int main(int argc, char *argv[]) {
    pcap_t *handle;
    struct pcap_pkthdr *header;
    struct iphdr *ipHeader;
    const u_char *packet;
    int res;
    char errorBuffer[100];

    parseArgs(argc, argv);

    // pokud nebylo zadane rozhrani, vypise vsechny rozhrani a ukonci program
    if (params.interface == 0) {
        pcap_if_t *devList, *device;
        pcap_findalldevs(&devList, errorBuffer);
        printf("Seznam aktivnich rozhrani:\n");
        for (device = devList; device != NULL; device = device->next) {
            printf("%s - %s\n", device->name, device->description);
        }
        pcap_freealldevs(devList);
        return 0;
    }

    // otevreni rozhrani pro odchyceni paketu
    handle = pcap_open_live(params.interfaceId, 65536, 1, 1000, errorBuffer);
    if (!handle) {
        // nastala chyba pri otevirani rozhrani
        printf("%s\n", errorBuffer);
        return 1;
    }

    // dokud nebyl zpracovan pozadovany pocet paketu a je odchyceny dalsi paket
    while (totalPackets < params.num && (res = pcap_next_ex(handle, &header, &packet))) {
        // pokud program nestihl precist cely paket, pokracuje v cyklu
        if (res == 0) {
            continue;
        }
        // ulozeni ip hlavicky z paketu do struktury
        ipHeader = (struct iphdr *) (packet + sizeof(struct ethhdr));
        if (ipHeader->protocol == 6) {          // TCP
            // kontrola zda byl pouzit parametr -t nebo --tcp nebo zadny z nich
            if ((params.tcp == 0 && params.udp == 0) || params.tcp == 1) {
                tcpPacket(packet, header->len);
            }
        } else if (ipHeader->protocol == 17) {  // UDP
            // kontrola zda byl pouzit parametr -u nebo --udp nebo zadny z nich
            if ((params.tcp == 0 && params.udp == 0) || params.udp == 1) {
                udpPacket(packet, header->len);
            }
        }
    }
    // uvolneni pameti nazvu zadaneho rozhrani
    free(params.interfaceId);
    return 0;
}

/**
 * Funkce vypise zakladni informace o paketu, jako jsou cas odchyceni, zdrojova a cilova ip adresa a port atd.
 *
 * @param buffer Data paketu
 * @param sourcePort Zdrojovy port, pro nastaveni filtru na port
 * @param destPort Cilovy port, pro nastaveni filtru na port
 */
void printHeader(const u_char *buffer, unsigned short sourcePort, unsigned short destPort) {
    struct addrinfo *res, *result;
    char srcHostname[1025] = "";
    char destHostname[1025] = "";
    struct iphdr *ipHeader = (struct iphdr *) (buffer + sizeof(struct ethhdr));
    int err;
    struct sockaddr_in source, dest;

    // ulozeni ip adres do struktur pro nasledne uziti adres
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ipHeader->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ipHeader->daddr;

    // pokus o ziskani domenoveho jmena zdrojove ip adresy
    err = getaddrinfo(inet_ntoa(source.sin_addr), NULL, NULL, &result);
    if (err != 0) {
        printf("err getaddrinfo\n");
        exit(1);
    }
    for (res = result; res != NULL; res = res->ai_next) {
        err = getnameinfo(res->ai_addr, res->ai_addrlen, srcHostname, 1025, NULL, 0, 0);
        if (err != 0) {
            continue;
        }
        if (*srcHostname != '\0') {
            break;
        }
    }
    // pokud nebylo nalezeno domenove jmeno, pouzije se ip adresa
    if (!strcmp(srcHostname, "")) {
        strcpy(srcHostname, inet_ntoa(source.sin_addr));
    }
    // pokus o ziskani domenoveho jmena cilove ip adresy
    err = getaddrinfo(inet_ntoa(dest.sin_addr), NULL, NULL, &result);
    if (err != 0) {
        printf("err getaddrinfo\n");
        exit(1);
    }
    for (res = result; res != NULL; res = res->ai_next) {
        err = getnameinfo(res->ai_addr, res->ai_addrlen, destHostname, 1025, NULL, 0, 0);
        if (err != 0) {
            continue;
        }
        if (*srcHostname != '\0') {
            break;
        }
    }
    // pokud nebylo nalezeno domenove jmeno, pouzije se ip adresa
    if (!strcmp(destHostname, "")) {
        strcpy(destHostname, inet_ntoa(dest.sin_addr));
    }
    freeaddrinfo(result);

    // ziskani aktualniho casu
    char buf[80];
    struct timeval time;
    gettimeofday(&time, NULL);
    time_t raw = time.tv_sec;
    struct tm ts;
    ts = *localtime(&raw);
    strftime(buf, sizeof(buf), "%H:%M:%S", &ts);
    int usec = (int) time.tv_usec;

    // vypis zakladnich informaci: cas ip/domenove_jmeno port > ip/domenove_jmeno port
    printf("%s.%d %s : %d > %s : %d\n\n", buf, usec, srcHostname, sourcePort,
           destHostname, destPort);
}

/**
 * Funkce vypise data celeho paketu v hexadecimalnim a ascii formatu
 *
 * @param buffer Data paketu
 * @param len Delka paketu
 */
void printPacket(const u_char *buffer, int len) {
    // ocislovani radku
    int hexnum = 0;
    // vypis celeho paketu
    for (int i = 0; i < len; ++i) {
        // hexadecimalni format - po 16 bitech
        if (i != 0 && i % 16 == 0) {
            printf("%#06x: ", hexnum);
            //vypis hexa
            for (int j = i - 16; j < i; ++j) {
                if (j % 8 == 0) {
                    printf(" ");
                }
                printf("%02x ", (unsigned int) buffer[j]);
            }
            // vypis ascii
            for (int j = i - 16; j < i; ++j) {
                if (j % 8 == 0) {
                    printf(" ");
                }
                if (buffer[j] > 32 && buffer[j] < 128) {
                    printf("%c", (unsigned char) buffer[j]);
                } else {
                    printf(".");
                }
            }
            hexnum += 16;
            printf("\n");
        }
    }
    printf("\n");
}

/**
 * Funkce ulozi data o tcp paketu do struktury, pro ziskani potrebnych dat a vola vypis celeho paketu
 *
 * @param buffer Data paketu
 * @param len Delka paketu
 */
void tcpPacket(const u_char *buffer, int len) {
    struct iphdr *ipHeader = (struct iphdr *) (buffer + sizeof(struct ethhdr));

    struct tcphdr *tcpHeader = (struct tcphdr *) (buffer + sizeof(struct ethhdr) + ipHeader->ihl * 4);

    if (params.port == 0 || ntohs(tcpHeader->source) == params.port || ntohs(tcpHeader->dest) == params.port) {
        printHeader(buffer, ntohs(tcpHeader->source), ntohs(tcpHeader->dest));

        printPacket(buffer, len);

        ++totalPackets;
    }
}

/**
 * Funkce ulozi data o udp paketu do struktury, pro ziskani potrebnych dat a vola vypis celeho paketu
 *
 * @param buffer Data paketu
 * @param len Delka paketu
 */
void udpPacket(const u_char *buffer, int len) {
    struct iphdr *ipHeader = (struct iphdr *) (buffer + sizeof(struct ethhdr));

    struct udphdr *udpHeader = (struct udphdr *) (buffer + sizeof(struct ethhdr) + ipHeader->ihl * 4);

    if (params.port == 0 || ntohs(udpHeader->source) == params.port || ntohs(udpHeader->dest) == params.port) {
        printHeader(buffer, ntohs(udpHeader->source), ntohs(udpHeader->dest));

        printPacket(buffer, len);

        ++totalPackets;
    }
}

/**
 * Funkce na parsovani argumentu programu do struktury Params
 *
 * @param argc Pocet argumentu programu
 * @param argv Argumenty programu
 * @return Chybovy kod
 */
int parseArgs(int argc, char *argv[]) {
    params.interface = 0;
    params.interfaceId = (char *) malloc(sizeof(optarg));
    params.port = 0;
    params.tcp = 0;
    params.udp = 0;
    params.num = 1;

    int c = 0;
    int optionIndex = 0;
    struct option options[] = {
            {"tcp", no_argument, 0, 0},
            {"udp", no_argument, 0, 0}
    };
    while ((c = getopt_long(argc, argv, "i:p:tun:", options, &optionIndex)) != -1) {
        switch (c) {
            case 0:
                if ((strcmp(options[optionIndex].name, "tcp")) == 0) {
                    params.tcp = 1;
                } else {
                    params.udp = 1;
                }
                break;
            case 'i':
                params.interface = 1;
                strcpy(params.interfaceId, optarg);
                break;
            case 'p':
                params.port = atoi(optarg);
                break;
            case 't':
                params.tcp = 1;
                break;
            case 'u':
                params.udp = 1;
                break;
            case 'n':
                params.num = atoi(optarg);
                break;
            case '?':
                break;
            default:
                fprintf(stderr, "CHYBA: Neznamy argument. %o\n", c);
                return 1;
        }
    }
    return 0;
}
