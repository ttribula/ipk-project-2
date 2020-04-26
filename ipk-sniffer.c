#include <stdlib.h>
#include <stdio.h>
#include "string.h"
#include "getopt.h"
#include "arpa/inet.h"
#include "netdb.h"
#include "sys/types.h"
#include "sys/socket.h"
#include "netinet/ip.h"
#include "netinet/tcp.h"
#include "netinet/udp.h"
#include "netinet/ip_icmp.h"
#include "netinet/if_ether.h"
#include "netinet/ip6.h"
#include "unistd.h"
#include "pcap.h"

typedef struct parameters {
    int interface;
    char *interfaceId;
    int port;
    int tcp;
    int udp;
    int num;
} Params;
Params params;

int parseArgs(int argc, char *argv[]);

int main(int argc, char *argv[]) {
    parseArgs(argc, argv);


    char errorBuffer[PCAP_ERRBUF_SIZE];

    if (params.interface == 0) {
        pcap_if_t *devList, *device;;
        pcap_findalldevs(&devList, errorBuffer);
        char  interfaces[100][100];
        printf("Seznam aktivnich rozhrani:\n");
        int count = 1;
        for(device = devList ; device != NULL ; device = device->next)
        {
            printf("%d. %s - %s\n" , count , device->name , device->description);
            if(device->name != NULL)
            {
                strcpy(interfaces[count] , device->name);
            }
            count++;
        }
        return 0;
    }

    char ip[13];
    char mask[13];
    bpf_u_int32 rawIp;
    bpf_u_int32 rawMask;
    int lookupReturn;
    struct in_addr address;

    if ((lookupReturn = pcap_lookupnet(params.interfaceId, &rawIp, &rawMask, errorBuffer)) == -1) {
        fprintf(stderr, "CHYBA: %s", errorBuffer);
        return 1;
    }

    address.s_addr = rawIp;
    strcpy(ip, inet_ntoa(address));
    if (!strcmp(ip, "")) {
        fprintf(stderr, "CHYBA: inet_ntoa\n");
        return 1;
    }

    address.s_addr = rawMask;
    strcpy(mask, inet_ntoa(address));
    if (!strcmp(mask, "")) {
        fprintf(stderr, "CHYBA: inet_ntoa\n");
        return 1;
    }

    printf("Device: %s\n", params.interfaceId);
    printf("IP address: %s\n", ip);
    printf("Subnet mask: %s\n", mask);


    free(params.interfaceId);
    return 0;
}


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
