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

typedef struct parameters {
    char *interface;
    int port;
    int tcp;
    int udp;
    int num;
} Params;

int parseArgs(int argc, char *argv[], Params *params);

int main(int argc, char *argv[]) {
    Params params;
    parseArgs(argc, argv, &params);


    return 0;
}


int parseArgs(int argc, char *argv[], Params *params) {
    params->interface = "";
    params->port = 0;
    params->tcp = 0;
    params->udp = 0;
    params->num = 0;

    int c = 0;
    int optionIndex = 0;
    struct option options[] = {
            {"tcp", no_argument, 0, 0},
            {"udp", no_argument, 0, 0}
    };

    while ((c = getopt_long(argc, argv, "iptun", options, &optionIndex)) != -1) {
        switch (c) {
            case 0:
                if ((strcmp(options[optionIndex].name, "tcp")) == 0) {
                    params->tcp = 1;
                } else {
                    params->udp = 1;
                }
            case 'i':
                params->interface = optarg;
                break;
            case 'p':
                params->port = atoi(optarg);
                break;
            case 't':
                params->tcp = 1;
                break;
            case 'u':
                params->udp = 1;
                break;
            case 'n':
                params->num = atoi(optarg);
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
