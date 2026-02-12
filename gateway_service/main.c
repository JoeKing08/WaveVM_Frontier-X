#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "aggregator.h"
#include "../common_include/wavevm_protocol.h" 

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "Usage: %s <LOCAL_PORT> <UPSTREAM_IP> <UPSTREAM_PORT> <CONFIG_FILE> <CTRL_PORT>\n", argv[0]);
        return 1;
    }

    int local = atoi(argv[1]);
    const char *up_ip = argv[2];
    int up_port = atoi(argv[3]);
    const char *conf = argv[4];

    g_ctrl_port = atoi(argv[5]);

    printf("[*] WaveVM Gateway V16 (Chain Mode) | CtrlPort: %d\n", g_ctrl_port);
    
    if (init_aggregator(local, up_ip, up_port, conf) != 0) {
        fprintf(stderr, "[-] Init failed.\n");
        return 1;
    }

    while(1) {
        flush_all_buffers();
        usleep(1000); //太长会卡，太短烧 CPU
    }
    return 0;
}
