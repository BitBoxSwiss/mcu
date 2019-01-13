#include <arpa/inet.h>
#include "commander.h"
#include "ecc.h"
#include "flags.h"
#include "memory.h"
#include "sd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define PORT 35345
#define BUF_SIZE COMMANDER_REPORT_SIZE

int main(int argc, char* argv[])
{
    // Get and set the root directory
    if (argc < 2) {
        fprintf(stderr, "The directory to be used for the sd card files must be specified\n");
        exit(1);
    } else if (argc > 2) {
        fprintf(stderr, "Too many arguments\n");
        exit(1);
    }
    set_root_dir(argv[1]);

    // Init device
    ecc_context_init();
#ifdef ECC_USE_SECP256K1_LIB
    bitcoin_ecc.ecc_context_init();
#endif
    memory_setup();
    memory_setup();

    // Create socket
    int s;
    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        fprintf(stderr, "Socket could not be created\n");
        exit(1);
    }

    // Make socket struct
    struct sockaddr_in sock;
    memset(&sock, 0, sizeof(sock));
    sock.sin_family = AF_INET;
    sock.sin_addr.s_addr = htonl(INADDR_ANY);
    sock.sin_port = htons(PORT);

    // Bind socket
    if (bind(s, (struct sockaddr*)&sock, sizeof(sock)) == -1) {
        fprintf(stderr, "Could not bind socket\n");
        exit(1);
    }
    fprintf(stderr, "Digital Bitbox simulator started\n");

    // Wait for connections and handle
    char buf[BUF_SIZE];
    char* result;
    struct sockaddr_in in_sock;
    int recv_len;
    socklen_t in_sock_len = sizeof(in_sock);
    while (1) {
        int rc;
        // Receive
        memset(buf, 0, BUF_SIZE);
        if ((recv_len = recvfrom(s, buf, BUF_SIZE, 0, (struct sockaddr*)&in_sock, &in_sock_len)) < 0) {
            fprintf(stderr, "Failed to receive udp data, error %d\n", recv_len);
            exit(1);
        }

        // Execute the command
        result = commander(buf);

        // Send result to socket
        if ((rc = sendto(s, result, strlen(result), 0, (struct sockaddr*)&in_sock, in_sock_len)) < 0) {
            fprintf(stderr, "Failed to send udp data, error %d\n", rc);
            exit(1);
        }
    }
}
