#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "include/sans.h"
#include "include/rudp.h"

typedef struct {
    int sockfd;
    socklen_t peer_len;
    struct sockaddr_storage peer_addr;
} rudp_conn_t;

extern rudp_conn_t* get_rudp_connection(int fd);

const unsigned int swnd_size = 1;

typedef struct {
    int socket;
    int packetlen;
    rudp_packet_t* packet;
} swnd_entry_t;

static swnd_entry_t* sw_window;
static int sw_head = 0;
static int sw_count = 0;
static int sw_send_seq = 0;
static int sw_inflight_sent = 0;

int init_rudp_backend(void) {
    sw_window = malloc(sizeof(swnd_entry_t) * swnd_size);
    sw_head = 0;
    sw_count = 0;
    sw_inflight_sent = 0;
    return 0;
}

void enqueue_packet(int sock, const char* buf, int len) {
    while (sw_count == 1) {}

    swnd_entry_t* entry = &sw_window[sw_head];
    entry->socket = sock;
    entry->packetlen = sizeof(rudp_packet_t) + len;
    entry->packet = malloc(entry->packetlen);

    entry->packet->type = DAT;
    entry->packet->seqnum = sw_send_seq;
    memcpy(entry->packet->payload, buf, len);

    sw_count = 1;
    sw_inflight_sent = 0;
}

static void dequeue_packet() {
    swnd_entry_t* entry = &sw_window[sw_head];
    if (entry->packet) free(entry->packet);
    entry->packet = NULL;
    sw_count = 0;
    sw_inflight_sent = 0;
    sw_send_seq++;
}

void* rudp_backend(void* unused) {
    for (;;) {
        if (sw_count == 0) continue;

        swnd_entry_t* entry = &sw_window[sw_head];
        rudp_conn_t* conn = get_rudp_connection(entry->socket);
        if (!conn) continue;

        if (!sw_inflight_sent) {
            sendto(entry->socket, entry->packet, entry->packetlen, 0,
                   (struct sockaddr*)&conn->peer_addr, conn->peer_len);
            sw_inflight_sent = 1;
        }

        struct sockaddr_storage src;
        socklen_t slen = sizeof(src);
        rudp_packet_t ackpkt;

        ssize_t n = recvfrom(entry->socket, &ackpkt, sizeof(ackpkt), 0,
                             (struct sockaddr*)&src, &slen);

        if (n < 0) {
            if (errno == EBADF || errno == ENOTSOCK) pthread_exit(NULL);
            sw_inflight_sent = 0;
            continue;
        }

        if (n < (ssize_t)sizeof(ackpkt.type)) {
            sw_inflight_sent = 0;
            continue;
        }

        if (ackpkt.type == ACK) {
            if (ackpkt.seqnum == sw_send_seq) {
                dequeue_packet();
            } else if (ackpkt.seqnum < sw_send_seq) {
                continue;
            } else {
                continue;
            }
        }
    }
    return NULL;
}