#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include "include/sans.h"
#include "include/rudp.h"

typedef struct {
    int sockfd;
    socklen_t peer_len;
    struct sockaddr_storage peer_addr;
} rudp_conn_t;

extern void enqueue_packet(int sock, const char* buf, int len);
extern rudp_conn_t* get_rudp_connection(int fd);

static int sw_recv_seq = 0;
#define MAX_PAYLOAD 1024

int sans_send_pkt(int socket_fd, const char* buffer, int length) {
    rudp_conn_t* conn = get_rudp_connection(socket_fd);

    if (!conn) {
        ssize_t bytes = send(socket_fd, buffer, length, 0);
        return (bytes < 0) ? -1 : (int)bytes;
    }

    enqueue_packet(socket_fd, buffer, length);
    return length;
}

int sans_recv_pkt(int socket_fd, char* buffer, int length) {
    rudp_conn_t* conn = get_rudp_connection(socket_fd);

    if (!conn) {
        ssize_t bytes = recv(socket_fd, buffer, length, 0);
        return (bytes < 0) ? -1 : (int)bytes;
    }

    for (;;) {
        unsigned char rbuf[sizeof(rudp_packet_t) + MAX_PAYLOAD];
        struct sockaddr_storage src;
        socklen_t slen = sizeof(src);

        ssize_t n = recvfrom(socket_fd, rbuf, sizeof(rbuf), 0,
                             (struct sockaddr*)&src, &slen);

        if (n < 0) {
            if (errno == EBADF || errno == ENOTSOCK) return 0;
            return -1;
        }

        if (n < (ssize_t)sizeof(rudp_packet_t))
            return -1;

        rudp_packet_t* packet = (rudp_packet_t*)rbuf;
        ssize_t payload_len = n - sizeof(rudp_packet_t);

        if (packet->type == DAT && packet->seqnum == sw_recv_seq) {
            ssize_t to_copy = payload_len;
            if (to_copy > length) to_copy = length;
            if (to_copy > 0) memcpy(buffer, packet->payload, to_copy);

            if (to_copy < length) {
                if (to_copy == 0 || buffer[to_copy - 1] != '\0')
                    buffer[(to_copy < length) ? to_copy : length - 1] = '\0';
            }

            rudp_packet_t ackpkt = { ACK, sw_recv_seq };
            sendto(socket_fd, &ackpkt, sizeof(ackpkt), 0,
                   (struct sockaddr*)&conn->peer_addr, conn->peer_len);

            sw_recv_seq++;
            return (int)to_copy;
        }

        rudp_packet_t ackpkt = { ACK, sw_recv_seq - 1 };
        sendto(socket_fd, &ackpkt, sizeof(ackpkt), 0,
               (struct sockaddr*)&conn->peer_addr, conn->peer_len);
    }
}