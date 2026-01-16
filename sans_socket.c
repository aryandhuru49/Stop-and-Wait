#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include "sans.h"
#include "rudp.h"

typedef struct {
    int in_use;
    int sck_fd;
    struct sockaddr_storage remote_addr;
    socklen_t remote_len;
} rudp_conn_t;

static rudp_conn_t rudp_tble[64];

static rudp_conn_t* find_connection(int sockfd) {
    int i = 0;
    while (i < 64) {
        if (rudp_tble[i].in_use && rudp_tble[i].sck_fd == sockfd) {
            return &rudp_tble[i];
        }
        i++;
    }
    return NULL;
}

static rudp_conn_t* allocate_connection(int sockfd) {
    int i = 0;
    while (i < 64) {
        if (!rudp_tble[i].in_use) {
            rudp_tble[i].in_use = 1;
            rudp_tble[i].sck_fd = sockfd;
            return &rudp_tble[i];
        }
        i++;
    }
    return NULL;
}

static void store_peer(int sockfd, const struct sockaddr* remote, socklen_t remote_ln) {
    rudp_conn_t* enty = find_connection(sockfd);
    if (!enty) enty = allocate_connection(sockfd);
    if (!enty) return;
    memcpy(&enty->remote_addr, remote, remote_ln);
    enty->remote_len = remote_ln;
}

rudp_conn_t* get_rudp_connection(int sockfd) {
    return find_connection(sockfd);
}

static int send_pkt(int sockfd, char type, const struct sockaddr* dst_addr, socklen_t dst_len) {
    rudp_packet_t ctrl;
    ctrl.type = type;
    ctrl.seqnum = 0;
    return sendto(sockfd, &ctrl, sizeof(ctrl), 0, dst_addr, dst_len);
}

static int recv_pkt(int sockfd, rudp_packet_t* ctrl_pkt, struct sockaddr* src_addr, socklen_t* src_len) {
    ssize_t nread = recvfrom(sockfd, ctrl_pkt, sizeof(*ctrl_pkt), 0, src_addr, src_len);
    if (nread < (ssize_t)sizeof(ctrl_pkt->type)) return -1;
    return ctrl_pkt->type;
}

int sans_connect(const char* hostname, int prt_num, int proto) {
    if (proto == IPPROTO_TCP) {
        struct addrinfo ai_hints, *ai_list, *ai;
        char port_str[8];
        int tcp_fd = -1;
        snprintf(port_str, sizeof(port_str), "%d", prt_num);
        memset(&ai_hints, 0, sizeof(ai_hints));
        ai_hints.ai_family = AF_UNSPEC;
        ai_hints.ai_socktype = SOCK_STREAM;
        ai_hints.ai_protocol = IPPROTO_TCP;
        if (getaddrinfo(hostname, port_str, &ai_hints, &ai_list) != 0) return -1;
        for (ai = ai_list; ai != NULL; ai = ai->ai_next) {
            tcp_fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (tcp_fd < 0) continue;
            if (connect(tcp_fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
            close(tcp_fd);
            tcp_fd = -1;
        }
        freeaddrinfo(ai_list);
        return tcp_fd;
    }

    if (proto != IPPROTO_RUDP) {
        errno = EPROTONOSUPPORT;
        return -1;
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) return -1;

    struct sockaddr_in remote_addr;
    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(prt_num);
    remote_addr.sin_addr.s_addr = inet_addr(hostname);

    struct timeval rcv_timeout = (struct timeval){ .tv_sec = 0, .tv_usec = 20000 };
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &rcv_timeout, sizeof(rcv_timeout));

    struct sockaddr_storage reply_addr;
    socklen_t reply_len = sizeof(reply_addr);
    rudp_packet_t ctrl;

    for (;;) {
        send_pkt(sockfd, SYN, (struct sockaddr*)&remote_addr, sizeof(remote_addr));
        int pkt_type = recv_pkt(sockfd, &ctrl, (struct sockaddr*)&reply_addr, &reply_len);
        if (pkt_type == (SYN | ACK)) break;
    }

    store_peer(sockfd, (struct sockaddr*)&reply_addr, reply_len);
    send_pkt(sockfd, ACK, (struct sockaddr*)&reply_addr, reply_len);
    return sockfd;
}

int sans_accept(const char* hostname, int prt_num, int proto) {
    if (proto == IPPROTO_TCP) {
        struct addrinfo ai_hints, *ai_list, *ai;
        char port_str[8];
        int listen_fd_tcp = -1, client_fd_tcp = -1;
        int reuseaddr_opt = 1;
        snprintf(port_str, sizeof(port_str), "%d", prt_num);
        memset(&ai_hints, 0, sizeof(ai_hints));
        ai_hints.ai_family = AF_UNSPEC;
        ai_hints.ai_socktype = SOCK_STREAM;
        ai_hints.ai_protocol = IPPROTO_TCP;
        ai_hints.ai_flags = AI_PASSIVE;
        if (getaddrinfo(hostname, port_str, &ai_hints, &ai_list) != 0) return -1;
        for (ai = ai_list; ai != NULL; ai = ai->ai_next) {
            listen_fd_tcp = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (listen_fd_tcp < 0) continue;
            setsockopt(listen_fd_tcp, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_opt, sizeof(reuseaddr_opt));
            if (bind(listen_fd_tcp, ai->ai_addr, ai->ai_addrlen) == 0 && listen(listen_fd_tcp, 10) == 0) {
                client_fd_tcp = accept(listen_fd_tcp, NULL, NULL);
                close(listen_fd_tcp);
                break;
            }
            close(listen_fd_tcp);
            listen_fd_tcp = -1;
        }
        freeaddrinfo(ai_list);
        return client_fd_tcp;
    }

    if (proto != IPPROTO_RUDP) {
        errno = EPROTONOSUPPORT;
        return -1;
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) return -1;

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(prt_num);
    bind_addr.sin_addr.s_addr = (hostname && *hostname) ? inet_addr(hostname) : INADDR_ANY;
    bind(sockfd, (struct sockaddr*)&bind_addr, sizeof(bind_addr));

    struct timeval rcv_timeout = (struct timeval){ .tv_sec = 0, .tv_usec = 20000 };
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &rcv_timeout, sizeof(rcv_timeout));

    struct sockaddr_storage remote_addr;
    socklen_t remote_len = sizeof(remote_addr);
    rudp_packet_t ctrl;

    for (;;) {
        int pkt_type = recv_pkt(sockfd, &ctrl, (struct sockaddr*)&remote_addr, &remote_len);
        if (pkt_type == SYN) break;
    }

    for (;;) {
        send_pkt(sockfd, SYN | ACK, (struct sockaddr*)&remote_addr, remote_len);
        int pkt_type = recv_pkt(sockfd, &ctrl, (struct sockaddr*)&remote_addr, &remote_len);
        if (pkt_type == ACK) break;
    }

    store_peer(sockfd, (struct sockaddr*)&remote_addr, remote_len);
    return sockfd;
}

int sans_disconnect(int sockfd) {
    close(sockfd);
    return 0;
}
