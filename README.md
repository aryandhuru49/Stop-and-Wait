# Stop-and-Wait Reliability (RUDP)

An implementation of **Stop-and-Wait ARQ** for a Reliable UDP (RUDP) transport layer. The protocol sends one packet at a time and retransmits until a valid acknowledgement is received, providing basic reliability over UDP.

---

## Overview

This implementation adds reliability to RUDP by:
- Allowing only a single in-flight packet (send window size = 1)
- Retransmitting packets on timeout
- Ignoring incorrect or out-of-order acknowledgements
- Maintaining compatibility with existing HTTP and SMTP clients

---

## Core Behavior

- Packets are wrapped as `rudp_packet_t` structures
- A sequence number is tracked for each transmission
- The sender blocks if the send window is full
- The receiver acknowledges the last valid packet received
- Timeouts trigger retransmission until success

---

## File Roles

- **`sans_transport.c`**  
  Implements Stop-and-Wait logic in `sans_send_pkt` and `sans_recv_pkt`, including packet transmission, acknowledgement handling, and sequence number tracking.

- **`sans_backend.c`**  
  Implements the `rudp_backend` loop responsible for sending packets, handling timeouts, retransmissions, and clearing the send window on successful acknowledgement.

- **`sans_socket.c`**  
  Configures socket behavior for RUDP connections, including receive timeouts required for retransmission logic.

---

## Build

```bash
scons build
```

This produces:
- `sans` – main executable
- `sans-tests` – automated test suite

---

## Run Example

```bash
./sans http client www.example.com 80
```

**Input**
```
GET index.html
```

---

## Debugging

```bash
gdb --args ./sans http client www.example.com 80
```

---

## Notes

- Designed for correctness and clarity rather than throughput
- Serves as a foundation for more advanced reliability mechanisms
- Preserves behavior of higher-level protocols

---

## Tech

- Language: C
- UDP sockets
- Custom Stop-and-Wait reliability logic
