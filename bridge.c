/**
 * @file bridge.c
 * @author your name (you@domain.com)
 * @brief usage:
 *  gcc bridge.c -o bridge -lpcap
 *  bridge enp2s0f1 wlp3s0
 * @version 0.1
 * @date 2022-04-13
 *
 * @copyright Copyright (c) 2022
 *
 */
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>

#define ec(cmd, op, arg, err) \
  do {                        \
    if ((cmd)op(arg)) {       \
      err;                    \
    }                         \
  } while (0)

void help() {
  printf("Usage: sudo ./bridge.c <interface_1> <interface_2>\n");
}
void forward(pcap_t *from, pcap_t *to);

int main(int argc, const char **argv) {
  char *device = NULL, c, *bpfFilter = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];
  int promisc = 1, snaplen = 1500;  // TODO get actual mtu dynamically
  pcap_t *i1, *i2;

  if (argc != 3) {
    help();
    return -1;
  }

  // capture packets from the two interfaces
  ec(i1 = pcap_open_live(argv[1], snaplen, promisc, 500, errbuf), ==, NULL,
     printf("pcap_open_live: %s\n", errbuf);
     return (-1););
  ec(i2 = pcap_open_live(argv[2], snaplen, promisc, 500, errbuf), ==, NULL,
     printf("pcap_open_live: %s\n", errbuf);
     return (-1););

  // capture only incoming packets
  ec(pcap_setdirection(i1, PCAP_D_IN), !=, 0, pcap_perror(i1, argv[1]); return -1;);
  ec(pcap_setdirection(i2, PCAP_D_IN), !=, 0, pcap_perror(i2, argv[2]); return -1;);

  int res,
      fd1 = pcap_fileno(i1),
      fd2 = pcap_fileno(i2),
      fd_max = fd1 > fd2 ? fd1 : fd2;
  ;

  fd_set mask;
  struct timeval timeout;
  timeout.tv_sec = 1;  // wake from select every second
  timeout.tv_usec = 0;
  while (1) {
    // restore select set
    FD_ZERO(&mask);
    FD_SET(fd1, &mask);
    FD_SET(fd2, &mask);
    if (select(fd_max + 1, &mask, NULL, NULL, &timeout)) {
      if (FD_ISSET(fd1, &mask))
        forward(i1, i2);
      if (FD_ISSET(fd2, &mask))
        forward(i2, i1);
    }
  }

  return 0;
}

/**
 * @brief Reads a packet from 'from' and forwards it to 'to'. Didn't expect that huh?
 *
 * @param from net interface to read a packet from
 * @param to net interface to send the previously read packet to
 */
void forward(pcap_t *from, pcap_t *to) {
  const unsigned char *pkt_data;
  struct pcap_pkthdr *header;
  int res;
  if ((res = pcap_next_ex(from, &header, &pkt_data)) != 1) {
    if (res == 0)
      printf("pcap_next: timeout %s\n", );
    else
      printf("pcap_next: some error\n");
  } else {
    // printf("pcap_next: ok\n");
    if ((res = pcap_sendpacket(to, pkt_data, header->caplen)) != 0)
      printf("pcap_send: some error\n");
    // else
    // printf("pcap_send: ok\n");
  }
}