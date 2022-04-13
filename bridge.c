#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
  char *device = NULL, c, *bpfFilter = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];
  int promisc = 1, snaplen = 1500;
  pcap_t *i1, *i2;

  if ((i1 = pcap_open_live("enp2s0f1", snaplen,
                             promisc, 500, errbuf)) == NULL) {
    printf("pcap_open_live: %s\n", errbuf);
    return (-1);
  }
  if ((i2 = pcap_open_live("wlp3s0", snaplen,
                           promisc, 500, errbuf)) == NULL) {
    printf("pcap_open_live: %s\n", errbuf);
    return (-1);
  }

  const unsigned char *pkt_data;
  struct pcap_pkthdr *header;
  int res;
  pcap_t *from = i1, *to = i2;
  while (1) {
    from = from == i1 ? i2 : i1;
    to = to == i1 ? i2 : i1;
    if ((res = pcap_next_ex(from, &header, &pkt_data)) != 1) {
      if (res == 0)
        printf("pcap_next: timeout\n");
      else
        printf("pcap_next: some error\n");
    } else {
      printf("pcap_next: ok\n");
      unsigned char *rec = (unsigned char*) pkt_data;
      rec[0] = rec[1] = rec[2] = rec[3] = rec[4] = rec[5] = 0xa;
      if ((res = pcap_sendpacket(to, pkt_data, header->caplen)) != 0)
        printf("pcap_send: some error\n");
      else
        printf("pcap_send: ok\n");
    }
  }

  return 0;
}
