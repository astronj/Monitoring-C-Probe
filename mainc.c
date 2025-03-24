#include <pcap/pcap.h>  // Ensures proper inclusion of u_char
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>      // Defines standard integer types

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    printf("Packet captured - Length: %d bytes\n", header->len);
    // Process and send the packet data to CMI
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Error opening device: %s\n", errbuf);
        return 1;
    }

    pcap_loop(handle, 10, packet_handler, NULL);
    pcap_close(handle);
    return 0;
}
