#include <pcap.h>

#include "device.h"

#define NCID "ens33"
#define MAX_SNAPLEN 262144

void device_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    printf("\nPacket captured: %u bytes\n", header->len);
    printf("Timestamp: %ld.%06ld\n", header->ts.tv_sec, header->ts.tv_usec);
}

int main(){
    pcap_if_t *device = find_device_by_name(NCID);
    if (device == NULL) {
        fprintf(stderr, "Device %s not found\n", NCID);
        return 1;
    }
    printf("Device %s found\n", NCID);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handler = pcap_open_live(device->name, MAX_SNAPLEN, 1, 1000, errbuf);
    if (handler == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", device->name, errbuf);
        return 1;
    }
    printf("Device %s opened successfully\n", device->name);
    
    pcap_loop(handler, 10, device_handler, NULL);
    pcap_close(handler);
    return 0;
}
