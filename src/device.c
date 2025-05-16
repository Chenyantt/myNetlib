#include "device.h"

#include <string.h>
#include <pcap.h>

void list_devices(){
    pcap_if_t *alldevs;
    pcap_if_t *device;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return;
    }

    printf("Available devices:\n");

    for (device = alldevs; device != NULL; device = device->next) {
        printf("\nDevice Name: %s\n", device->name);
        if (device->description) {
            printf("Description: %s\n", device->description);
        } else {
            printf("No description available\n");
        }

        pcap_addr_t *address;
        for (address = device->addresses; address != NULL; address = address->next) {
            if (address->addr && address->addr->sa_family == AF_INET) {
                struct sockaddr_in *addr = (struct sockaddr_in *)address->addr;
                struct sockaddr_in *netmask = (struct sockaddr_in *)address->netmask;

                printf("IP Address: %s\n", inet_ntoa(addr->sin_addr));
                if (netmask) {
                    printf("Netmask: %s\n", inet_ntoa(netmask->sin_addr));
                }
            }
        }
    }
}

pcap_if_t* find_device_by_name(const char* name) {
    pcap_if_t *alldevs;
    pcap_if_t *device;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return NULL;
    }

    for (device = alldevs; device != NULL; device = device->next) {
        if (strcmp(device->name, name) == 0) {
            return device;
        }
    }
    return NULL;
}