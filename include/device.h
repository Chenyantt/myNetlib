#ifndef __DEVICE_H
#define __DEVICE_H

#include <pcap.h>

void list_devices();
pcap_if_t* find_device_by_name(const char* name);

#endif