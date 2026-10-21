#ifndef NETSTACK_DEVICE_H
#define NETSTACK_DEVICE_H

#include <net/if.h>
#include <netinet/in.h>
#include <pcap/pcap.h>

#define MAX_DEVICES 32

struct device {
    int id;
    char name[IFNAMSIZ];
    unsigned char mac[6];
    int mtu;
    pcap_t *handle;
};

int addDevice(const char *device);
int findDevice(const char *device);

int listDevices(void);
struct device *getDevice(int id);
void closeDevices(void);

#endif
