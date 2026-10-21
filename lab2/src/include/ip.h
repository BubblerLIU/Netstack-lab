#ifndef NETSTACK_IP_H
#define NETSTACK_IP_H

#include <pthread.h>
#include <netinet/in.h>
#include <net/if.h>
#include <pcap/pcap.h>

#define MAX_IP_DEVICES 32
#define MAX_CONFIG_LINE 256
#define MAX_MAC_STR 18

typedef struct {
    int id;
    char name[IFNAMSIZ];
    struct in_addr ip;
    struct in_addr mask;

    pthread_t recv_thread;
    int recv_started;

    pcap_t *handle;
} IPDevice;

typedef struct {
    IPDevice devices[MAX_IP_DEVICES];
    int count;
} IPDeviceTable;

int sendIPPacket(
    const struct in_addr src, const struct in_addr dest,
    int proto, const void *buf, int len
);

typedef int (*IPPacketReceiveCallback)(const void* buf, int len);
int setIPPacketReceiveCallback(IPPacketReceiveCallback callback);

int processIPPacket(const void *buf, int len, int id);

int setRoutingTable(
    const struct in_addr dest, const struct in_addr mask,
    const void* nextHopMAC, const char *device
);

int startIPModule(const char *device_file, const char *route_file, IPPacketReceiveCallback callback);
int stopIPModule();

#endif
