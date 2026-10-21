#include "ip.h"
#include "route.h"
#include "device.h"
#include "packetio.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <netinet/ip.h>

/* Local data variables */

static atomic_bool ip_module_running = 0;
static ReceiveThreadArg rtas[MAX_IP_DEVICES];
static IPDeviceTable *ip_devices = NULL;
static RoutingTable *rtb = NULL;
static IPPacketReceiveCallback receiver = NULL;

/* Tool functions */

static int readDeviceFile(const char *device_file) {
    FILE *fp = fopen(device_file, "r");
    if (fp == NULL) {
        perror(device_file);
        return -1;
    }

    char line[MAX_CONFIG_LINE];
    while (fgets(line, sizeof(line), fp) != NULL) {
        char device[IFNAMSIZ];
        char ip_str[INET_ADDRSTRLEN];
        char mask_str[INET_ADDRSTRLEN];

        sscanf(line, "%s %s %s", device, ip_str, mask_str);

        struct in_addr ip, mask;
        inet_pton(AF_INET, ip_str, &ip);
        inet_pton(AF_INET, mask_str, &mask);

        int id = addDevice(device);
        if (id == -1) {
            perror("addDevice");
            fclose(fp);
            return -1;
        }

        if (ip_devices->count == MAX_IP_DEVICES) {
            fprintf(stderr, "Failed to read device file: too much devices\n");
            fclose(fp);
            return -1;
        }

        struct device *dev = getDevice(id);
        ip_devices->devices[ip_devices->count].id = id;
        ip_devices->devices[ip_devices->count].ip = ip;
        ip_devices->devices[ip_devices->count].mask = mask;
        ip_devices->devices[ip_devices->count].handle = dev->handle;
        strcpy(ip_devices->devices[ip_devices->count].name, device);
        ++(ip_devices->count);
    }

    fclose(fp);
    return 0;
}

static int readRouteFile(const char *route_file) {
    FILE *fp = fopen(route_file, "r");
    if (fp == NULL) {
        perror(route_file);
        return -1;
    }

    char line[MAX_CONFIG_LINE];
    while (fgets(line, sizeof(line), fp) != NULL) {
        char dest_str[INET_ADDRSTRLEN];
        char mask_str[INET_ADDRSTRLEN];
        char mac_str[MAX_MAC_STR];
        char device[IFNAMSIZ];

        sscanf(line, "%s %s %s %s", dest_str, mask_str, mac_str, device);

        struct in_addr dest, mask;
        unsigned char mac[6];

        inet_pton(AF_INET, dest_str, &dest);
        inet_pton(AF_INET, mask_str, &mask);

        sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
            &mac[0], &mac[1], &mac[2],&mac[3], &mac[4], &mac[5]);

        if(setRoutingTable(dest, mask, mac, device) == -1) {
            fprintf(stderr, "Failed to read route file: can't set routing table\n");
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    return 0;  
}

static int startReceiveThreads() {
    for (int i = 0; i < ip_devices->count; ++i) {
        IPDevice *current = ip_devices->devices + i;

        if (current->recv_started) {
            fprintf(stderr, "Failed to start receive threads: thread running\n");
            return -1;
        }

        rtas[i].id_ptr = &current->id;
        rtas[i].running_ptr = &ip_module_running;
        int ret = pthread_create(&current->recv_thread, NULL, 
            receiveThread, &rtas[i]);
        if (ret != 0) {
            fprintf(stderr, "Failed to create receive thread, device=%s", current->name);
            return -1;
        }

        current->recv_started = 1;
    }
    return 0;
}

static void stopReceiveThreads() {
    /* Stop receive threads */
    atomic_store(&ip_module_running, 0);
    for (int i = 0; i < ip_devices->count; ++i) {
        IPDevice *current = ip_devices->devices + i;
        if (current->recv_started) {
            pcap_breakloop(current->handle);
        }
    }
    for (int i = 0; i < ip_devices->count; ++i) {
        IPDevice *current = ip_devices->devices + i;
        if (current->recv_started) {
            pthread_join(current->handle, NULL);
            current->recv_started = 0;
        }
    }
}

static void cleanupIPModule() {
    if (ip_devices != NULL) {
        free(ip_devices);
        ip_devices = NULL;
    }
    if (rtb != NULL) {
        free(rtb);
        rtb = NULL;
    }
    if (receiver != NULL) receiver = NULL;
}

static int getPrefixLen(const struct in_addr mask) {
    uint32_t m = ntohl(mask.s_addr), n = 0x80000000u;
    int len = 0;

    while (m & n) {
        ++len;
        m <<= 1;
    }

    return len;
}

static uint16_t calChecksum(const void *header, int len)
{
    const uint8_t *data = header;
    uint32_t sum = 0;

    for (int i = 0; i < len; i += 2) {
        sum += ((uint16_t)data[i] << 8) | data[i + 1];
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)~sum;
}

/* Interfaces */

int sendIPPacket(
    const struct in_addr src, const struct in_addr dest,
    int proto, const void *buf, int len
) {
    if (proto != 0x8000) {
        fprintf(stderr, "Failed to send IP packet: not IP protocal\n");
        return -1;
    }

    RouteEntry *best = lookupRoute(rtb, dest);
    if (best == NULL) {
        fprintf(stderr, "Failed to send IP packet: route entry not found\n");
        return -1;
    }

    if (sendFrame(buf, len, 0x8000, best->next_hop_mac, best->device_id) != 0) {
        perror("sendFrame");
        return -1;
    }

    return 0;
}

int setIPPacketReceiveCallback(IPPacketReceiveCallback callback) {
    receiver = callback;
    return 0;
}

int processIPPacket(const void *buf, int len, int id) {
    const unsigned char *header = buf;

    /* Check network layer protocol type */
    uint16_t network_type;
    memcpy(&network_type, header + 2 * ETHERNET_ADDRESS_SIZE,
            sizeof(network_type));
    if (ntohs(network_type) != 0x8000) {
        /* Not IPv4 packet, drop it */
        return 0;
    }

    /* Calculate checksum */
    uint8_t first_byte;
    memcpy(&first_byte, header, sizeof(first_byte));
    int header_len_32b = first_byte & 0x0f;
    int header_len_byte = header_len_32b * 4;
    uint16_t checksum = calChecksum(header, header_len_byte);
    if (checksum != 0) {
        fprintf(stderr, "IP packet from device id=%d: wrong checksum\n", id);
        return 0;
    }

    /* If fragmented, drop it */
    uint16_t frag, mask_frag = 0x3fff;
    memcpy(&frag, header + 3 * sizeof(uint16_t), sizeof(uint16_t));
    if ((frag & mask_frag)) {
        return 0;
    }
    
    /* If dest address is one of the host's ip address, hand it to application */
    struct in_addr dest;
    memcpy(&dest.s_addr, header + 16, 4);
    int total_len = (header[2] << 8) | header[3];
    int data_len = total_len - header_len_byte;
    for (int i = 0; i < ip_devices->count; ++i) {
        IPDevice *current = ip_devices->devices + i;
        if (current->ip.s_addr == dest.s_addr) {
            if (reciever(header + header_len_byte, data_len) != 0) {
                fprintf(stderr, "Failed to process IP packet: callback error\n");
                return -1;
            }
            break;
        }
    }

    /* If dest address is not host, forward it */
    if (header[8] <= 1) {
        /* TTL decreased to zero, drop it */
        return 0;
    }

    unsigned char *forward_buf = calloc(1, total_len);
    memcpy(forward_buf, header, total_len);
    --forward_buf[8];
    forward_buf[10] = forward_buf[11] = 0;
    checksum = calChecksum(forward_buf, header_len_byte);
    forward_buf[10] = checksum >> 8;
    forward_buf[11] = checksum & 0xff;

    struct in_addr src;
    memcpy(&src.s_addr, forward_buf + 12, 4);
    if (sendIPPacket(src, dest, 0x8000, forward_buf, total_len) != 0) {
        fprintf(stderr, "Failed to forward IP packet\n");
        free(forward_buf);
        return -1;
    }
    
    free(forward_buf);
    return 0;
}

/*
 * setRoutingTable - set route entry for a specific destination address
 */
int setRoutingTable(
    const struct in_addr dest, const struct in_addr mask,
    const void* nextHopMAC, const char *device
) {
    int device_id = findDevice(device);
    if (device_id == -1) {
        perror("findDevice");
        return -1;
    }

    /* Mask host bits, only reserve network address */
    struct in_addr network;
    network.s_addr = dest.s_addr & mask.s_addr;

    for (int i = 0; i < rtb->count; ++i) {
        RouteEntry *current = rtb->entries + i;
        if ((current->valid) && (network.s_addr == current->dest.s_addr) && 
            (mask.s_addr == current->mask.s_addr))
        {
            memcpy(current->next_hop_mac, nextHopMAC, 6);
            current->device_id = device_id;
            return 0;
        }
    }

    /* Full routing table */
    if (rtb->count == MAX_ROUTES) {
        fprintf(stderr, "Failed to set a new route entry: full routing table\n");
        return -1;
    }

    /* Add a new route entry */
    RouteEntry *new_entry = rtb->entries + rtb->count;
    new_entry->dest = network;
    new_entry->mask = mask;
    new_entry->prefix_len = getPrefixLen(mask);
    new_entry->device_id = device_id;
    memcpy(new_entry->next_hop_mac, nextHopMAC, 6);
    new_entry->valid = 1;
    ++(rtb->count);

    return 0;
}

/*
 * startIPModule - initialize resources and start receive threads
 */
int startIPModule(
    const char *device_file, const char *route_file,
    IPPacketReceiveCallback callback
) {
    /* Don't start twice! */
    if ((ip_devices != NULL) || (rtb != NULL) || (receiver != NULL)) {
        fprintf(stderr, "Failed to start IP module: old resources not released\n");
        return -1;
    }

    /* Initialize resources */
    ip_devices = calloc(1, sizeof(IPDeviceTable));
    rtb = calloc(1, sizeof(RoutingTable));
    receiver = callback;

    if (ip_devices == NULL) {
        fprintf(stderr, "Failed to start IP module: device table allocation error\n");
        goto cleanup;
    }
    if(readDeviceFile(device_file) != 0) {
        fprintf(stderr, "Failed to start IP module: device file error\n");
        goto cleanup;
    }

    if (rtb == NULL) {
        fprintf(stderr, "Failed to start IP module: routing table allocation error\n");
        goto cleanup;
    }
    if(readRouteFile(route_file) != 0) {
        fprintf(stderr, "Failed to start IP module: route file error\n");
        goto cleanup;
    }

    /* Start receive threads */
    atomic_store(&ip_module_running, 1);
    setFrameReceiveCallback(processIPPacket);
    if (startReceiveThreads() != 0) {
        fprintf(stderr, "Failed to start IP module: receive threads error\n");
        goto cleanup;
    }

    return 0;

cleanup:
    cleanupIPModule();
    return -1;
}

int stopIPModule() {
    stopReceiveThreads();
    cleanupIPModule();
    return 0;
}