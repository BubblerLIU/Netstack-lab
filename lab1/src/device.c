#include "device.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <net/if_arp.h>

static struct device devices[MAX_DEVICES];
static int device_count = 0;

/*
 * listDevices - find all devices in the namespace and print the list
 */
int listDevices(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devices = NULL;
    if (pcap_findalldevs(&devices, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
        return -1;
    }

    for (pcap_if_t *d = devices; d; d = d->next) {
        // If device has a description, print it.
        printf("%s%s%s\n", d->name, d->description ? " : " : "",
               d->description ? d->description : "");
    }

    pcap_freealldevs(devices);
    return 0;
}

/*
 * queryDeviceInfo - read the MAC address and MTU of an Ethernet device
 */
static int queryDeviceInfo(const char *device, unsigned char mac[6], int *mtu)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct ifreq req = {0};
    snprintf(req.ifr_name, sizeof(req.ifr_name), "%s", device);

    if (ioctl(fd, SIOCGIFHWADDR, &req) < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    if (req.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
        close(fd);
        errno = EPROTONOSUPPORT;
        return -1;
    }
    memcpy(mac, req.ifr_hwaddr.sa_data, 6);

    // ifreq contains a union, so query the MTU only after copying the MAC
    if (ioctl(fd, SIOCGIFMTU, &req) < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    *mtu = req.ifr_mtu;

    close(fd);
    return 0;
}

/*
 * addDevice - register an Ethernet device after all initialization succeeds
 */
int addDevice(const char *device)
{
    if (device == NULL || device[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    size_t name_len = strlen(device);
    if (name_len >= IFNAMSIZ) {
        errno = ENAMETOOLONG;
        return -1;
    }

    int existing = findDevice(device);
    if (existing >= 0) {
        return existing;
    }

    if (device_count >= MAX_DEVICES) {
        errno = ENOSPC;
        return -1;
    }

    // Initialize locally so a failed registration cannot leave a partial entry.
    struct device candidate = {0};
    memcpy(candidate.name, device, name_len + 1);

    if (queryDeviceInfo(device, candidate.mac, &candidate.mtu) < 0) {
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    candidate.handle = pcap_open_live(device, 65535, 0, 100, errbuf);
    if (candidate.handle == NULL) {
        fprintf(stderr, "pcap_open_live(%s): %s\n", device, errbuf);
        errno = EIO;
        return -1;
    }
    if (errbuf[0] != '\0') {
        fprintf(stderr, "pcap warning (%s): %s\n", device, errbuf);
    }

    if (pcap_datalink(candidate.handle) != DLT_EN10MB) {
        pcap_close(candidate.handle);
        errno = EPROTONOSUPPORT;
        return -1;
    }

    candidate.id = device_count;
    devices[device_count] = candidate;
    ++device_count;
    return candidate.id;
}

/*
 * findDevice - find a device by its name, return its id 
 */
int findDevice(const char *device)
{
    // Invalid device name
    if (device == NULL || device[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    for (int i = 0; i < device_count; ++i) {
        if (strcmp(devices[i].name, device) == 0) {
            return devices[i].id;
        }
    }

    errno = ENODEV;
    return -1;
}

/*
 * getDevice - get the pointer to a device by its id
 */
struct device *getDevice(int id)
{
    if (id < 0 || id >= device_count) {
        errno = ENODEV;
        return NULL;
    }

    return &devices[id];
}

/*
 * closeDevices - release all handles and invalidate all registered device IDs
 */
void closeDevices(void)
{
    for (int i = 0; i < device_count; ++i) {
        pcap_close(devices[i].handle);
    }

    memset(devices, 0, sizeof(devices));
    device_count = 0;
}
