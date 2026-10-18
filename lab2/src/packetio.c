#include "packetio.h"
#include "device.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ETHERNET_ADDRESS_SIZE 6
#define ETHERNET_HEADER_SIZE 14
#define ETHERNET_MIN_FRAME_SIZE 60
#define ETHERNET_TYPE_MIN 0x0600

static frameReceiveCallback receiver;

/*
 * setFrameReceiveCallback - register callback funtion after receive frame
 */
int setFrameReceiveCallback(frameReceiveCallback callback)
{
    receiver = callback;
    return 0;
}

/*
 * sendFrame - format a frame and inject it to network
 */
int sendFrame(const void *buf, int len, int ethtype, const void *destmac, int id)
{
    struct device *device = getDevice(id);
    if (device == NULL) {
        return -1;
    }

    if (len < 0 || destmac == NULL || (len > 0 && buf == NULL)) {
        errno = EINVAL;
        return -1;
    }

    // Values below 0x0600 is not an EtherType
    if (ethtype < ETHERNET_TYPE_MIN || ethtype > UINT16_MAX) {
        errno = EINVAL;
        return -1;
    }

    if (len > device->mtu) {
        errno = EMSGSIZE;
        return -1;
    }

    size_t frame_size = ETHERNET_HEADER_SIZE + (size_t)len;
    if (frame_size < ETHERNET_MIN_FRAME_SIZE) {
        frame_size = ETHERNET_MIN_FRAME_SIZE;
    }

    // calloc also fills any bytes required for Ethernet minimum-size padding
    unsigned char *frame = calloc(1, frame_size);
    if (frame == NULL) {
        errno = ENOMEM;
        return -1;
    }

    memcpy(frame, destmac, ETHERNET_ADDRESS_SIZE);
    memcpy(frame + ETHERNET_ADDRESS_SIZE,
           device->mac, ETHERNET_ADDRESS_SIZE);

    uint16_t network_type = htons((uint16_t)ethtype);
    memcpy(frame + 2 * ETHERNET_ADDRESS_SIZE,
           &network_type, sizeof(network_type));

    if (len > 0) {
        memcpy(frame + ETHERNET_HEADER_SIZE, buf, (size_t)len);
    }

    int sent = pcap_inject(device->handle, frame, frame_size);
    free(frame);

    if (sent < 0) {
        fprintf(stderr, "pcap_inject(%s): %s\n",
                device->name, pcap_geterr(device->handle));
        errno = EIO;
        return -1;
    }

    if ((size_t)sent != frame_size) {
        fprintf(stderr, "pcap_inject(%s): sent %d of %zu bytes\n",
                device->name, sent, frame_size);
        errno = EIO;
        return -1;
    }

    return 0;
}

/*
 * receiveFrames - receive a frame from a device and callback
 */
int receiveFrames(int id)
{
    struct device *device = getDevice(id);
    if (device == NULL) {
        return -1;
    }

    if (receiver == NULL) {
        errno = EINVAL;
        return -1;
    }

    for (;;) {
        struct pcap_pkthdr *header = NULL;
        const unsigned char *frame = NULL;
        int result = pcap_next_ex(device->handle, &header, &frame);

        if (result == 0) {
            continue;
        }

        if (result == PCAP_ERROR_BREAK) {
            return 0;
        }

        if (result == PCAP_ERROR) {
            fprintf(stderr, "pcap_next_ex(%s): %s\n",
                    device->name, pcap_geterr(device->handle));
            errno = EIO;
            return -1;
        }

        if (header->caplen < ETHERNET_HEADER_SIZE ||
            header->caplen < header->len) {
            continue;
        }

        uint16_t network_type;
        memcpy(&network_type, frame + 2 * ETHERNET_ADDRESS_SIZE,
               sizeof(network_type));
        if (ntohs(network_type) < ETHERNET_TYPE_MIN) {
            continue;
        }

        if (receiver(frame, (int)header->caplen, id) < 0) {
            return -1;
        }
    }
}
