#ifndef NETSTACK_PACKETIO_H
#define NETSTACK_PACKETIO_H

#define ETHERNET_ADDRESS_SIZE 6

typedef struct {
    int *id_ptr;
    atomic_bool *running_ptr;
} ReceiveThreadArg;

int sendFrame(const void *buf, int len, int ethtype, const void *destmac, int id);

typedef int (*frameReceiveCallback)(const void *buf, int len, int id);
int setFrameReceiveCallback(frameReceiveCallback callback);
int receiveFrames(int id);
void *receiveThread(void *arg);

#endif
