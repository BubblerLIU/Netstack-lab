#ifndef NETSTACK_PACKETIO_H
#define NETSTACK_PACKETIO_H

int sendFrame(const void *buf, int len, int ethtype, const void *destmac, int id);

typedef int (*frameReceiveCallback)(const void *buf, int len, int id);
int setFrameReceiveCallback(frameReceiveCallback callback);
int receiveFrames(int id);

#endif
