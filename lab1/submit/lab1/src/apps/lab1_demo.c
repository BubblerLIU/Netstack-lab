#include "device.h"
#include "packetio.h"
#include <stdio.h>
#include <string.h>

static int printFrame(const void *buf, int len, int id)
{
    const unsigned char *bytes = buf;
    printf("device=%d length=%d\n", id, len);
    for (int i = 0; i < len; ++i)
        printf("%02x%s", bytes[i], (i + 1) % 16 == 0 ? "\n" : " ");
    if (len % 16) putchar('\n');
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "list") == 0)
        return listDevices() == 0 ? 0 : 1;
    if (argc != 3 || (strcmp(argv[1], "recv") && strcmp(argv[1], "send"))) {
        fprintf(stderr, "Usage: %s list | recv INTERFACE | send INTERFACE\n", argv[0]);
        return 2;
    }

    int id = addDevice(argv[2]);
    if (id < 0) {
        perror("addDevice");
        return 1;
    }

    int result;
    if (strcmp(argv[1], "recv") == 0) {
        setFrameReceiveCallback(printFrame);
        result = receiveFrames(id);
    } else {
        const unsigned char broadcast[6] = {255, 255, 255, 255, 255, 255};
        const char payload[] = "hello from lab1";
        result = sendFrame(payload, (int)sizeof(payload) - 1, 0x88b5, broadcast, id);
    }
    if (result < 0) perror("packet I/O");
    
    closeDevices();
    return result == 0 ? 0 : 1;
}
