#ifndef NETSTACK_ROUTE_H
#define NETSTACK_ROUTE_H

#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <time.h>

/* Global parameters for routing */
#define MAX_ROUTES 1024
#define MAC_ADDR_LEN 6

/* Data structures for routing table */
typedef struct {
    struct in_addr dest;
    struct in_addr mask;
    int prefix_len;

    unsigned char next_hop_mac[MAC_ADDR_LEN];
    int device_id;

    uint32_t metric;
    time_t last_update;
    int valid;
} RouteEntry;

typedef struct {
    RouteEntry entries[MAX_ROUTES];
    int count;
} RoutingTable;

/* Functions for routing */
RouteEntry *lookupRoute(RoutingTable *table, const struct in_addr dst_ip);

#endif
