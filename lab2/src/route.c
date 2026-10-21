#include "route.h"

/*
 * lookupRoute - return the best match with maximum prefix
 */
RouteEntry *lookupRoute(RoutingTable *table, const struct in_addr dst_ip) {
    RouteEntry *best = NULL, *current = NULL;
    for (int i = 0; i < table->count; ++i) {
        current = table->entries + i;

        /* Although it is not necessary to transmit byte order to host order
         * here, we still do this for convinience. */
        uint32_t ip = ntohl(dst_ip.s_addr);
        uint32_t dest = ntohl(current->dest.s_addr);
        uint32_t mask = ntohl(current->mask.s_addr);

        if (current->valid == 0) {
            continue;
        }

        /* Skip if it is not target network */
        if ((ip & mask) != (dest & mask)) {
            continue;
        }

        /* Reserve the entry with maximum prefix */
        if ((best == NULL) || (current->prefix_len > best->prefix_len)) {
            best = current;
        }
    }
    return best;
}