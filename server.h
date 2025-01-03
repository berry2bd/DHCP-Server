#ifndef __cs361_dhcp_server_h__
#define __cs361_dhcp_server_h__

#include <stdbool.h>
#include <stdint.h>

#include "dhcp.h"

#define HARDWARE_ADDR_LEN 16
#define MAX_ASSIGNMENTS 4

extern bool debug;
extern struct in_addr THIS_SERVER;

void run_dhcp_server(uint16_t port, int runtime);

typedef struct {
    uint8_t chaddr[HARDWARE_ADDR_LEN];
    struct in_addr ip;
    bool in_use;
} ip_assignment_t;


void initialize_assignments();
ip_assignment_t *find_assignment(uint8_t *chaddr);
ip_assignment_t *assign_record(uint8_t *chaddr, struct in_addr ip);
void release_record(uint8_t *chaddr);
bool check_chaddr(uint8_t *chaddr);
bool any_assignments_left();
int get_free_assignment();


#endif
