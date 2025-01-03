#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "dhcp.h"
#include "format.h"
#include "port_utils.h"
#include "server.h"

static bool get_args (int, char **);
static int server_runtime = 0;

bool debug = false;

int
main (int argc, char **argv)
{
  uint16_t port = strtol(get_port(), NULL, 10);
    if (!get_args(argc, argv)) {
        fprintf(stderr, "Usage: %s [-d] [-s seconds]\n", argv[0]);
        return EXIT_FAILURE;
    }
      if (debug)
        fprintf(stderr, "Starting DHCP server on port %u\n", port);
        
      run_dhcp_server(port, server_runtime);
  
        
      if (debug)
          fprintf(stderr, "Shutting down\n");
    return EXIT_SUCCESS;
    
}

static bool
get_args (int argc, char **argv)
{
  int ch = 0;
  while ((ch = getopt (argc, argv, "dhs:")) != -1)
    {
      switch (ch)
        {
        case 'd':
          debug = true;
          break;
        case 's':
          ;
          char *endptr = 0;
          server_runtime = (int) strtol(optarg, &endptr, 10);
          if (*endptr != '\0' || server_runtime <= 0) {
              fprintf(stderr, "Invalid runtime value.\n");
              return false;
          }
          break;
        default:
          return false;
        }
    }
  return true;
}
