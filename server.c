#include <arpa/inet.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "dhcp.h"
#include "format.h"
#include "port_utils.h"
#include "server.h"

#define DHCP_SERVER_IP "192.168.1.0"

static volatile bool server_running = true;
char *addresses[]
    = { "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4" };
int last_index = 0;
int waiting = -1;

static ip_assignment_t ip_assignments[MAX_ASSIGNMENTS];

// Setup socket parameters and bind
static int
create_server_socket (uint16_t port, int runtime)
{
  int sockfd = socket (AF_INET, SOCK_DGRAM, 0);
  setsockopt (sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof (int));

  struct timeval timeout = { .tv_sec = runtime, .tv_usec = 0 };

  setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof (timeout));

  struct sockaddr_in server_addr = { 0 };
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl (INADDR_ANY);
  server_addr.sin_port = htons (port);

  bind (sockfd, (struct sockaddr *)&server_addr, sizeof (server_addr));

  return sockfd;
}

// Read given dhcp message and construct a reponse message, appending options
// as needed.
static void
process_dhcp_message (uint8_t *buffer, size_t size,
                      struct sockaddr_in *client_addr, socklen_t addr_len,
                      int sockfd)
{
  msg_t *request = (msg_t *)buffer;
  uint8_t *response_buffer = malloc (MAX_DHCP_LENGTH);

  // Response will always be the size of the header + any options added later
  size_t response_size = BOOTP_HEADER_SIZE;
  msg_t *response = (msg_t *)response_buffer;
  options_t options = { 0 };

  get_options (buffer + sizeof (msg_t) + 4, buffer + size, &options);

  memcpy (response, request, sizeof (msg_t));
  response->op = BOOTREPLY;

  // DHCP Discover
  if (options.type && *options.type == DHCPDISCOVER)
    {
      ip_assignment_t *assignment = find_assignment (request->chaddr);
      struct in_addr assigned_ip;

      //valid assignment found
      if (assignment)
        {
          assigned_ip = assignment->ip;
        }

      //Check for place to put new assignment
      else if (any_assignments_left ())
        {
          assigned_ip.s_addr = inet_addr (addresses[get_free_assignment ()]);
          assignment = assign_record (request->chaddr, assigned_ip);
        }

      //No space left, NAK
      else
        {
          append_cookie (response_buffer, &response_size);
          uint8_t msg_type = DHCPNAK;
          append_option (response_buffer, &response_size, DHCP_opt_msgtype, 1,
                         &msg_type);

          struct in_addr ip_address;
          inet_pton (AF_INET, "192.168.1.0", &ip_address);
          uint8_t *ip_ptr = (uint8_t *)&ip_address.s_addr;
          response_buffer = append_option (response_buffer, &response_size,
                                           DHCP_opt_sid, 4, (uint8_t *)ip_ptr);
          response_buffer = append_option (response_buffer, &response_size,
                                           DHCP_opt_end, 0, 0);
          sendto (sockfd, response_buffer, response_size, 0,
                  (struct sockaddr *)client_addr, addr_len);
          free (response_buffer);
          
          //free the last released ip if there is one
          if (waiting != -1)
            {
              ip_assignments[waiting].in_use = false;
              waiting = -1;
            }
          return;
        }
      response->yiaddr = assigned_ip;

      // Add options
      response_buffer = append_cookie (response_buffer, &response_size);
      uint8_t msg_type = DHCPOFFER;
      response_buffer = append_option (response_buffer, &response_size,
                                       DHCP_opt_msgtype, 1, &msg_type);

      // Convert the larger int value to network byte order to be passed as an
      // option
      uint32_t lease_time = 2592000;
      lease_time = htonl (lease_time);
      response_buffer
          = append_option (response_buffer, &response_size, DHCP_opt_lease, 4,
                           (uint8_t *)&lease_time);

      struct in_addr ip_address;
      inet_pton (AF_INET, "192.168.1.0", &ip_address);
      uint8_t *ip_ptr = (uint8_t *)&ip_address.s_addr;
      response_buffer = append_option (response_buffer, &response_size,
                                       DHCP_opt_sid, 4, (uint8_t *)ip_ptr);
      response_buffer = append_option (response_buffer, &response_size,
                                       DHCP_opt_end, 0, 0);
      if (waiting != -1)
        {
          ip_assignments[waiting].in_use = false;
          waiting = -1;
        }
      // DHCP Request
    }
  else if (options.type && *options.type == DHCPREQUEST)
    {
      if (options.sid && options.sid->s_addr == inet_addr (DHCP_SERVER_IP))
        {
          ip_assignment_t *assignment = find_assignment (request->chaddr);
          struct in_addr assigned_ip;
          //chaddr previously assigned
          if (assignment && assignment->ip.s_addr == options.request->s_addr)
            {
              response->yiaddr = assignment->ip;
              assigned_ip = assignment->ip;
            }
          
          //new assignment
          else
            {
              assigned_ip.s_addr = inet_addr (addresses[last_index]);
              assignment = assign_record (request->chaddr, assigned_ip);
              last_index = (last_index + 1);
            }
          response->yiaddr = assignment->ip;
          response_buffer = append_cookie (response_buffer, &response_size);
          uint8_t msg_type = DHCPACK;
          response_buffer = append_option (response_buffer, &response_size,
                                           DHCP_opt_msgtype, 1, &msg_type);
          uint32_t lease_time = 2592000;
          lease_time = htonl (lease_time);
          response_buffer
              = append_option (response_buffer, &response_size, DHCP_opt_lease,
                               4, (uint8_t *)&lease_time);
          struct in_addr ip_address;
          inet_pton (AF_INET, "192.168.1.0", &ip_address);
          uint8_t *ip_ptr = (uint8_t *)&ip_address.s_addr;
          response_buffer = append_option (response_buffer, &response_size,
                                           DHCP_opt_sid, 4, (uint8_t *)ip_ptr);
          response_buffer = append_option (response_buffer, &response_size,
                                           DHCP_opt_end, 0, 0);

          
        }

      //DHCPNAK
      else
        {
          append_cookie (response_buffer, &response_size);
          uint8_t msg_type = DHCPNAK;
          append_option (response_buffer, &response_size, DHCP_opt_msgtype, 1,
                         &msg_type);

          struct in_addr ip_address;
          inet_pton (AF_INET, "192.168.1.0", &ip_address);
          uint8_t *ip_ptr = (uint8_t *)&ip_address.s_addr;
          response_buffer = append_option (response_buffer, &response_size,
                                           DHCP_opt_sid, 4, (uint8_t *)ip_ptr);
          response_buffer = append_option (response_buffer, &response_size,
                                           DHCP_opt_end, 0, 0);
        }
    }
  else if (options.type && *options.type == DHCPRELEASE)
    {
      release_record (request->chaddr);
      free (response_buffer);
      return;

    }
  else
    {
      append_cookie (response_buffer, &response_size);
      uint8_t msg_type = DHCPNAK;
      append_option (response_buffer, &response_size, DHCP_opt_msgtype, 1,
                     &msg_type);

      struct in_addr ip_address;
      inet_pton (AF_INET, "192.168.1.0", &ip_address);
      uint8_t *ip_ptr = (uint8_t *)&ip_address.s_addr;
      response_buffer = append_option (response_buffer, &response_size,
                                       DHCP_opt_sid, 4, (uint8_t *)ip_ptr);
      response_buffer = append_option (response_buffer, &response_size,
                                       DHCP_opt_end, 0, 0);
    }
  sendto (sockfd, response_buffer, response_size, 0,
          (struct sockaddr *)client_addr, addr_len);
  free (response_buffer);
}

static void
stop_server (int signum)
{
  server_running = false;
}

void
run_dhcp_server (uint16_t port, int runtime)
{
  int sockfd = create_server_socket (port, runtime);
  struct sockaddr_in client_addr = { 0 };
  socklen_t addr_len = sizeof (client_addr);
  uint8_t buffer[MAX_DHCP_LENGTH] = { 0 };

  // Shut down server on these signals
  signal (SIGINT, stop_server);
  signal (SIGTERM, stop_server);

  time_t start_time, current_time;
  time (&start_time);

  //
  initialize_assignments ();

  while (server_running)
    {
      ssize_t n = recvfrom (sockfd, buffer, MAX_DHCP_LENGTH, 0,
                            (struct sockaddr *)&client_addr, &addr_len);
      if (n > 0)
        {
          process_dhcp_message (buffer, n, &client_addr, addr_len, sockfd);
          // get time of dhcp message being recieved
          time (&start_time);
          // no message recieved
        }
      else if (n < 0)
        {
          time (&current_time);
          // If there has been no messages for longer than the given period,
          // shut down the server.
          if (difftime (current_time, start_time) >= runtime)
            {
              fprintf (stderr,
                       "No messages received for %d seconds. Shutting down "
                       "server.\n",
                       runtime);
              break;
            }
        }
    }
  close (sockfd);
}


void
initialize_assignments ()
{
  for (int i = 0; i < MAX_ASSIGNMENTS; i++)
    {
      ip_assignments[i].in_use = false;
      memset (ip_assignments[i].chaddr, 0, HARDWARE_ADDR_LEN);
      inet_pton (AF_INET, addresses[i], &ip_assignments[i].ip);
    }
}

//Find if chaddr is present in assignment list
ip_assignment_t *
find_assignment (uint8_t *chaddr)
{
  for (int i = 0; i < MAX_ASSIGNMENTS; i++)
    {
      if (ip_assignments[i].in_use
          && memcmp (ip_assignments[i].chaddr, chaddr, HARDWARE_ADDR_LEN) == 0)
        {
          return &ip_assignments[i];
        }
    }
  return NULL;
}

//Assign ip to given chaddr
ip_assignment_t *
assign_record (uint8_t *chaddr, struct in_addr ip)
{
  for (int i = 0; i < MAX_ASSIGNMENTS; i++)
    {
      if (!ip_assignments[i].in_use)
        {
          memcpy (ip_assignments[i].chaddr, chaddr, HARDWARE_ADDR_LEN);
          ip_assignments[i].ip = ip;
          ip_assignments[i].in_use = true;
          return &ip_assignments[i];
        }
    }
  return NULL;
}

//Release the ip assigned to the given chaddr 
void
release_record (uint8_t *chaddr)
{
  for (int i = 0; i < MAX_ASSIGNMENTS; i++)
    {
      if (ip_assignments[i].in_use
          && memcmp (ip_assignments[i].chaddr, chaddr, HARDWARE_ADDR_LEN) == 0)
        {
          ip_assignments[i].in_use = true;
          if (!any_assignments_left ())
            {
              ip_assignments[i].in_use = false;
              waiting = i;
            }
          break;
        }
    }
}

//Check if given chaddr is present in assignments
bool
check_chaddr (uint8_t *chaddr)
{
  for (int i = 0; i < MAX_ASSIGNMENTS; i++)
    {
      if (ip_assignments[i].in_use
          && memcmp (ip_assignments[i].chaddr, chaddr, HARDWARE_ADDR_LEN) == 0)
        {
          return true;
        }
    }
  return false;
}

//Check if all ips are in use
bool
any_assignments_left ()
{
  for (int i = 0; i < MAX_ASSIGNMENTS; i++)
    {
      if (!ip_assignments[i].in_use)
        {
          return true;
        }
    }
  return false;
}

//Get the first free index in assignments
int
get_free_assignment ()
{
  for (int i = 0; i < MAX_ASSIGNMENTS; i++)
    {
      if (!ip_assignments[i].in_use)
        {
          return i;
        }
    }
  return -1;
}