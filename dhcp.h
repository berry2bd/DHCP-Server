#ifndef __cs361_dhcp_h__
#define __cs361_dhcp_h__

#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>

// For reference, see:
// https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml
// https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml

// Rules for MUST and MUST NOT options, as well as values of BOOTP fields:
// https://www.rfc-editor.org/rfc/rfc2131

// Option interpretations:
// https://www.rfc-editor.org/rfc/rfc2132

#define MAX_DHCP_LENGTH 576
#define BOOTP_HEADER_SIZE 236

// Possible BOOTP message op codes:
#define BOOTREQUEST 1
#define BOOTREPLY 2

// Hardware types (htype) per ARP specifications:
#define ETH 1
#define IEEE802 6
#define ARCNET 7
#define FRAME_RELAY 15
#define FIBRE 18

// Hardware address lengths (hlen) per ARP specifications:
#define ETH_LEN 6
#define IEEE802_LEN 6
#define ARCNET_LEN 1
#define FRAME_LEN 2
#define FIBRE_LEN 3

// For DHCP messages, options must begin with this value:
#define MAGIC_COOKIE 0x63825363

// DHCP Message types
// If client detects offered address in use, MUST send DHCP Decline
// If server detects requested address in use, SHOULD send DHCP NAK
// Client can release its own IP address with DHCP Release
#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define DHCPREQUEST 3
#define DHCPDECLINE 4
#define DHCPACK 5
#define DHCPNAK 6
#define DHCPRELEASE 7

// DHCP Option types
// All messages will use only these message types
#define DHCP_opt_reqip 50
#define DHCP_opt_lease 51
#define DHCP_opt_msgtype 53
#define DHCP_opt_sid 54
#define DHCP_opt_end 255

// BOOTP message type struct. This has an exact size. Add other fields to
// match the structure as defined in RFC 1542 and RFC 2131. This struct
// should NOT include the BOOTP vend field or the DHCP options field.
// (DHCP options replaced BOOTP vend, but does not have a fixed size and
// cannot be declared in a fixed-size struct.)
typedef struct {
  uint8_t op;
  uint8_t htype;
  uint8_t hlen;
  uint8_t hops;   // always 0
  uint32_t xid;   // selected by client/server
  uint16_t secs;  // seconds since DHCP process started
  uint16_t flags; // leading bit is for broadcast...all others must be zero
  struct in_addr ciaddr; // Client IP address
  struct in_addr yiaddr; // "Your" IP address
  struct in_addr siaddr; // Server IP address
  struct in_addr giaddr; // Gateway IP address
  uint8_t chaddr[16];    // Client hardware address 08002B2ED85E
                         // Skip the next 192 bytes...legacy BOOTP support
  uint8_t sname[64];     // Server sending DHCPOFFER or DHCPACK (optional)
  uint8_t file[128];     // Boot file (used in BOOTP from client)
} msg_t;

// Helper struct for gathering and setting DHCP options
//  DHCP: Magic Cookie   0x63825363
typedef struct {
  struct in_addr *request; //  DHCP: [50] Requested IP address
  uint32_t *lease;     //  DHCP: [51] IP Address Lease Time = 16 Days, 0:00:00
  uint8_t *type;       //  DHCP: [53] DHCP Message Type = DHCP ACK, 1+1+1
  struct in_addr *sid; //  DHCP: [54] Server Identifier = 157.54.48.151, 1+1+N
} options_t;
//  DHCP: [255] End (no data)

// Utility function for printing the raw bytes of a packet:
void dump_packet(uint8_t *, size_t);

// Utility functions for getting and freeing the DHCP options
// If you have read in a message from a socket, you can get the
// DHCP options as follows:
//    nbytes = recvfrom (socketfd, buffer, length, 0, &addr, &addrlen);
//    get_options (buffer, buffer + nbytes - 1, &opts);
// If an option is set (e.g., server ID), then options.sid would not be
// NULL.
void free_options (options_t *options);
bool get_options (uint8_t *packet, uint8_t *end, options_t *options);

// Utility functions to append a DHCP cookie and a single DHCP option to the
// end of the packet. In both cases, packet_size is the current length of
// the array and packet points at the start of it. To set an option (e.g.,
// message type), you can call:
//    packet = append_option (packet, &size, DHCP_opt_msgtype, 1, DHCPOFFER);
// The return value is the packet but resized to also store the option. Note
// that the size variable is updated to specify the new length.
uint8_t *append_cookie (uint8_t *packet, size_t *packet_size);
uint8_t *append_option (uint8_t *packet, size_t *packet_size, uint8_t option,
		uint8_t option_size, uint8_t *option_value);

#endif
