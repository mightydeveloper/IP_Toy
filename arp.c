// arp.cpp
//
// int send_arp_packet(in_addr_t ip_to, const uint8_t *eth_to, uint16_t arp_op)
// 
//
//
// void arp_request(char *ip_dot)
//  send_arp_packet #request
//
//
// void handle_arp_packet(arp_t *packet)
// case ARP_OP_REQUEST:
//   send_arp_packet #reply
// case ARP_OP_REPLY:
//   print block
//
//
//
//

#include <net/arp.h>


void arp_request(char *ip_dot) {
	in_addr_t ip;
	if ( !inet_aton(ip_dot, &ip) ) {
		printf("\n\r%s", "Not valid address!!!");
	}
	while(TRUE) {
		send_arp_packet(ip_addr, eth_bcast, ARP_OP_REQUEST);
		
	}

}

void handle_arp_packet(arp_t *packet) {
	#ifdef DEBUG
    // Dump the packet contents                                     
    printf(
            "\n\rhard_type:%04X proto_type:%04X hard_size:%u"
            "\n\rproto_size:%u op:%04X"
            "\n\rsource=%02x:%02x:%02x:%02x:%02x:%02x (%u.%u.%u.%u)"
            "\n\rdest  =%02x:%02x:%02x:%02x:%02x:%02x (%u.%u.%u.%u)",

            ntohs(packet->arp_hard_type), ntohs(packet->arp_proto_type), packet->arp_hard_size,
            packet->arp_proto_size, ntohs(packet->arp_op),

            packet->arp_eth_source[0], packet->arp_eth_source[1], packet->arp_eth_source[2],
            packet->arp_eth_source[3], packet->arp_eth_source[4], packet->arp_eth_source[5],

            IP_A(ntohl(packet->arp_ip_source)), IP_B(ntohl(packet->arp_ip_source)),
            IP_C(ntohl(packet->arp_ip_source)), IP_D(ntohl(packet->arp_ip_source)),

            packet->arp_eth_dest[0], packet->arp_eth_dest[1], packet->arp_eth_dest[2],
            packet->arp_eth_dest[3], packet->arp_eth_dest[4], packet->arp_eth_dest[5],

            IP_A(ntohl(packet->arp_ip_dest)), IP_B(ntohl(packet->arp_ip_dest)),
            IP_C(ntohl(packet->arp_ip_dest)), IP_D(ntohl(packet->arp_ip_dest))
        );
 
        printf("\n\radding into ARP cache %u.%u.%u.%u",
                IP_A(ntohl(packet->arp_ip_source)),
                IP_B(ntohl(packet->arp_ip_source)),
                IP_C(ntohl(packet->arp_ip_source)),
                IP_D(ntohl(packet->arp_ip_source))
        );
    #endif

    // Identify the ARP operation                                   
    switch( ntohs(packet->arp_op) )
        case ARP_OP_REQUEST:
        #ifdef DEBUG
        printf("\n\rarp who-has %u.%u.%u.%u tell %u.%u.%u.%u (%02x:%02x:%02x:%02x:%02x:%02x)",

                 IP_A(ntohl(packet->arp_ip_dest)), IP_B(ntohl(packet->arp_ip_dest)),
                 IP_C(ntohl(packet->arp_ip_dest)), IP_D(ntohl(packet->arp_ip_dest)),

                 IP_A(ntohl(packet->arp_ip_source)), IP_B(ntohl(packet->arp_ip_source)),
                 IP_C(ntohl(packet->arp_ip_source)), IP_D(ntohl(packet->arp_ip_source)),

                 packet->arp_eth_source[0], packet->arp_eth_source[1], packet->arp_eth_source[2],
                 packet->arp_eth_source[3], packet->arp_eth_source[4], packet->arp_eth_source[5]
        );
        #endif
        // Check if we must reply our address to the sender     
        if (packet->arp_ip_dest == get_host_ip())
        {
            // Send our address resolution reply             
            send_arp_packet(
                    packet->arp_ip_source,
                    packet->arp_eth_source,
                    ARP_OP_REPLY
            );
        }
        break;


        case ARP_OP_REPLY:
        printf("\n\r%s", "received ARP Reply.");
        printf("\n\rarp reply %u.%u.%u.%u is-at %02x:%02x:%02x:%02x:%02x:%02x",

                    IP_A(ntohl(packet->arp_ip_source)), IP_B(ntohl(packet->arp_ip_source)),
                    IP_C(ntohl(packet->arp_ip_source)), IP_D(ntohl(packet->arp_ip_source)),

                    packet->arp_eth_source[0], packet->arp_eth_source[1], packet->arp_eth_source[2],
                    packet->arp_eth_source[3], packet->arp_eth_source[4], packet->arp_eth_source[5]
            );
        break;

        default:
        printf("\n\rarp: message unknown!");
        break;
        }


}