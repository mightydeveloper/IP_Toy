// arp.c
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

#include <const.h>
#include <errno.h>

#include <arch/mem.h>

#include <kernel/clock.h>
#include <kernel/console.h>
#include <kernel/kmalloc.h>
#include <kernel/semaphore.h>
#include <kernel/task.h>

#include <net/eth.h>
#include <net/ip.h>
#include <net/network.h>
#include <net/rtl8139.h>

#include <net/arp.h>

// sending the ARP packet to the eth layer.
// either reply or request. 
// param ip_to The wanted IP destination address in network format.
// param eth_to The ethernet destination address.
// param arp_op The ARP operation.
//
// return 0 if success. 
// return Negative value if success

int send_arp_packet(in_addr_t ip_to, const uint8_t *eth_to, uint16_t arp_op)
{
    arp_t *packet;
    int total_len; // to be returned if success
    uint8_t *mac_addr;


    packet = kmalloc(sizeof(arp_t));
    if (packet==NULL)
        return(-ENOMEM);

    // create arp header
    packet->arp_hard_type = htons(ARPHRD_ETHER); // ethernet address of the sender.
    packet->arp_proto_type = htons(ETH_FRAME_IP); // format of the protocol address = IP packet type.
    packet->arp_hard_size = ETH_ADDR_LEN; // length of the ethernet address.
    packet->arp_proto_size = sizeof(in_addr_t) // size need not be converted to network order.
    packet->arp_op = htons(arp_op);


    // Copy the MAC address of this host                           
    if ( (mac_addr = get_eth_mac_addr()) == NULL )
        // No such device or address! 
        return(-ENXIO);
    memcpy(packet->arp_eth_source, mac_addr, ETH_ADDR_LEN);
    // Copy the IP address of this host 
    packet->arp_ip_source = get_host_ip();

    // Set the destination MAC address
    memcpy(packet->arp_eth_dest, eth_to, ETH_ADDR_LEN);
    // Set the destination IP 
    packet->arp_ip_dest = ip_to;


    tot_len = send_eth_packet(eth_to, packet, sizeof(arp_t), htons(ETH_FRAME_ARP));  
    #ifdef DEBUG
    kprintf("\n\r%u bytes sent from ethernet layer", tot_len);
    #endif

    kfree(packet);

    if ( tot_len < 0 )
        return(tot_len);

    return(0);
}


int send_eth_packet (const uint8_t *to, const void *data, size_t len, uint16_t type)
{
    uint8_t *packet;
    uint8_t *mac_addr;

    // Analyze the packet length (must be less than ETH_MTU)        //
    // TODO: if the packet length if great than ETH_MTU             //
    // perform a packet fragmentation.                              //
    len = MIN(len, ETH_MTU);

    // Create the ethernet packet                                   //
    packet = kmalloc( MAX(len+ETH_HEAD_LEN, ETH_MIN_LEN) );
    if (!packet)
        return(-ENOMEM);

    // Get the local mac address                                    //
    if ( (mac_addr = get_eth_mac_addr()) == NULL )
        // No such device or address!                           //
        return(-ENXIO);

    // Add the ethernet header to the packet                        //
    memcpy(packet, to, ETH_ADDR_LEN);
    memcpy(packet + ETH_ADDR_LEN, mac_addr, ETH_ADDR_LEN);
    memcpy(packet + 2 * ETH_ADDR_LEN, &type, sizeof(uint16_t));

    // Copy the data into the packet                                //
    memcpy(packet + ETH_HEAD_LEN, data, len);

    // Adjust the packet length including the size of the header    //

    // Auto-pad! Send a minimum payload (another 4 bytes are        //
    // sent automatically for the FCS, totalling to 64 bytes)       //
    // It is the minimum length of an ethernet packet.              //
    while (len < ETH_MIN_LEN)
        packet[len++] = '\0';

    // Go to the physical layer                                     //
    len = send_rtl8139_packet(get_rtl8139_device(), packet, len);

    // Free the memory of the packet                                //
    kfree(packet);

    // Return the bytes transmitted at this level                   //
    return(len);

}


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
