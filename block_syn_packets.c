#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>

#define MAX_SYN_PER_CLIENT 10

struct bpf_map_def SEC("maps") syn_count_map = {
    .type = BPF_MAP_HASH,
    .key_size = sizeof(struct __be32),
    .value_size = sizeof(unsigned int),
    .max_entries = 65536,
};

SEC("filter")
int block_excessive_syn_packets(struct __sk_buff *skb) {
    // Parse the Ethernet frame
    struct ethhdr *eth = bpf_hdr_pointer(skb);
    
    // Check if it's an IPv4 packet
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        // Parse the IP header
        struct iphdr *ip = (struct iphdr *)(eth + 1);
        
        // Check if it's a TCP packet
        if (ip->protocol == IPPROTO_TCP) {
            // Parse the TCP header
            struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
            
            // Check if it's a SYN packet (TCP flag's SYN bit set)
            if (tcp->syn) {
                // Get the source IP address
                struct __be32 src_ip = ip->saddr;
                
                // Lookup the SYN count for this client in the map
                unsigned int *count = bpf_map_lookup_elem(&syn_count_map, &src_ip);
                if (!count) {
                    // Client not found, initialize count
                    unsigned int initial_count = 1;
                    bpf_map_update_elem(&syn_count_map, &src_ip, &initial_count, BPF_NOEXIST);
                } else {
                    // Client found, increment count
                    (*count)++;
                    
                    // If the count exceeds the limit, drop the packet
                    if (*count > MAX_SYN_PER_CLIENT) {
                        return XDP_DROP;
                    }
                }
            }
        }
    }
    
    // Allow all other packets
    return XDP_PASS;
}
/* Guy The King */
