//
// Created by andrew on 12/10/25.
//

#ifndef PROTOBUF2_PROTOBUF_H
#define PROTOBUF2_PROTOBUF_H

#include <stdio.h>
#include <strings.h>
#include <pcap.h>
#include <asm-generic/types.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <locale.h>
#include <stdbool.h>
#include <unistd.h>

#define TELEMETRY_PORT 2301

struct container {
    __u64 last_msg; // The encoded last message / message type we received
    const u_char *ptr; // A pointer to the current position of the packet
    __u64 remaining_length; // Remaining length of the packet
    bool error; // Return this set if we hit an error
};

struct stats {
    __u64 if_packets;
    __u64 if_octets;
    __u64 if_ucast_packets;
    __u64 if_mcast_packets;
};

struct interfaces {
    char name[1024];
    __u64 init_time;
    __u64 snmp_index;
    char ae_parent[1024];
    struct stats ingress;
    struct stats egress;
    char op_state[1024];
    char admin_state[1024];
};

struct gnmi_header {
    char system_id[1024];
    __u64 component_id;
    __u64 sub_component_id;
    char path[2048];
    __u64 sequence_number;
    __u64 timestamp;
    __u64 version_major;
    __u64 version_minor;
};

void process_junos_gnmi_header(struct container *cont, struct gnmi_header *hdr);
void dump_gnmi_header(struct gnmi_header *hdr);
void recurse_by_msg_num(struct container *cont, __u64 recurse_array[], int array_point, int recurse_len);
const u_char *get_var_numeric(const u_char *payload, __u64 *output);
const u_char *process_junos_interface(struct container *cont, struct interfaces *iface);
void dump_interface_info(struct interfaces *iface);
#endif //PROTOBUF2_PROTOBUF_H
