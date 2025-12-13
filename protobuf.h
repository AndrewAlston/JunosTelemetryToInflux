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
#include <pthread.h>

#define TELEMETRY_PORT 2301

struct thread_container;
typedef int(*callback)(struct thread_container *tc);

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

struct thread_container {
    struct gnmi_header hdr;
    struct sockaddr_in server_addr;
    struct container cont;
    struct interfaces interfaces[50];
    char listen_addr[INET_ADDRSTRLEN];
    __u16 listen_port;
    int socket;
    __u64 recurse_array[50]; // Probably way bigger than we need
    __u64 recurse_depth;
    pthread_t thread;
    callback cb;
    bool shutdown;
    struct ifdb *db;
    char error[2048];
    u_char read_buffer[1024*1024];
    unsigned long receive_len;
};


void process_junos_gnmi_header(struct container *cont, struct gnmi_header *hdr);
void dump_gnmi_header(struct gnmi_header *hdr);
void recurse_by_msg_num(struct container *cont, __u64 recurse_array[], int array_point, int recurse_len);
const u_char *get_var_numeric(const u_char *payload, __u64 *output);
const u_char *process_junos_interface(struct container *cont, struct interfaces *iface);
void dump_interface_info(struct interfaces *iface);
struct thread_container *create_listener(char *addr, __u16 port, callback cb);
int proto_add_recurse(struct thread_container *listener, __u64 cp);
int proto_interfaces(struct thread_container *tc);
void *proto_listen(void *thread_container);
#endif //PROTOBUF2_PROTOBUF_H
