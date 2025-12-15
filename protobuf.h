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
    char description[2048];
    __u64 last_change;
    __u64 high_speed;
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
    struct sockaddr_in client_addr;
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
    ssize_t receive_len;
};

#define MAX_THREADS 50
struct threads {
    pthread_t thread;
    struct thread_container *tc;
};

struct thread_group {
    struct threads th [50];
    int num_threads;
};

struct optic_lanes {
    __u64 lane_number;  // 1
    double laser_temp; // 2
    float laser_output_dbm; // 3
    float laser_receive_dbm; // 4
    double laser_bias_current; // 5
    bool laser_output_high_alarm; // 6
    bool laser_output_low_alarm; // 7
    bool laser_output_high_warning; // 8
    bool laser_output_low_warning; // 9
    bool laser_receive_high_alarm; // 10
    bool laser_receive_low_alarm; // 11
    bool laser_receive_high_warning; // 12
    bool laser_receive_low_warning; // 13
    bool laser_bias_high_alarm; // 14
    bool laser_bias_low_alarm; // 15
    bool laser_bias_high_warning; // 16
    bool laser_bias_low_warning; // 17
    bool laser_tx_los_alarm; // 18
    bool laser_rx_los_alarm; // 19
    __u64 fec_corrected_bits; // 20
    __u64 fec_uncorrected_bits; // 21

};

struct optic_stats {
    __u64 optic_type;
    double module_temp;
    double temp_high_alarm_thresh;
    double temp_low_alarm_thresh;
    double temp_high_warning_thresh;
    double temp_low_warning_thresh;
    double laser_output_high_alarm_thresh;
    double laser_output_low_alarm_thresh;
    double laser_output_high_warning_thresh;
    double laser_output_low_warning_thresh;
    double laser_rx_high_alarm_thresh;
    double laser_rx_low_alarm_thresh;
    double laser_rx_high_warning_thresh;
    double laser_rx_low_warning_thresh;
    double laser_bias_high_alarm_thresh;
    double laser_bias_low_alarm_thresh;
    double laser_bias_high_warning_thresh;
    double laser_bias_low_warning_thresh;
    bool temp_high_alarm;
    bool temp_low_alarm;
    bool temp_high_warning;
    bool temp_low_warning;
    struct optic_lanes lanes[8]; // Realistically we shouldnt have more than 8 lanes
    __u8 num_lanes;
};

struct optics {
    char name[1024];
    __u64 snmp_if_index;
    struct optic_stats stats;

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
int proto_optics(struct thread_container *tc);
#endif //PROTOBUF2_PROTOBUF_H
