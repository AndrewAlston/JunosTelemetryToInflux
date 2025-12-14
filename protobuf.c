//
// Created by andrew on 12/10/25.
//

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
#include "influx.h"
#include "protobuf.h"

void dump_buffer(void *buffer,__u16 size)
{
    char ret_print[18];
    void *cur_pkt = buffer;
    printf ("%06x\t",0);
    fflush (stdout);
    for(int p = 0; p < size; p++)
    {
        if((p + 1) % 16 == 0)
            snprintf (ret_print,10,"\n%06x\t",p + 1);
        printf ("%02x%s",*(uint8_t *) (cur_pkt + p),
                ((p + 1) % 16 == 0)?ret_print:" ");
        fflush (stdout);
    }
    printf ("\n\n");
    fflush (stdout);
}

/* reverse_array_10 is just a basic inline function to reverse an array of 10 bytes
* in order to create a big endian array of 7 bit integers that can be concatenated
*/
static inline void reverse_array_10(__u8 bytes[]) {
    __u8 size = 10;
    for(int i = 0; i < size/2; i++) {
        __u8 temp = bytes[i];
        bytes[i] = bytes[size-1-i];
        bytes[size-1-i] = temp;
    }
}

static __u64 get_var_int(const u_char *data, __u64 *var_int) {
    __u8 bytes[10] = {0};
    __u8 data_count = 0;
    __u8 length = 9;
    __u8 bc = 0;
    *var_int = 0;
    if((data[data_count] & 128) != 128) {
        bytes[length] = data[data_count];
        bc = 1;
    } else {
        while((data[data_count] & 128) == 128) {
            bytes[length--] = data[data_count++];
            bc++;
        }
        bytes[length] = data[data_count];
        bc++;
    }
    reverse_array_10(bytes);
    for(int i = 0; i < 10; i++) {
        __u64 masked_value = bytes[i]&0x7F;
        *var_int |= (masked_value << (i*7));
    }
    return bc;
}

static const u_char *get_double(const u_char *data, void *output) {
    memcpy(output, data, 8);
    return &data[8];
}

static const u_char *get_float(const u_char *data, void *output) {
    memcpy(output, data, 4);
    return &data[4];
}

static const u_char *get_string(const u_char *payload, char *output, int max_len)
{
    __u64 var_int = 0;
    __u64 bc = get_var_int(payload, &var_int);
    memset(output, 0, max_len);
    if(var_int < max_len) {
        memcpy(output, &payload[bc], var_int);
        return &payload[bc+var_int];
    }
    return NULL;
}

const u_char *get_var_numeric(const u_char *payload, __u64 *output)
{
    __u64 bc = get_var_int(payload, output);
    return &payload[bc];
}

const u_char *get_boolean(const u_char *payload, bool *output)
{
    __u64 boolean;
    const u_char *ret = get_var_numeric(payload, &boolean);
    if(boolean) {
        *output = true;
    } else {
        *output = false;
    }
    return ret;
}

void dump_gnmi_header(struct gnmi_header *hdr) {
    printf("Got system ID [%s]\n", hdr->system_id);
    printf("\tComponent ID: %llu\n", hdr->component_id);
    printf("\tSub Component ID: %llu\n", hdr->sub_component_id);
    printf("\tTelemetry Path: %s\n", hdr->path);
    printf("\tSequence Number: %llu\n", hdr->sequence_number);
    printf("\tTimestamp: %llu\n", hdr->timestamp);
    printf("\tVersion [Major:Minor]: %llu:%llu\n", hdr->version_major, hdr->version_minor);
}

/* process_junos_gnmi_header processes the top level GNMI header
* It returns a pointer to the buffer that will refer to the next message */
void process_junos_gnmi_header(struct container *cont, struct gnmi_header *hdr) {
    __u64 eom = 0;
    const u_char *end = cont->ptr+cont->remaining_length;
    while(cont->ptr <= end) {
        cont->ptr = get_var_numeric(cont->ptr, &cont->last_msg);  // Get the message number
        switch(cont->last_msg>>3) {
            case 1: // System ID
                cont->ptr = get_string(cont->ptr, hdr->system_id, 1024);
                break;
            case 2: // Component ID
                cont->ptr = get_var_numeric(cont->ptr, &hdr->component_id);
                break;
            case 3: // Sub Component ID
                cont->ptr = get_var_numeric(cont->ptr, &hdr->sub_component_id);
                break;
            case 4:
                cont->ptr = get_string(cont->ptr, hdr->path, 1024);
                break;
            case 5: // Sequence number
                cont->ptr = get_var_numeric(cont->ptr, &hdr->sequence_number);
                break;
            case 6: // Timestamp
                cont->ptr = get_var_numeric(cont->ptr, &hdr->timestamp);
                break;
            case 7: // Version Major
                cont->ptr = get_var_numeric(cont->ptr, &hdr->version_major);
                break;
            case 8: // Version Minor
                cont->ptr = get_var_numeric(cont->ptr, &hdr->version_minor);
                break;
            case 9: // EOM
                cont->ptr = get_var_numeric(cont->ptr, &eom);
                cont->remaining_length = end-cont->ptr;
                if(eom) {
                    return;
                }
                break;
            case 100: // IETF Sensors - just return this
            case 101: // Junos Specific Sensors - again just return for recursion
                cont->remaining_length = end-cont->ptr;
                return;
            default:
                cont->error = true;
                cont->remaining_length = end-cont->ptr;
                return;
        }
    }
}

const u_char *process_interface_stats(struct container *cont, struct stats *stat) {
    __u64 length = 0;
    // Get the length of the interface statistics message
    cont->ptr = get_var_numeric(cont->ptr, &length);
    const u_char *real_end = cont->ptr + cont->remaining_length;
    const u_char *end = cont->ptr + length;
    while(cont->ptr < end) {
        cont->ptr = get_var_numeric(cont->ptr, &cont->last_msg);
        switch(cont->last_msg>>3) {
            case 1:
                cont->ptr = get_var_numeric(cont->ptr, &stat->if_packets);
                cont->remaining_length = real_end-cont->ptr;
                break;
            case 2:
                cont->ptr = get_var_numeric(cont->ptr, &stat->if_octets);
                cont->remaining_length = real_end-cont->ptr;
                break;
            case 3:
                cont->ptr = get_var_numeric(cont->ptr, &stat->if_ucast_packets);
                cont->remaining_length = real_end-cont->ptr;
                break;
            case 4:
                cont->ptr = get_var_numeric(cont->ptr, &stat->if_mcast_packets);
                cont->remaining_length = real_end-cont->ptr;
            default:
                return cont->ptr;
        }
    }
    return cont->ptr;
}


const u_char *process_junos_interface(struct container *cont, struct interfaces *iface) {
    __u64 int_msg = 0;
    __u64 msg_len = 0;
    cont->ptr = get_var_numeric(cont->ptr, &int_msg);
    cont->ptr = get_var_numeric(cont->ptr, &msg_len);
    const u_char *end = cont->ptr + msg_len;
    __u64 length = 0;
    while(cont->ptr < end) {
        cont->ptr = get_var_numeric(cont->ptr, &cont->last_msg);
        switch(cont->last_msg>>3) {
            case 1:
                cont->ptr = get_string(cont->ptr, iface->name, 1024);
                cont->remaining_length = end-cont->ptr;
                break;
            case 2:
                cont->ptr = get_var_numeric(cont->ptr, &iface->init_time);
                cont->remaining_length = end-cont->ptr;
                break;
            case 3:
                cont->ptr = get_var_numeric(cont->ptr, &iface->snmp_index);
                cont->remaining_length = end-cont->ptr;
                break;
            case 4:
                cont->ptr = get_string(cont->ptr, iface->ae_parent, 1024);
                cont->remaining_length = end-cont->ptr;
                break;
            case 5:
                cont->ptr = process_interface_stats(cont, &iface->ingress);
                break;
            case 6:
                cont->ptr = process_interface_stats(cont, &iface->egress);
                break;
            case 7:
                cont->ptr = get_string(cont->ptr, iface->op_state, 1024);
                break;
            case 8:
                cont->ptr = get_string(cont->ptr, iface->admin_state, 1024);
                break;
            default:
                return NULL;
        }
    }
    return cont->ptr;
}

const u_char *process_optic_lane_stats(struct container *cont, const u_char *end, struct optic_lanes *lane) {
    while(cont->ptr < end) {
        cont->ptr = get_var_numeric(cont->ptr, &cont->last_msg);
        switch(cont->last_msg>>3) {
            case 1:
                cont->ptr = get_var_numeric(cont->ptr, &lane->lane_number);
                break;
            case 2:
                cont->ptr = get_double(cont->ptr, &lane->laser_temp);
                break;
            case 3:
                cont->ptr = get_float(cont->ptr, &lane->laser_output_dbm);
                break;
            case 4:
                cont->ptr = get_float(cont->ptr, &lane->laser_receive_dbm);
                break;
            case 5:
                cont->ptr = get_double(cont->ptr, &lane->laser_bias_current);
                break;
            case 6:
                cont->ptr = get_boolean(cont->ptr, &lane->laser_output_high_alarm);
                break;
            case 7:
                cont->ptr = get_boolean(cont->ptr, &lane->laser_output_low_alarm);
                break;
            case 8:
                cont->ptr = get_boolean(cont->ptr, &lane->laser_output_high_warning);
                break;
            case 9:
                cont->ptr = get_boolean(cont->ptr, &lane->laser_output_low_warning);
                break;
            case 10:
                cont->ptr = get_boolean(cont->ptr, &lane->laser_receive_high_alarm);
                break;
            case 11:
                cont->ptr = get_boolean(cont->ptr, &lane->laser_receive_low_alarm);
                break;
            case 12:
                cont->ptr = get_boolean(cont->ptr, &lane->laser_receive_high_warning);
                break;
            case 13:
                cont->ptr = get_boolean(cont->ptr, &lane->laser_receive_low_warning);
                break;
            case 14:
                cont->ptr = get_boolean(cont->ptr, &lane->laser_bias_high_alarm);
                break;
            case 15:
                cont->ptr = get_boolean(cont->ptr, &lane->laser_bias_low_alarm);
                break;
            case 16:
                cont->ptr = get_boolean(cont->ptr, &lane->laser_bias_high_warning);
                break;
            case 17:
                cont->ptr = get_boolean(cont->ptr, &lane->laser_bias_low_warning);
                break;
            case 18:
                cont->ptr = get_boolean(cont->ptr, &lane->laser_tx_los_alarm);
                break;
            case 19:
                cont->ptr = get_boolean(cont->ptr, &lane->laser_rx_los_alarm);
                break;
            case 20:
                cont->ptr = get_var_numeric(cont->ptr, &lane->fec_corrected_bits);
                break;
            case 21:
                cont->ptr = get_var_numeric(cont->ptr, &lane->fec_uncorrected_bits);
                break;
            default:
                return end;
        }
    }
    return cont->ptr;
}



const u_char *process_optic_stats(struct container *cont, struct optic_stats *stats)
{
    __u64 int_msg = 0;
    __u64 msg_len = 0;
    __u64 boolean;
    const u_char *lane_end = NULL;
    int lane_count = 0;
    cont->ptr = get_var_numeric(cont->ptr, &msg_len);
    const u_char *end = cont->ptr + msg_len;
    cont->ptr = get_var_numeric(cont->ptr, &int_msg);
    cont->ptr = get_var_numeric(cont->ptr, &msg_len);
    while(cont->ptr < end) {
        cont->ptr = get_var_numeric(cont->ptr, &cont->last_msg);
        switch(cont->last_msg>>3) {
            case 1:
                cont->ptr = get_var_numeric(cont->ptr, &stats->optic_type);
                break;
            case 2:
                cont->ptr = get_double(cont->ptr, &stats->module_temp);
                break;
            case 3:
                cont->ptr = get_double(cont->ptr, &stats->temp_high_alarm_thresh);
                break;
            case 4:
                cont->ptr = get_double(cont->ptr, &stats->temp_low_alarm_thresh);
                break;
            case 5:
                cont->ptr = get_double(cont->ptr, &stats->temp_high_warning_thresh);
                break;
            case 6:
                cont->ptr = get_double(cont->ptr, &stats->temp_low_warning_thresh);
                break;
            case 7:
                cont->ptr = get_double(cont->ptr, &stats->laser_output_high_alarm_thresh);
                break;
            case 8:
                cont->ptr = get_double(cont->ptr, &stats->laser_output_low_alarm_thresh);
                break;
            case 9:
                cont->ptr = get_double(cont->ptr, &stats->laser_output_high_warning_thresh);
                break;
            case 10:
                cont->ptr = get_double(cont->ptr, &stats->laser_output_low_warning_thresh);
                break;
            case 11:
                cont->ptr = get_double(cont->ptr, &stats->laser_rx_high_alarm_thresh);
                break;
            case 12:
                cont->ptr = get_double(cont->ptr, &stats->laser_rx_low_alarm_thresh);
                break;
            case 13:
                cont->ptr = get_double(cont->ptr, &stats->laser_rx_high_warning_thresh);
                break;
            case 14:
                cont->ptr = get_double(cont->ptr, &stats->laser_rx_low_warning_thresh);
                break;
            case 15:
                cont->ptr = get_double(cont->ptr, &stats->laser_bias_high_alarm_thresh);
                break;
            case 16:
                cont->ptr = get_double(cont->ptr, &stats->laser_bias_low_alarm_thresh);
                break;
            case 17:
                cont->ptr = get_double(cont->ptr, &stats->laser_bias_high_warning_thresh);
                break;
            case 18:
                cont->ptr = get_double(cont->ptr, &stats->laser_bias_low_warning_thresh);
                break;
            case 19:
                cont->ptr = get_boolean(cont->ptr, &stats->temp_high_alarm);
                break;
            case 20:
                cont->ptr = get_boolean(cont->ptr, &stats->temp_low_alarm);
                break;
            case 21:
                cont->ptr = get_boolean(cont->ptr, &stats->temp_high_warning);
                break;
            case 22:
                cont->ptr = get_boolean(cont->ptr, &stats->temp_low_warning);
                break;
            case 23:
                cont->ptr = get_var_numeric(cont->ptr, &msg_len);
                lane_end = cont->ptr+msg_len;
                while((cont->ptr < lane_end) && (lane_count < 8)) {
                    cont->ptr = process_optic_lane_stats(cont, lane_end, &stats->lanes[lane_count++]);
                }
                stats->num_lanes = lane_count;
                break;
            default:
                printf("Something went wrong, got message %llu\n", cont->last_msg>>3);
                return NULL;
        }
    }
    return end;
}

const u_char *process_junos_optics(struct container *cont, struct optics *optic)
{
    __u64 int_msg = 0;
    __u64 msg_len = 0;
    cont->ptr = get_var_numeric(cont->ptr, &int_msg);
    cont->ptr = get_var_numeric(cont->ptr, &msg_len);
    const u_char *end = cont->ptr + msg_len;
    while(cont->ptr < end) {
        cont->ptr = get_var_numeric(cont->ptr, &cont->last_msg);
        switch(cont->last_msg>>3) {
            case 1:
                cont->ptr = get_string(cont->ptr, optic->name, 1024);
                cont->remaining_length = end-cont->ptr;
                break;
            case 2:
                cont->ptr = get_var_numeric(cont->ptr, &optic->snmp_if_index);
                break;
            case 3:
                cont->ptr = process_optic_stats(cont, &optic->stats);
                break;
            default:
                printf("Got unknown code point\n");
                return NULL;
        }
    }
    return cont->ptr;
}

void dump_interface_info(struct interfaces *iface) {
    printf("Interface name: %s\n", iface->name);
    printf("\tIngress Octets: %llu\n", iface->ingress.if_octets);
    printf("\tIngress Packets: %llu\n", iface->ingress.if_packets);
    printf("\tEgress Octets: %llu\n", iface->egress.if_octets);
    printf("\tEgress Packets: %llu\n", iface->egress.if_packets);
}

struct thread_container *create_listener(char *addr, __u16 port, callback cb)
{
    struct thread_container *tc = calloc(1, sizeof(struct thread_container));
    if(!tc) {
        printf("Failed allocating for listener thread structure\n");
        return NULL;
    }
    printf("Allocated for thread container\n");
    fflush(stdout);
    if(addr != NULL) {
        printf("Got address at %p\n", addr);
        fflush(stdout);
        if((inet_pton(AF_INET, addr, &tc->server_addr.sin_addr)) != 1) {
            printf("Invalid server address specified, listening on all addresses\n");
            tc->server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        }
    } else {
        tc->server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    fflush(stdout);
    tc->server_addr.sin_port = htons(port);
    tc->server_addr.sin_family = AF_INET;
    tc->cb = cb;
    return tc;
}

int proto_add_recurse(struct thread_container *listener, __u64 cp) {
    if(listener->recurse_depth < 49) {
        listener->recurse_array[listener->recurse_depth++] = cp;
        return 0;
    }
    return -1;
}

int proto_interfaces(struct thread_container *tc)
{
    struct interfaces interfaces[255] = {0};
    int i_count = 0;
    process_junos_gnmi_header(&tc->cont, &tc->hdr);
    recurse_by_msg_num(&tc->cont, tc->recurse_array, 0, tc->recurse_depth);
    const u_char *end = tc->cont.ptr + tc->cont.remaining_length;
    while (tc->cont.ptr < end) {
        process_junos_interface(&tc->cont, &interfaces[i_count++]);
    }
    char in_if_packets[4096];
    char in_if_octets[2048];
    char out_if_packets[2048];
    char out_if_octets[2048];
    ifdb_set_tags(tc->db, "interface_data_test=junos");
    ifdb_start_measurement(tc->db, tc->hdr.system_id);
    tc->cont.remaining_length = tc->receive_len;
    tc->cont.ptr = tc->read_buffer;
    process_junos_gnmi_header(&tc->cont, &tc->hdr);
    if (tc->cont.error) {
        snprintf(tc->error, 2048, "Failed processing GNMI Header\n");
        tc->shutdown = true;
        return -1;
    }
    for (int i = 0; i < i_count - 1; i++) {
        if (strlen(interfaces[i].name) < 2048) {
            snprintf(in_if_packets, 4096, "%s:if_packets_ingress", interfaces[i].name);
        }
        snprintf(in_if_octets, 2048, "%s:if_octets_ingress", interfaces[i].name);
        snprintf(out_if_packets, 2048, "%s:if_packets_egress", interfaces[i].name);
        snprintf(out_if_octets, 2048, "%s:if_octets_egress", interfaces[i].name);
        ifdb_add_long(tc->db, in_if_packets, interfaces[i].ingress.if_packets);
        ifdb_add_long(tc->db, in_if_octets, interfaces[i].ingress.if_octets * 8);
        ifdb_add_long(tc->db, out_if_packets, interfaces[i].egress.if_packets);
        ifdb_add_long(tc->db, out_if_octets, interfaces[i].egress.if_octets * 8);
    }
    time_t epoch = tc->hdr.timestamp / 1000;
    struct tm *timeinfo = localtime(&epoch);
    ifdb_end_measurement(tc->db, tc->hdr.timestamp * 1000000);
    ifdb_push(tc->db);
    char time_buf[80];
    strftime(time_buf, 80, "%Y-%m-%d %H:%M:%S", timeinfo);
    printf("Completed push at %s\n", time_buf);
    return 0;
}

int proto_optics(struct thread_container *tc)
{
    struct optics optics[255] = {0};
    struct ifdb *db = tc->db;
    int i_count = 0;
    char optic_temp[4096];
    char lane_temp[4096];
    char lane_output[4096];
    char lane_receive[4096];
    process_junos_gnmi_header(&tc->cont, &tc->hdr);
    recurse_by_msg_num(&tc->cont, tc->recurse_array, 0, tc->recurse_depth);
    const u_char *end = tc->cont.ptr + tc->cont.remaining_length;
    while(tc->cont.ptr < end) {
        process_junos_optics(&tc->cont, &optics[i_count++]);
    }
    ifdb_set_tags(tc->db, "interface_optic_data=junos");
    ifdb_start_measurement(tc->db, tc->hdr.system_id);
    struct optic_stats *stats;
    for(int i = 0; i < i_count-1; i++) {
        snprintf(optic_temp, 4096, "%s_optic_temp", optics[i].name);
        ifdb_add_double(tc->db, optic_temp, optics[i].stats.module_temp);
        for(int l = 0; l < optics[i].stats.num_lanes; l++) {
            stats = &optics[i].stats;
            snprintf(lane_temp, 4096, "%s_lane_%llu_laser_temp", optics[i].name, stats->lanes[l].lane_number);
            snprintf(lane_output, 4096, "%s_lane_%llu_output", optics[i].name, stats->lanes[l].lane_number);
            snprintf(lane_receive, 4096,  "%s_lane_%llu_receive", optics[i].name, stats->lanes[l].lane_number);
            ifdb_add_double(tc->db, lane_temp, stats->lanes[l].laser_temp);
            ifdb_add_double(tc->db, lane_output, stats->lanes[l].laser_output_dbm);
            ifdb_add_double(tc->db, lane_receive, stats->lanes[l].laser_receive_dbm);
        }
    }
    ifdb_end_measurement(tc->db, tc->hdr.timestamp * 1000000);
    ifdb_push(tc->db);
    memset(tc->read_buffer, 0, 1024*1024);
    return 0;
}

void *proto_listen(void *thread_container)
{
    int i_count;
    struct thread_container *tc = thread_container;
    struct ifdb *db = tc->db;
    if(!db) {
        pthread_exit(NULL);
    }
    if((tc->socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(tc->error, 2048, "Failed creating socket\n");
        tc->shutdown = true;
        pthread_exit(NULL);
    }
    if(bind(tc->socket, (struct sockaddr *)&tc->server_addr, sizeof(struct sockaddr_in)) < 0) {
        snprintf(tc->error, 2048, "Failed binding socket\n");
        tc->shutdown = true;
        pthread_exit(NULL);
    }
    while(!tc->shutdown) { // Enter an endless loop reading packets from the UDP stream
        i_count = 0;
        tc->receive_len = recvfrom(tc->socket, tc->read_buffer, (1024*1024)-1, 0, NULL, 0);
        fflush(stdout);
        if (tc->receive_len < 0) {
            snprintf(tc->error, 2048, "Failed receiving data from socket\n");
            close(tc->socket);
            tc->shutdown = true;
            pthread_exit(NULL);
        }
        tc->cont.ptr = tc->read_buffer;
        tc->cont.remaining_length = tc->receive_len;
        if(tc->cb(tc) != 0) {
            snprintf(tc->error, 2048, "Failed processing data\n");
            tc->shutdown = NULL;
            pthread_exit(NULL);
        }
    }
    snprintf(tc->error, 2048, "Thread exit due to shutdown\n");
    pthread_exit(NULL);
}

void recurse_by_msg_num(struct container *cont, __u64 recurse_array[], int array_point, int recurse_len) {
    __u64 msg_length;
    const u_char *end = cont->ptr+cont->remaining_length;
    cont->ptr = get_var_numeric(cont->ptr, &msg_length);
    // We are recursing into sub messages, so we need to grab the length first
    bool recursed = false;
    __u64 length = 0;
    while(cont->ptr < end && array_point < recurse_len) {
        __u64 msg_num;
        cont->ptr = get_var_numeric(cont->ptr, &msg_num);
        if(msg_num>>3 == recurse_array[array_point]) {
            cont->last_msg = msg_num;
            cont->remaining_length = end-cont->ptr;
            recursed = true;
            recurse_by_msg_num(cont, recurse_array, array_point+1, recurse_len);
            if(recursed) {
                return;
            }
        } else if((msg_num&7) == 2) {
            cont->ptr = get_var_numeric(cont->ptr, &length);
            cont->ptr += length;
            cont->remaining_length = end - cont->ptr;
        } else
            return;
    }
}