//
// Created by andrew on 12/10/25.
//
#include "protobuf.h"
#include "influx.h"

int main() {
    struct gnmi_header hdr = {0}; // Top level GNMI Header
    struct sockaddr_in server_addr = {0}; // Server listen struct
    struct container cont = {0}; // Container for our buffer pointer
    struct interfaces interfaces[50];
    int i_count = 0;
    u_char buffer[9000] = {0}; // UDP Packet read buffer
    // Recurse through the protobuf messages to tree point 2636, and then to point 7
    __u64 recurse_array[] = { 2636, 7};
    int fd; // File descriptor for the socket
    long receive_len;
    __u64 msg_len = 0;
    if((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("Failed to open UDP socket\n");
        return -1;
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);    // Listen on any address
    server_addr.sin_port = htons(TELEMETRY_PORT);
    if(bind(fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in)) < 0) {
        printf("Failed to bind UDP socket\n");
        return -1;
    }
    struct ifdb *db = ifdb_new("127.0.0.1", 8086, NULL, NULL, "interface_data_test");
    if(!db) {
        printf("Failed creating database structure\n");
        return -1;
    }

    for(;;) { // Enter an endless loop reading packets from the UDP stream
        i_count = 0;
        receive_len = recvfrom(fd, buffer, sizeof(buffer)-1, 0, NULL, 0);
        printf("Got packet with length %lu\n", receive_len);
        if(receive_len < 0) {
            printf("Failed receiving data\n");
            close(fd);
            return -1;
        }
        cont.remaining_length = receive_len;
        cont.ptr = buffer;
        process_junos_gnmi_header(&cont, &hdr);
        if(cont.error) {
            printf("Failed processing GNMI Header\n");
        } else {
            dump_gnmi_header(&hdr);
        }
        recurse_by_msg_num(&cont, recurse_array, 0, 2);
        const u_char *end = cont.ptr + cont.remaining_length;
        while(cont.ptr < end) {
            process_junos_interface(&cont, &interfaces[i_count++]);
        }
        char in_if_packets[4096];
        char in_if_octets[2048];
        char out_if_packets[2048];
        char out_if_octets[2048];
        ifdb_set_tags(db, "interface_data_test=junos");
        ifdb_start_measurement(db, hdr.system_id);
        for(int i = 0; i < i_count-1; i++) {
            if(strlen(interfaces[i].name) < 2048) {
                snprintf(in_if_packets, 4096, "%s:if_packets_ingress", interfaces[i].name);
            }
            snprintf(in_if_octets, 2048, "%s:if_octets_ingress", interfaces[i].name);
            snprintf(out_if_packets, 2048, "%s:if_packets_egress", interfaces[i].name);
            snprintf(out_if_octets, 2048, "%s:if_octets_egress", interfaces[i].name);
            ifdb_add_long(db, in_if_packets, interfaces[i].ingress.if_packets);
            ifdb_add_long(db, in_if_octets, interfaces[i].ingress.if_octets*8);
            ifdb_add_long(db, out_if_packets, interfaces[i].egress.if_packets);
            ifdb_add_long(db, out_if_octets, interfaces[i].egress.if_octets*8);
        }
        time_t epoch = hdr.timestamp/1000;
        struct tm *timeinfo = localtime(&epoch);
        char time_buf[80];
        strftime(time_buf, 80, "%Y-%m-%d %H:%M:%S", timeinfo);
        ifdb_end_measurement(db, hdr.timestamp*1000000);
        ifdb_push(db);
        printf("Pushed data at %s\n", time_buf);
    }
}