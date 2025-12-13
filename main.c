//
// Created by andrew on 12/10/25.
//
#include <signal.h>
#include "protobuf.h"
#include "influx.h"

static volatile sig_atomic_t running = 1;

static void sig_handler(int _)
{
    (void)_;
    running = 0;
}

int main() {
    struct gnmi_header hdr = {0}; // Top level GNMI Header
    struct sockaddr_in server_addr = {0}; // Server listen struct
    struct container cont = {0}; // Container for our buffer pointer
    struct interfaces interfaces[50];
    pthread_t thread;

    printf("Creating thread container...\n");
    fflush(stdout);
    struct thread_container *tc = create_listener(NULL, 2301, proto_interfaces);
    if(!tc) {
        printf("Failed to create thread listener\n");
        return EXIT_FAILURE;
    }
    printf("Thread container created, creating influx db connection\n");
    fflush(stdout);
    tc->db = ifdb_new("127.0.0.1", 8086, NULL, NULL, "interface_data_test");
    proto_add_recurse(tc, 2636);
    proto_add_recurse(tc, 7);
    printf("DB connection created\n");
    fflush(stdout);
    if(!tc->db) {
        printf("Failed creating database structure\n");
        return -1;
    }
    signal(SIGINT, sig_handler);
    pthread_create(&thread, NULL, proto_listen, tc);
    while(running) {
        sleep(1);
    }
    printf("Shutting down\n");
    tc->shutdown = 1;
    sleep(1);
    return EXIT_SUCCESS;
}