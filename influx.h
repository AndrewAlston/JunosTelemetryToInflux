//
// Created by andrew on 12/12/25.
//

#ifndef PROTOBUF2_INFLUX_H
#define PROTOBUF2_INFLUX_H

#include "protobuf.h"
#include <asm-generic/types.h>
#include <ctype.h>
#include <errno.h>

#define BUFFER_SIZE (4096*4096)
#define REMAINING ({ BUFFER_SIZE - strlen(db->buffer); })
#define RESULT_SIZE 8192

struct ifdb {
    char hostname[256];
    __u32 host_ip;
    __u16 host_port;
    char buffer[BUFFER_SIZE];
    char username[256];
    char password[256];
    char influx_tags[256];
    char database[256];
    char result[8192];
    int socket;
    struct sockaddr_in serv_addr;
};

struct ifdb *ifdb_new(const char *ip, __u16 port, const char *username, const char *password, const char *database);
void ifdb_set_tags(struct ifdb *db, char *tags);
void ifdb_start_measurement(struct ifdb *db, char *section);
void ifdb_end_measurement(struct ifdb *db, __u64 ts);
void ifdb_add_long(struct ifdb *db, char *name, long long value);
void ifdb_add_double(struct ifdb *db, char *name, double value);
void ifdb_add_string(struct ifdb *db, char *name, char *value);
void ifdb_push(struct ifdb *db);


#endif //PROTOBUF2_INFLUX_H
