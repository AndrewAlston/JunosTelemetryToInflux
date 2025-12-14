//
// Created by andrew on 12/12/25.
//
// This is a very basic influx wire protocol implementation.
#include "influx.h"

// Create a new influx database structure
struct ifdb *ifdb_new(const char *ip, const __u16 port, const char *username, const char *password, const char *database)
{
    struct ifdb *db = NULL;
    if(!(db = calloc(1, sizeof(struct ifdb)))) {
        printf("Failed to allocate for influx database structure\n");
        goto cleanup_error;
    }
    if(!inet_pton(AF_INET, ip, &db->host_ip)) {
        printf("Failed to get address from supplied IP %s\n", ip);
        goto cleanup_error;
    }
    if(htons(port) == 0) {
        printf("Invalid port specified\n");
    } else {
        db->host_port = port;
    }
    snprintf(db->hostname, 256, "%s", ip);
    if(username) {
        snprintf(db->username, 256, "%s", username);
    } else {
        memset(db->username, 0, 256);
    }
    if(password) {
        snprintf(db->password, 256, "%s", password);
    } else {
        memset(db->password, 0, 256);
    }
    if(!database)
        goto cleanup_error;
    snprintf(db->database, 256, "%s", database);
    return db;

    cleanup_error:
    if(db) {
        free(db);
    }
    return NULL;
}

void ifdb_set_tags(struct ifdb *db, char *tags)
{
    if(strlen(tags) == 0 || strlen(tags) > 255)
        return;
    memcpy(db->influx_tags, tags, strlen(tags));
}

void ifdb_start_measurement(struct ifdb *db, char *section)
{
    memset(db->buffer, 0, BUFFER_SIZE);
    snprintf(db->buffer, BUFFER_SIZE, "%s,%s ", section, db->influx_tags);
}

void ifdb_end_measurement(struct ifdb *db, __u64 ts)
{
    if(db->buffer[strlen(db->buffer)-1] == ',') {
        db->buffer[strlen(db->buffer)-1] = 0;
    }
    snprintf(&db->buffer[strlen(db->buffer)], REMAINING, " %llu", ts);
    snprintf(&db->buffer[strlen(db->buffer)], REMAINING, "    \n");
}

void ifdb_add_long(struct ifdb *db, char *name, long long value)
{
    snprintf(&db->buffer[strlen(db->buffer)], REMAINING, "%s=%lldi,", name, value);
}

void ifdb_add_double(struct ifdb *db, char *name, double value)
{
    if(isnan(value) || isinf(value)) {
        value = -40;
    }
    snprintf(&db->buffer[strlen(db->buffer)], REMAINING, "%s=%.3f,", name, value);
}

void ifdb_add_string(struct ifdb *db, char *name, char *value)
{
    // Sanitize the input string
    for(int i = 0; i < strlen(value); i++) {
        if(value[i] == '\n' || iscntrl(value[i]))
            value[i] = ' ';
    }
    snprintf(&db->buffer[strlen(db->buffer)], REMAINING, "%s=\"%s\"", name, value);
}

void ifdb_push(struct ifdb *db)
{
    char buf[8192] = {0};
    int code = 0;
    db->serv_addr.sin_family = AF_INET;
    db->serv_addr.sin_addr.s_addr = db->host_ip;
    db->serv_addr.sin_port = htons(db->host_port);
    db->socket = socket(AF_INET, SOCK_STREAM, 0);
    if(db->socket < 0) {
        printf("Failed creating socket\n");
        return;
    }
    if(connect(db->socket, (struct sockaddr *)&db->serv_addr, sizeof(db->serv_addr)) < 0) {
        printf("Failed connecting to server\n");
        return;
    }
    snprintf(buf, 8192, "POST /write?db=%s&u=%s&p=%s HTTP/1.1\r\nHost: %s:%u\r\nContent-Length: %ld\r\n\r\n",
        db->database, db->username, db->password, db->hostname, db->host_port, strlen(db->buffer));
    if((write(db->socket, buf, strlen(buf))) != strlen(buf)) {
        printf("Writing post to socket failed with errno %d\n", errno);
        goto cleanup;
    }
    int sent = 0;
    int total = strlen(db->buffer);
    int ret;
    while(sent < total) {
        ret = write(db->socket, &db->buffer[sent], total-sent);
        if(ret < 0) {
            printf("Error writing to database\n");
            goto cleanup;
        }
        sent = sent + ret;
    }
    if((ret = read(db->socket, db->result, RESULT_SIZE)) > 0) {
        sscanf(db->result, "HTTP/1.1 %d", &code);
        if(code != 204) {
            printf("Failed post, got error return code %d\n", code);
            printf("Attempted to post %s\n", db->buffer);
            printf("Got return %s\n", db->result);
        }
    }
cleanup:
    close(db->socket);
    db->socket = 0;
    memset(db->buffer, 0, BUFFER_SIZE);
}
