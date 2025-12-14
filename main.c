//
// Created by andrew on 12/10/25.
//
#include <signal.h>
#include "protobuf.h"
#include "influx.h"

const static struct thread_group *tg_global;

void sig_handler(int signal, siginfo_t *siginfo, void *threads)
{
    printf("Thread handler called\n");
    printf("Sending shutdown to %u threads\n", tg_global->num_threads);
    for(int i = 0; i < tg_global->num_threads; i++) {
        tg_global->th[i].tc->shutdown = true;
    }
}

struct thread_container *add_thread(struct thread_group *tg, char *addr, __u16 port, callback cb, char *db_ip, __u16 db_port, char *user, char *pw, char *db)
{
    if(tg->num_threads >= MAX_THREADS) {
        printf("Maximum number of threads exceeded\n");
        return NULL;
    }
    tg->th[tg->num_threads].tc = create_listener(addr, port, cb);
    if(!tg->th[tg->num_threads].tc) {
        printf("Failed allocating for thread container\n");
        return NULL;
    }
    printf("Thread container at %p\n", tg->th[tg->num_threads].tc);
    tg->th[tg->num_threads].tc->db = ifdb_new(db_ip, db_port, user, pw, db);
    if(!tg->th[tg->num_threads].tc->db) {
        printf("Failed allocating for new database connection\n");
        free(tg->th[tg->num_threads].tc);
        return NULL;
    }
    tg->num_threads++;
    return tg->th[tg->num_threads-1].tc;
}

int main() {
    struct sigaction action;
    action.sa_sigaction = sig_handler;
    sigemptyset(&action.sa_mask);
    struct thread_group tg = {0};
    tg_global = &tg; // This is safe in these circumstances
    struct thread_container *tc;

    fflush(stdout);
    tc = add_thread(&tg, NULL, 2301, proto_interfaces, "127.0.0.1", 8086, NULL, NULL, "interface_data_test");
    if(!tc) {
        return EXIT_FAILURE;
    } else {
        proto_add_recurse(tc, 2636);
        proto_add_recurse(tc, 7);
    }
    tc = add_thread(&tg, NULL, 2302, proto_optics, "127.0.0.1", 8086, NULL, NULL, "interface_data_test");
    if(!tc) {
        return EXIT_FAILURE;
    } else {
        proto_add_recurse(tc, 2636);
        proto_add_recurse(tc, 10);
    }
    for(int i = 0; i < tg.num_threads; i++) {
        pthread_create(&tg.th[i].thread, NULL, proto_listen, tg.th[i].tc);
    }
    sigaction(SIGINT, &action, NULL);
    for(int i = 0; i < tg.num_threads; i++) {
        pthread_join(tg.th[i].thread, NULL);
        printf("Thread %u exited\n", i);
    }
    return EXIT_SUCCESS;
}