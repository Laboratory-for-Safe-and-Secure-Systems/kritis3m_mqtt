#ifndef ASLSOCKET_H
#define ASLSOCKET_H

#if defined(PAHO_ASL)

#if defined(_WIN32) || defined(_WIN64)
#define ssl_mutex_type HANDLE
#else
#include <pthread.h>
#include <semaphore.h>
#define ssl_mutex_type pthread_mutex_t
#endif

#include "asl.h"
#include "SocketBuffer.h"
#include "Clients.h"

#define URI_SSL "ssl://"
#define URI_MQTTS "mqtts://"

/** if we should handle openssl initialization (bool_value == 1) or depend on it to be initalized externally (bool_value == 0) */
void SSLSocket_handleOpensslInit(int bool_value);

int ASLSocket_initialize(void);
void ASLSocket_terminate(void);
int ASLSocket_setSocketForTLS(networkHandles *net, asl_endpoint_configuration *ep_config, const char *hostname, size_t hostname_len);

int ASLSocket_getch(asl_session *ssl, SOCKET socket, char *c);
char *ASLSocket_getdata(asl_session *ssl, SOCKET socket, size_t bytes, size_t *actual_len, int *rc);

int ASLSocket_close(networkHandles *net);
int ASLSocket_putdatas(asl_session *ssl, SOCKET socket, char *buf0, size_t buf0len, PacketBuffers bufs);
int ASLSocket_connect(asl_session *ssl, SOCKET sock, const char *hostname, int verify, int (*cb)(const char *str, size_t len, void *u), void *u);

SOCKET ASLSocket_getPendingRead(void);
int ASLSocket_continueWrite(pending_writes *pw);
int ASLSocket_abortWrite(pending_writes *pw);

#endif

#endif
