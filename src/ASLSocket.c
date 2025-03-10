#if defined(PAHO_ASL)

#include "ASLSocket.h"
#include "StackTrace.h"
#include "Heap.h"
#include "Thread.h"

#include "SocketBuffer.h"

static List pending_reads = {NULL, NULL, NULL, 0, 0};
extern Sockets mod_s;

/* 1 ~ we are responsible for initializing openssl; 0 ~ openssl init is done externally */
static int handle_openssl_init = 1;
static ssl_mutex_type sslCoreMutex;

/*** FORWARD ***/
void ASLSocket_addPendingRead(SOCKET sock);

int SSL_create_mutex(ssl_mutex_type *mutex)
{
    int rc = 0;

    FUNC_ENTRY;
#if defined(_WIN32) || defined(_WIN64)
    *mutex = CreateMutex(NULL, 0, NULL);
#else
    rc = pthread_mutex_init(mutex, NULL);
#endif
    FUNC_EXIT_RC(rc);
    return rc;
}

int SSL_destroy_mutex(ssl_mutex_type *mutex)
{
    int rc = 0;

    FUNC_ENTRY;
#if defined(_WIN32) || defined(_WIN64)
    rc = CloseHandle(*mutex);
#else
    rc = pthread_mutex_destroy(mutex);
#endif
    FUNC_EXIT_RC(rc);
    return rc;
}

int SSLSocket_initialize(void)
{

    int rc = 0;
    /*int prc;*/

    FUNC_ENTRY;
    // make sure that asl is already initialized, we don't check it here

    // asl module mutex
    SSL_create_mutex(&sslCoreMutex);

    // tls_ex_index is not used, since asl is not intended to use psk
    FUNC_EXIT_RC(rc);

    return rc;
}

void ASLSocket_terminate(void)
{
    // las asl cleanup is called from outer context
    FUNC_ENTRY;
    SSL_destroy_mutex(&sslCoreMutex);
    FUNC_EXIT;
    return;
}

int ASLSocket_setSocketForTLS(networkHandles *net, asl_endpoint_configuration *opts, const char *hostname, size_t hostname_len)
{

    FUNC_ENTRY;
    int rc = 1;
    if (net->ep != NULL || (net->ep = asl_setup_client_endpoint(opts)) != NULL)
    {
        net->ssl = asl_create_session(net->ep, (int)net->socket);
        if (!net->ssl)
        {
            rc = -1;
        }
        // check hostname option ?
    }

    FUNC_EXIT_RC(rc);
    return -1;
}

int SSL_lock_mutex(ssl_mutex_type *mutex)
{
    int rc = -1;

    /* don't add entry/exit trace points, as trace gets lock too, and it might happen quite frequently  */
#if defined(_WIN32) || defined(_WIN64)
    if (WaitForSingleObject(*mutex, INFINITE) != WAIT_FAILED)
#else
    if ((rc = pthread_mutex_lock(mutex)) == 0)
#endif
        rc = 0;

    return rc;
}

int SSL_unlock_mutex(ssl_mutex_type *mutex)
{
    int rc = -1;

    /* don't add entry/exit trace points, as trace gets lock too, and it might happen quite frequently  */
#if defined(_WIN32) || defined(_WIN64)
    if (ReleaseMutex(*mutex) != 0)
#else
    if ((rc = pthread_mutex_unlock(mutex)) == 0)
#endif
        rc = 0;

    return rc;
}

int ASLSocket_getch(asl_session *ssl, SOCKET socket, char *c)
{
    int rc = SOCKET_ERROR;

    FUNC_ENTRY;
    if ((rc = SocketBuffer_getQueuedChar(socket, c)) != SOCKETBUFFER_INTERRUPTED)
        goto exit;

    if ((rc = asl_receive(ssl, c, (size_t)1)) < 0)
    {
        if (rc == ASL_WANT_READ || rc == ASL_WANT_WRITE)
        {
            rc = TCPSOCKET_INTERRUPTED;
            SocketBuffer_interrupted(socket, 0);
        }
    }
    else if (rc == 0)
        rc = SOCKET_ERROR; /* The return value from recv is 0 when the peer has performed an orderly shutdown. */
    else if (rc == 1)
    {
        SocketBuffer_queueChar(socket, *c);
        rc = TCPSOCKET_COMPLETE;
    }
exit:
    FUNC_EXIT_RC(rc);
    return rc;
}

char *ASLSocket_getdata(asl_session *ssl, SOCKET socket, size_t bytes, size_t *actual_len, int *rc)
{
    char *buf;

    FUNC_ENTRY;
    if (bytes == 0)
    {
        buf = SocketBuffer_complete(socket);
        goto exit;
    }

    buf = SocketBuffer_getQueuedData(socket, bytes, actual_len);

    if (*actual_len != bytes)
    {
        if ((*rc = asl_receive(ssl, buf + (*actual_len), (int)(bytes - (*actual_len)))) < 0)
        {
            if (*rc != ASL_WANT_READ && *rc != ASL_WANT_WRITE)
            {
                buf = NULL;
                goto exit;
            }
        }
        else if (*rc == 0) /* rc 0 means the other end closed the socket */
        {
            buf = NULL;
            goto exit;
        }
        else
            *actual_len += *rc;
    }

    if (*actual_len == bytes)
    {
        SocketBuffer_complete(socket);
        if (asl_pending(ssl) > 0)
        {
            ASLSocket_addPendingRead(socket);
        }
    }
    else /* we didn't read the whole packet */
    {
        SocketBuffer_interrupted(socket, *actual_len);
    }
exit:
    FUNC_EXIT;
    return buf;
}

void ASLSocket_addPendingRead(SOCKET sock)
{
    FUNC_ENTRY;
    if (ListFindItem(&pending_reads, &sock, intcompare) == NULL) /* make sure we don't add the same socket twice */
    {
        SOCKET *psock = (SOCKET *)malloc(sizeof(SOCKET));
        if (psock)
        {
            *psock = sock;
            ListAppend(&pending_reads, psock, sizeof(sock));
        }
    }
    else
        Log(TRACE_MIN, -1, "SSLSocket_addPendingRead: socket %d already in the list", sock);

    FUNC_EXIT;
}

int ASLSocket_close(networkHandles *net)
{

    int rc = 1;

    FUNC_ENTRY;
    /* clean up any pending reads for this socket */
    if (pending_reads.count > 0 && ListFindItem(&pending_reads, &net->socket, intcompare))
        ListRemoveItem(&pending_reads, &net->socket, intcompare);

    if (net->ssl)
    {
        asl_close_session(net->ssl);
        asl_free_session(net->ssl);
        net->ssl = NULL;
    }
    asl_free_endpoint(net->ep);
    FUNC_EXIT_RC(rc);
    return rc;
}
int ASLSocket_putdatas(asl_session *ssl, SOCKET socket, char *buf0, size_t buf0len, PacketBuffers bufs)
{
    int rc = 0;
    int i;
    char *ptr;
    iobuf iovec;
    int sslerror;

    FUNC_ENTRY;
    iovec.iov_len = (ULONG)buf0len;
    for (i = 0; i < bufs.count; i++)
        iovec.iov_len += (ULONG)bufs.buflens[i];

    ptr = iovec.iov_base = (char *)malloc(iovec.iov_len);
    if (!ptr)
    {
        rc = PAHO_MEMORY_ERROR;
        goto exit;
    }
    memcpy(ptr, buf0, buf0len);
    ptr += buf0len;
    for (i = 0; i < bufs.count; i++)
    {
        if (bufs.buffers[i] != NULL && bufs.buflens[i] > 0)
        {
            memcpy(ptr, bufs.buffers[i], bufs.buflens[i]);
            ptr += bufs.buflens[i];
        }
    }

    SSL_lock_mutex(&sslCoreMutex);
    if ((rc = asl_send(ssl, iovec.iov_base, iovec.iov_len)) == ASL_SUCCESS)
        rc = TCPSOCKET_COMPLETE;
    else
    {
        sslerror = rc;
        if (sslerror == ASL_WANT_WRITE)
        {
            SOCKET *sockmem = (SOCKET *)malloc(sizeof(SOCKET));
            int free = 1;

            if (!sockmem)
            {
                rc = PAHO_MEMORY_ERROR;
                SSL_unlock_mutex(&sslCoreMutex);
                goto exit;
            }
            Log(TRACE_MIN, -1, "Partial write: incomplete write of %lu bytes on SSL socket %d",
                iovec.iov_len, socket);
            SocketBuffer_pendingWrite(socket, ssl, 1, &iovec, &free, iovec.iov_len, 0);
            *sockmem = socket;
            ListAppend(mod_s.write_pending, sockmem, sizeof(int));
#if defined(USE_SELECT)
            FD_SET(socket, &(mod_s.pending_wset));
#endif
            rc = TCPSOCKET_INTERRUPTED;
        }
        else
            rc = SOCKET_ERROR;
    }
    SSL_unlock_mutex(&sslCoreMutex);

    if (rc != TCPSOCKET_INTERRUPTED)
        free(iovec.iov_base);
    else
    {
        free(buf0);
        for (i = 0; i < bufs.count; ++i)
        {
            if (bufs.frees[i])
            {
                free(bufs.buffers[i]);
                bufs.buffers[i] = NULL;
            }
        }
    }
exit:
    FUNC_EXIT_RC(rc);
    return rc;
}
int ASLSocket_connect(asl_session *ssl, SOCKET sock, const char *hostname, int verify, int (*cb)(const char *str, size_t len, void *u), void *u)
{

    int rc = 0;

    FUNC_ENTRY;

    rc = asl_handshake(ssl);

    if (rc == ASL_WANT_READ || rc == ASL_WANT_WRITE)
        rc = TCPSOCKET_INTERRUPTED;

    FUNC_EXIT_RC(rc);
    return rc;
}


SOCKET ASLSocket_getPendingRead(void)
{
    SOCKET sock = -1;

    if (pending_reads.count > 0)
    {
        sock = *(int *)(pending_reads.first->content);
        ListRemoveHead(&pending_reads);
    }
    return sock;
}

int ASLSocket_continueWrite(pending_writes *pw)
{
    int rc = 0;

    FUNC_ENTRY;
    if ((rc = asl_send(pw->ssl, pw->iovecs[0].iov_base, pw->iovecs[0].iov_len)) == ASL_SUCCESS)
    {
        /* topic and payload buffers are freed elsewhere, when all references to them have been removed */
        free(pw->iovecs[0].iov_base);

        Log(TRACE_MIN, -1, "SSL continueWrite: partial write now complete for socket %d", pw->socket);
        rc = 1;
    }
    else
    {
        if (rc == ASL_WANT_WRITE)
            rc = 0;
    }
    FUNC_EXIT_RC(rc);
    return rc;
}

int ASLSocket_abortWrite(pending_writes *pw)
{
    int rc = 0;

    FUNC_ENTRY;
    free(pw->iovecs[0].iov_base);
    FUNC_EXIT_RC(rc);
    return rc;
}

#endif // PAHO_ASL