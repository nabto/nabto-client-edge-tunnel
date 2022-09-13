#ifndef NABTO_CLIENT_EXPERIMENTAL_H
#define NABTO_CLIENT_EXPERIMENTAL_H

#include "nabto_client.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Experimental header. Functions here are all experimental. They
 * should be used with caution and can be changed in future releases
 * without notice.
 */



/**
 * TCP Tunel experimental features
 */


/* enum NabtoClientTcpTunnelListenMode { */
/*     LISTEN_MODE_LOCALHOST, */
/*     LISTEN_MODE_ANY */
/* }; */

/**
 * NOT IMPLEMENTED. TBD.
 * Set the listen mode for the tcp listener. Default is to only listen
 * on localhost / loopback such that only applications on the local
 * machine can connect to the tcp listener. Anyone on the local system
 * can connect to the tcp listener. Some form of application layer
 * authentication needs to be present on the tcp connection if the
 * system is multi tenant or not completely trusted or if the
 * application is not run in isolation.
 */
/* NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API */
/* nabto_client_tcp_tunnel_listen_mode(NabtoClientTcpTunnel* tunnel, */
/*                                     enum NabtoClientTcpTunnelListenMode listenMode); */

/**
 * sets a certificate for a connection. The certificate is a pem
 * encoded string. This has to be called when the connection is in the setup state ie. before connect is called on the connection.
 *
 * @param connection [in]  The connection
 * @param certificate [in]  The certificate is copied into the connection object.
 * @return NABTO_CLIENT_EC_OK if set.
 *         NABTO_CLIENT_EC_INVALID_STATE if the connection is not in the setup phase
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_set_certificate(NabtoClientConnection* connection, const char* certificate);

#ifdef __cplusplus
} // extern C
#endif

#endif
