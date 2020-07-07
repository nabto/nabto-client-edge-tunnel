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

/*****************
 * mDNS API
 ******************/
typedef struct NabtoClientMdnsResult_ NabtoClientMdnsResult;

/**
 * Init listener as mdns resolver
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_mdns_resolver_init_listener(NabtoClient* client, NabtoClientListener* listener);

/**
 * Wait for a new mdns result.
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_listener_new_mdns_result(NabtoClientListener* listener, NabtoClientFuture* future, NabtoClientMdnsResult** mdnsResult);

/**
 * Experimental: free result object
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_mdns_result_free(NabtoClientMdnsResult* result);

/**
 * Experimental: get IP address of from result object
 * @return String representation of IP address or NULL
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_mdns_result_get_address(NabtoClientMdnsResult* result, const char** address);

/**
 * Experimental: get port of from result object
 * @return port number or 0
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_mdns_result_get_port(NabtoClientMdnsResult* result, uint16_t* port);

/**
 * Experimental: get device ID of from result object
 * @return the device ID or NULL
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_mdns_result_get_device_id(NabtoClientMdnsResult* result, const char** deviceId);

/**
 * Experimental: get product ID of from result object
 * @return the product ID or NULL
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_mdns_result_get_product_id(NabtoClientMdnsResult* result, const char** productId);


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

#ifdef __cplusplus
} // extern C
#endif

#endif
