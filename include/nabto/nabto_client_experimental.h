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
 * Experimental options for nabto_client_connection_set_options
 */

/**
 * MdnsTimeout timeout in milliseconds from mdns for a connection starts to it
 * is decided to give up and accept that the device is not available locally.
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
/*                                     enum NabtoClientTcpTunnelListenMode
 * listenMode); */

/**
 * sets a certificate for a connection. The certificate is a pem
 * encoded string. This has to be called when the connection is in the setup
 * state ie. before connect is called on the connection.
 *
 * @param connection [in]  The connection
 * @param certificate [in]  The certificate is copied into the connection
 * object.
 * @return NABTO_CLIENT_EC_OK if set.
 *         NABTO_CLIENT_EC_INVALID_STATE if the connection is not in the setup
 * phase
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_set_certificate(NabtoClientConnection *connection,
                                        const char *certificate);

/**
 * WIP. exported error codes as functions such that wrappers that uses p/invoke
 * can access the values.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_OK_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_ABORTED_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_BAD_RESPONSE_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_BAD_REQUEST_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_CLOSED_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_DNS_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_EOF_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_FORBIDDEN_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_FUTURE_NOT_RESOLVED_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_INVALID_ARGUMENT_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_INVALID_STATE_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_NOT_CONNECTED_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_NOT_FOUND_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_NOT_IMPLEMENTED_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_NO_CHANNELS_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_NO_DATA_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_OPERATION_IN_PROGRESS_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_PARSE_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_PORT_IN_USE_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_STOPPED_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_TIMEOUT_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_UNKNOWN_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_NONE_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_NOT_ATTACHED_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_TOKEN_REJECTED_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_COULD_BLOCK_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_UNAUTHORIZED_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_TOO_MANY_REQUESTS_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_UNKNOWN_PRODUCT_ID_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_UNKNOWN_DEVICE_ID_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_UNKNOWN_SERVER_KEY_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_CONNECTION_REFUSED_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_DEVICE_INTERNAL_ERROR_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
NABTO_CLIENT_EC_PRIVILEGED_PORT_value();

/**
 * Helper functions for log messages, this way the layout of the log message
 * struct is not important for consumers of the library.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientLogSeverity NABTO_CLIENT_API
nabto_client_log_message_get_severity(NabtoClientLogMessage *message);
NABTO_CLIENT_DECL_PREFIX const char *NABTO_CLIENT_API
nabto_client_log_message_get_severity_string(NabtoClientLogMessage *message);
NABTO_CLIENT_DECL_PREFIX const char *NABTO_CLIENT_API
nabto_client_log_message_get_module(NabtoClientLogMessage *message);
NABTO_CLIENT_DECL_PREFIX const char *NABTO_CLIENT_API
nabto_client_log_message_get_file(NabtoClientLogMessage *message);
NABTO_CLIENT_DECL_PREFIX int NABTO_CLIENT_API
nabto_client_log_message_get_line(NabtoClientLogMessage *message);
NABTO_CLIENT_DECL_PREFIX const char *NABTO_CLIENT_API
nabto_client_log_message_get_message(NabtoClientLogMessage *message);

/**
 * Make connection event values available as function calls.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientConnectionEvent NABTO_CLIENT_API
NABTO_CLIENT_CONNECTION_EVENT_CONNECTED_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientConnectionEvent NABTO_CLIENT_API
NABTO_CLIENT_CONNECTION_EVENT_CLOSED_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientConnectionEvent NABTO_CLIENT_API
NABTO_CLIENT_CONNECTION_EVENT_CHANNEL_CHANGED_value();
NABTO_CLIENT_DECL_PREFIX NabtoClientConnectionEvent NABTO_CLIENT_API
NABTO_CLIENT_CONNECTION_EVENT_WAITING_FOR_ATTACH_value();

#ifdef __cplusplus
} // extern C
#endif

#endif
