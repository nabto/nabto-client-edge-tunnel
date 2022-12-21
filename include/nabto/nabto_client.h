#ifndef NABTO_CLIENT_API_H
#define NABTO_CLIENT_API_H

/*
 * Nabto Client C API.
 *
 * Nabto provides a platform for connecting applications with
 * devices. The platform consists of three major parts.
 *
 * Vocabulary:
 *
 * Client: Clients are often apps where this library is embedded
 * inside. The clients can make connections to devices. Using the
 * servers.
 *
 * Device: Devices is often embedded devices running the Nabto
 * Embedded SDK, e.g. a heating control system or an ip camera.
 *
 * Server: Servers are hosted in datacenters and makes it possible to
 * create connections between the clients and devices.
 *
 * Connections: The connection is the connection from this client to a device. The connection is end
 * to end encrypted. The connection can use several channels to establish the connection to the
 * device. There are three classes of channels.
 *
 * Local channels: These are made using mdns discovery of the
 * device. If the device is found on the local network the ips and
 * ports it annunces is used to make the connection.
 *
 * Remote channels: These are made using a central service, which the
 * devices is also connected to. The client uses the central
 * mediation service to create an initial remote connection to the
 * device. When the remote connection is established the client and
 * device tries to upgrade the connection to a p2p connection using
 * UDP holepunching.
 *
 * Direct candidate channels: A direct candidate channel is a channel
 * which the user of this api adds through the direct candidates
 * api. This is useful if the device is found locally or remotely
 * using some other mechanism than the built in local and remote
 * channels.
 */


#if defined(_WIN32)
#  define NABTO_CLIENT_API __stdcall
#  if defined(NABTO_CLIENT_WIN32_API_STATIC)
#    define NABTO_CLIENT_DECL_PREFIX
#  elif defined(NABTO_CLIENT_API_EXPORTS)
#    define NABTO_CLIENT_DECL_PREFIX __declspec(dllexport)
#  else
#    define NABTO_CLIENT_DECL_PREFIX __declspec(dllimport)
#  endif
#else
#  define NABTO_CLIENT_API
#  if defined(NABTO_CLIENT_API_EXPORTS)
#    define NABTO_CLIENT_DECL_PREFIX __attribute__((visibility("default")))
#  else
#    define NABTO_CLIENT_DECL_PREFIX
#  endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>

typedef uint64_t nabto_client_uint64_t;
typedef nabto_client_uint64_t nabto_client_duration_t;

typedef enum NabtoClientLogSeverity_ {
    NABTO_CLIENT_LOG_SEVERITY_ERROR,
    NABTO_CLIENT_LOG_SEVERITY_WARN,
    NABTO_CLIENT_LOG_SEVERITY_INFO,
    NABTO_CLIENT_LOG_SEVERITY_DEBUG,
    NABTO_CLIENT_LOG_SEVERITY_TRACE,
} NabtoClientLogSeverity;

/**
 * Some commonly used CoAP content formats. These are assigned by iana.
 * https://www.iana.org/assignments/core-parameters/core-parameters.xhtml
 */
typedef enum {
    NABTO_CLIENT_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8 = 0,
    NABTO_CLIENT_COAP_CONTENT_FORMAT_APPLICATION_LINK_FORMAT = 40,
    NABTO_CLIENT_COAP_CONTENT_FORMAT_XML = 41,
    NABTO_CLIENT_COAP_CONTENT_FORMAT_APPLICATION_OCTET_STREAM = 42,
    NABTO_CLIENT_COAP_CONTENT_FORMAT_APPLICATION_JSON = 50,
    NABTO_CLIENT_COAP_CONTENT_FORMAT_APPLICATION_CBOR = 60
} NabtoClientCoapContentFormat;

/**
 * NabtoClientError
 *
 * Error codes return by api functions.
 */
typedef int NabtoClientError;

NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_OK;
/*
 * @deprecated
 * NABTO_CLIENT_EC_ABORTED is now synonym for NABTO_CLIENT_EC_STOPPED.
 */
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_ABORTED;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_BAD_RESPONSE;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_BAD_REQUEST;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_CLOSED;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_DNS;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_EOF;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_FORBIDDEN;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_FUTURE_NOT_RESOLVED;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_INVALID_ARGUMENT;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_INVALID_STATE;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_NOT_CONNECTED;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_NOT_FOUND;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_NOT_IMPLEMENTED;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_NO_CHANNELS;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_NO_DATA;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_OPERATION_IN_PROGRESS;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_PARSE;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_PORT_IN_USE;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_STOPPED;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_TIMEOUT;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_UNKNOWN;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_NONE;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_NOT_ATTACHED;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_TOKEN_REJECTED;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_COULD_BLOCK;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_UNAUTHORIZED;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_TOO_MANY_REQUESTS;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_UNKNOWN_PRODUCT_ID;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_UNKNOWN_DEVICE_ID;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_UNKNOWN_SERVER_KEY;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_CONNECTION_REFUSED;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_PRIVILEGED_PORT;

/*
 * @Deprecated
 *
 * NABTO_CLIENT_EC_INTERNAL_ERROR is renamed to
 * NABTO_CLIENT_EC_DEVICE_INTERNAL_ERROR signaling that the internal error is
 * coming from the device
 */
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_INTERNAL_ERROR;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientError NABTO_CLIENT_EC_DEVICE_INTERNAL_ERROR;





/**
 * Type of connection.
 */
typedef enum NabtoClientConnectionType_ {
    NABTO_CLIENT_CONNECTION_TYPE_RELAY, // The connection is a relay connection
    NABTO_CLIENT_CONNECTION_TYPE_DIRECT // The connection is a direct connection. The underlying channel is either p2p, local or a direct candidate.
} NabtoClientConnectionType;

/**
 * A coap resource is a context for a coap request and response.
 */
typedef struct NabtoClientCoap_ NabtoClientCoap;

/**
 * A NabtoClient is a context holding common state across
 * connections.
 */
typedef struct NabtoClient_ NabtoClient;

/**
 * A connection object is the representation of a connection between a client
 * and a specific device.  The connection contains options to specify
 * how the connect should happen. After the connect has been called on
 * a connection most of the options can no longer be set.
 */
typedef struct NabtoClientConnection_ NabtoClientConnection;

/**
 * A nabto stream is a bidirectional stream of bytes on top of a nabto connection
 */
typedef struct NabtoClientStream_ NabtoClientStream;

/**
 * A Nabto future is used for all async funtions, we deliver some
 * functions such that they can be handled blocking, but for an event
 * driven architecture, the future must be handled using the
 * callbacks. It's up to the application to make the machinery that
 * handles the callbacks.
 */
typedef struct NabtoClientFuture_ NabtoClientFuture;

/**
 * A Listener is used to get recurring events on a resource.
 */
typedef struct NabtoClientListener_ NabtoClientListener;


/**
 * Callback from a future when it is resolved.
 */
typedef void (*NabtoClientFutureCallback)(NabtoClientFuture* future, NabtoClientError error, void* data);

/* TODO nabtodoc
 * This struct contains the data to be logged.
 */
typedef struct NabtoClientLogMessage_ {
    NabtoClientLogSeverity severity;
    const char* severityString;
    const char* module; /* can be NULL */
    const char* file; /* can be NULL */
    int line; /* can be 0 */
    const char* message; /* the message null terminated utf-8 */
} NabtoClientLogMessage;

/**
 * Callback from the NabtoClient when a new log message is available.
 */
typedef void (*NabtoClientLogCallback)(const NabtoClientLogMessage* message, void* data);

/**********************
 * Client Context API
 **********************/

/**
 * @intro Client Context
 *
 * The Context API manages the context where all connections live.
 */

/**
 * Create a context.
 *
 * @return A new Nabto Client Context
 */
NABTO_CLIENT_DECL_PREFIX NabtoClient* NABTO_CLIENT_API
nabto_client_new();

/**
 * @deprecated use nabto_client_free2()
 *
 * Free a context.
 *
 * If stop has not been called prior to this function, free can block
 * until all io operations has finished.
 *
 * @param context [in]  The context
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_free(NabtoClient* context);

/**
 * Free a context.
 *
 * If stop has not been called prior to this function, free can block
 * until all io operations has finished.
 *
 * @param context [in]  The context
 * @retval NABTO_CLIENT_EC_OK iff the context is freed
 * @retval NABTO_CLIENT_EC_COULD_BLOCK if the free is called from a callback.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_free2(NabtoClient* context);



/**
 * @deprecated use nabto_client_stop2()
 *
 * Stop a client context.
 *
 * This function is blocking until no more callbacks is in progress on the event
 * or callback queues.
 * @param context [in]  The NabtoClient to stop
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_stop(NabtoClient* context);

/**
 * Stop a client context.
 *
 * This function blocks until all callbacks are handled and the system has been
 * stopped. Once stop has been called no more callbacks can be initiated and no
 * more actions such as connects can be made. After stop has returned it is
 * still possible to free objects.
 *
 * @param context [in]  The NabtoClient to stop.
 * @retval NABTO_CLIENT_EC_COULD_BLOCK if called from a callback.
 * @retval NABTO_CLIENT_EC_OK iff the system was stopped.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_stop2(NabtoClient* context);

/**
 * Create a private key and return the private key as a pem encoded
 * string. The returned pointer should be freed with
 * nabto_client_string_free. This is a utility function and does not
 * alter the state of the client object.
 *
 * @param context [in]  The context
 * @param privateKey [out]  The resulting private key.
 * @retval NABTO_CLIENT_EC_OK iff the private key is created and available in privateKey.
 * @retval NABTO_CLIENT_EC_UNKNOWN if the key could not be created for some unknown reason.
 *                                 This should never happen. If the future has some more specific
 *                                 error cases which can be acted upon programmatically then they
 *                                 will be added as error codes.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_create_private_key(NabtoClient* context, char** privateKey);

/******************
 * Connection API *
 ******************/

/**
 * @intro Connection
 *
 * The connection API is used to establish a connection to a specific device. A
 * connection object is first created with `nabto_client_connection_new` and
 * configured with the various `nabto_client_connection_set_` functions,
 * specifying how the connection should be established. Once configured, the
 * connection can be established with `nabto_client_connection_connect`.
 */

/**
 * Create a new nabto connection
 *
 * @param context [in]  The client context.
 * @return A new connection or NULL.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientConnection* NABTO_CLIENT_API
nabto_client_connection_new(NabtoClient* context);

/**
 * Free a connection
 *
 * @param connection [in] the connection to be freed.
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_connection_free(NabtoClientConnection* connection);

/**
 * Stop outstanding connect or close on a connection.
 *
 * After stop has been called the connection should not be used
 * any more.
 *
 * Stop can be used if the user cancels a connect/close request.
 *
 * @param connection [in]  The connection.
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_connection_stop(NabtoClientConnection* connection);

/**
 * Set options with a json encoded document.
 *
 * There are two ways to setup connection options. Either use the
 * unified json interface which has all possible options, or use the
 * individual set functions for the most commonly used connection
 * options.
 *
 * This functions can be used to set connection parameters in
 * bulk or as indidual parameters.
 *
 * ```
 * Connection options.
 * - PrivateKey: string pem encoded EC private key
 * - ProductId: string
 * - DeviceId: string
 * - ServerUrl: string
 * - ServerKey: string
 * - ServerJwtToken: string
 * - ServerConnectToken: string
 * - AppName: string
 * - AppVersion: string
 * ```
 *
 * Control the keep alive settings for the connection between
 * the client and the device.
 * ```
 * - KeepAliveInterval: unsigned integer in milliseconds, default 30000
 * - KeepAliveRetryInterval: unsigned integer in milliseconds, default 2000
 * - KeepAliveMaxRetries: unsigned integer default 15
 * ```
 *
 * Set the timeout for getting the first DTLS packet back from the device. This is used to make a
 * connection attempt fail faster if a route to the device is believed to be open, when in fact it
 * is not. Eg. if the device lost its connection to the Nabto Server, but the server has yet to
 * detect the disconnect.
 * ```
 * - DtlsHelloTimeout: unsigned integer in milliseconds, default 10000
 * ```
 *
 * Control which connections features to use.
 *
 * Set local to enable/disable local connections
 * ```
 * - Local: (true|false)
 * ```
 *
 * Enable/disable connections mediated through a cloud server.
 * ```
 * - Remote: (true|false)
 * ```
 *
 * Enable/disable udp holepunching on remote connections.
 * ```
 * - Rendezvous: (true|false)
 * ```
 *
 * Use pre 5.2 local discovery.  Before 5.2 devices is located by
 * doing a mDNS scan for all the devices. After 5.2 including 5.2,
 * devices are located by a device specific mDNS subtype. Set this
 * option to true to use the pre 5.2 way of locating devices.
 * ```
 * - ScanLocalConnect: (true|false)
 * ```
 *
 * Example - force local connections:
 *
 * ```
 * std::string options = R"(
 * {
 *   "Remote": false
 * }
 * )";
 * nabto_client_connection_set_options(connection, options.c_str());
 * ```
 *
 * Example - setup a connection:
 *
 * ```
 * std::string options = R"(
 * {
 *   "ProductId": "pr-12345678",
 *   "DeviceId": "de-12345678",
 *   "ServerUrl": "https://pr-12345678.clients.nabto.net",
 *   "ServerKey": "sk-12345678123456781234567812345678"
 * }
 * )";
 * nabto_client_connection_set_options(connection, options.c_str());
 * ```
 *
 * This function can only be invoked before the connection
 * establishment is started.
 *
 * @param connection [in] The connection
 * @param json [in]  Options formatted as json
 * @retval NABTO_CLIENT_EC_OK  iff the json document is parsed and understood.
 * @retval NABTO_CLIENT_EC_INVALID_ARGUMENT if the json is not understood. See error log for more details.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_set_options(NabtoClientConnection* connection, const char* json);

/**
 * Get current representation of connection options.
 *
 * This is generally the same set of options as the
 * nabto_client_connection_set_options takes, except that the private
 * key is not exposed.
 *
 * @param connection [in]  The connection.
 * @param json [out]  The json string representation of the current connection options. The string should be freed with nabto_client_string_free().
 * @return NABTO_CLIENT_EC_OK iff the options is present in the output string.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_get_options(NabtoClientConnection* connection, char** json);

/**
 * Set the product id for the remote device.
 *
 * This function is required to be called before connecting to a
 * device. It cannot be changed after a connection is made.
 *
 * @param connection [in]  The connection.
 * @param productId [in]   The product id aka the id for the specific group of devices.
 * @retval NABTO_CLIENT_EC_OK if the id was set.
 * @retval NABTO_CLIENT_EC_INVALID_STATE if the connection is not in the setup phase
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_set_product_id(NabtoClientConnection* connection, const char* productId);

/**
 * Set the device id for the remote device.
 *
 * This function is required to be called before connecting to a
 * device. It cannot be changed after a connection is made.
 *
 * @param connection [in]  The connection.
 * @param deviceId [in]    The unique id for the device.
 * @retval NABTO_CLIENT_EC_OK if the id was set.
 * @retval NABTO_CLIENT_EC_INVALID_STATE if the connection is not in the setup phase
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_set_device_id(NabtoClientConnection* connection, const char* deviceId);


/**
 * @Deprecated use nabto_client_connection_set_server_key()
 *
 * Set the server api key, which is provided by nabto. Each APP needs
 * its own server api key to be able to connect to the nabto api. The
 * server api key is used to distinguish different apps. Since the
 * server api key will be put into the final applications it's not
 * secret.
 *
 * @param connection [in] the connection
 * @param serverApiKey [in] the clientId
 * @retval NABTO_CLIENT_EC_OK on success
 * @retval NABTO_CLIENT_EC_INVALID_STATE if the connection is not in the setup phase
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_set_server_api_key(NabtoClientConnection* connection,
                                           const char* serverApiKey);
/**
 * Set the server key, which is provided by Nabto. For remote
 * connections either a server key OR a server connect token is
 * required. The server key is used to distinguish different apps.
 * Since the server key will be put into the final applications it
 * is not secret.
 *
 * @param connection [in]  The connection
 * @param serverKey [in]   The server key
 * @retval NABTO_CLIENT_EC_OK on success
 * @retval NABTO_CLIENT_EC_INVALID_STATE if the connection is not in the setup phase
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_set_server_key(NabtoClientConnection* connection,
                                       const char* serverKey);

/**
 * Set a JWT token to use when connecting to the server.
 *
 * If the authentication method for the server_key is set to JWT in the solution
 * configuration set in the Nabto Cloud Console, this option is required.  If
 * the user is authenticated and can get a JWT this JWT can be given to the
 * connect such that the relay server can validate that the given user has
 * access to connect to the specific device.
 *
 * The server will look for a claim with a list of ids granted access to based
 *   on the token. `product_id`.`device_id`
 *
 * The server is configured with an audience, issuer, nabto_ids_claim and a
 * jwks_uri. The server validates the client requests against these parameters.
 * These parameters is customizable for each server_key.
 *
 * example token payload content:
 *
 * ```
 *{
 *   "aud": "...",
 *   "iss": "...",
 *   "exp": "...",
 *   "nabto_ids": "pr-12345678.de-12345678 pr-87654321.de-87654321"
 * }
 *```
 *
 * @param connection [in]  The connection
 * @param jwt [in]  The base64 JWT string, the string is copied into the
 * connection.
 * @retval NABTO_CLIENT_EC_OK on success
 * @retval NABTO_CLIENT_EC_INVALID_STATE if the
 *         connection is not in the setup phase
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_set_server_jwt_token(NabtoClientConnection* connection,
                                             const char* jwt);

/**
 * Set a SCT (Server Connect Token) token to use when connecting the the server.
 *
 * If using a SCT, a server key is not required to allow remote connections.
 *
 * This authorization method is distinct from the JWT token concept.
 *
 * This needs to be set before nabto_client_connect is called.
 *
 * @param connection [in]  The connection.
 * @param sct [in]  The Server Connect Token.
 * @return NABTO_CLIENT_EC_OK  if the token is set.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_set_server_connect_token(NabtoClientConnection* connection,
                                                 const char* sct);

/**
 * Provide information about the application which uses nabto, such
 * that it's easier to understand what apps has what communicaton
 * behavior. The application name is also present in central
 * connection information.
 *
 * @param connection [in] the connection
 * @param appName [in]  the application name. The string is copied into the connection.
 * @retval NABTO_CLIENT_EC_OK on success
 * @retval NABTO_CLIENT_EC_INVALID_STATE if the connection is not in the setup phase
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_set_application_name(NabtoClientConnection* connection,
                                             const char* appName);

/**
 * provide a version number for the application running nabto. This
 * information is used to see if a specific application version is
 * having a different behavior than other versions of the same app.
 *
 * @param connection [in]  The connection
 * @param appVersion [in]  The application version, the string is copied into the connection object.
 * @retval NABTO_CLIENT_EC_OK on success
 * @retval NABTO_CLIENT_EC_INVALID_STATE if the connection is not in the setup phase
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_set_application_version(NabtoClientConnection* connection,
                                                const char* appVersion);

/**
 * Override the default relay dispatcher endpoint. This is the initial
 * server the client connects to find and make a remote connection to
 * the remote peer. The default endpoint is
 * `https://<productid>.clients.nabto.com`. This is only needed if the
 * solution is deployed as a standalone solution with selfmanaged dns.
 *
 * This needs to be set before the connect is initiated to take
 * effect.
 *
 * @param connection [in] the connection
 * @param endpoint [in] the endpoint to use. The endpoint is a full https URL e.g. `https://example.com:4242/foo.php`. The endpoint is copied into the connection object.
 * @retval NABTO_CLIENT_EC_OK if set.
 * @retval NABTO_CLIENT_EC_INVALID_STATE if the connection is not in the setup phase
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_set_server_url(NabtoClientConnection* connection,
                                       const char* endpoint);
/**
 * sets a private key pair for a connection. The private key is a pem
 * encoded string. A private key can be created by using the
 * nabto_client_create_private_key function or using another tool
 * which can make an appropriate private key.
 *
 * @param connection [in]  The connection
 * @param privateKey [in]  The private key is copied into the connection object.
 * @retval NABTO_CLIENT_EC_OK if set.
 * @retval NABTO_CLIENT_EC_INVALID_STATE if the connection is not in the setup phase
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_set_private_key(NabtoClientConnection* connection, const char* privateKey);

/**
 * Get the full fingerprint of the remote device public key. The
 * fingerprint is used to validate the identity of the remote device.
 *
 * @param connection [in]  The connection.
 * @param fingerprint [out]  The fingerprint encoded as hex, the fingerprint has to be freed using nabto_client_string_free.
 * @retval NABTO_CLIENT_EC_OK if the fingerprint was copied to the fingerprint parameter.
 * @retval NABTO_CLIENT_EC_NOT_CONNECTED if the connection is not established yet.
 * @retval NABTO_CLIENT_EC_STOPPED if the connection is closed or stopped.
 * @retval NABTO_CLIENT_EC_NONE if no fingerprint is available.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_get_device_fingerprint(NabtoClientConnection* connection, char** fingerprintHex);

/**
 * @deprecated use nabto_client_connection_get_device_fingerprint()
 *
 * Get a truncated fingerprint a truncated version of nabto_client_connection_get_device_fingerprint()
 *
 * @param connection [in]  The connection.
 * @param fingerprintHex [out]  The fingerprint encoded as hex, the fingerprint has to be freed using nabto_client_string_free.
 * @retval NABTO_CLIENT_EC_OK if the fingerprint was copied to the fingerprint parameter.
 * @retval NABTO_CLIENT_EC_NOT_CONNECTED if the connection is not established yet.
 * @retval NABTO_CLIENT_EC_STOPPED if the connection is closed or stopped.
 * @retval NABTO_CLIENT_EC_NONE if no fingerprint is available.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_get_device_fingerprint_hex(NabtoClientConnection* connection, char** fingerprintHex);

/**
 * @deprecated use nabto_client_connection_get_device_fingerprint
 *
 * Get a fingerprint of the device public key of the current device.
 *
 * @param connection [in]  The connection.
 * @param fingerprintHex [out]  The fingerprint encoded as hex, the fingerprint has to be freed using nabto_client_string_free.
 * @retval NABTO_CLIENT_EC_OK if the fingerprint was copied to the fingerprint parameter.
 * @retval NABTO_CLIENT_EC_NOT_CONNECTED if the connection is not established yet.
 * @retval NABTO_CLIENT_EC_STOPPED if the connection is closed or stopped.
 * @retval NABTO_CLIENT_EC_NONE if no fingerprint is available.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_get_device_fingerprint_full_hex(NabtoClientConnection* connection, char** fingerprintHex);

/**
 * Get the fingerprint of the client public key used for this connection.
 *
 * @param connection [in]  The connection.
 * @param fingerprint [out]  The fingerprint, the fingerprint has to be freed using nabto_client_string_free after use.
 * @retval NABTO_CLIENT_EC_OK if the fingerprint was copied to the fingerprint parameter.
 * @retval NABTO_CLIENT_EC_INVALID_STATE if no client private key is set.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_get_client_fingerprint(NabtoClientConnection* connection, char** fingerprintHex);

/**
 * @deprecated use nabto_client_connection_get_client_fingerprint
 *
 * Get the truncated fingerprint of the clients public key.
 *
 * @param connection [in]  The connection.
 * @param fingerprintHex [out]  The fingerprint, the fingerprint has to be freed using nabto_client_string_free after use.
 * @retval NABTO_CLIENT_EC_OK if the fingerprint was copied to the fingerprint parameter.
 * @retval NABTO_CLIENT_EC_INVALID_STATE if no client private key is set.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_get_client_fingerprint_hex(NabtoClientConnection* connection, char** fingerprintHex);

/**
 * @deprecated use nabto_client_connection_get_client_fingerprint
 *
 * Get the fingerprint of the clients public key, same as nabto_client_connection_get_client_fingerprint
 *
 * @param connection [in]  The connection.
 * @param fingerprintHex [out]  The fingerprint, the fingerprint has to be freed using nabto_client_string_free after use.
 * @retval NABTO_CLIENT_EC_OK if the fingerprint was copied to the fingerprint parameter.
 * @retval NABTO_CLIENT_EC_INVALID_STATE if no client private key is set.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_get_client_fingerprint_full_hex(NabtoClientConnection* connection, char** fingerprintHex);

/**
 * Get the connection type. Use this function to limit the amount of
 * traffic sent over relay connections.
 *
 * @param connection [in]  The connection.
 * @param type [out]  The connection type.
 * @retval NABTO_CLIENT_EC_OK if the connection is established.
 * @retval NABTO_CLIENT_EC_NOT_CONNECTED if the connection is not opened yet.
 * @retval NABTO_CLIENT_EC_STOPPED if the connection is stopped or closed.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_get_type(NabtoClientConnection* connection, NabtoClientConnectionType* type);


/**
 * Enable direct communication for a connection, using candidates
 * provided by the nabto_client_connection_add_direct_candidate
 * function.
 *
 * Direct connections is a way to make the client create a connection
 * to a device which can be reached directly with ip communication.
 *
 * Usage:
 * ```
 * 1. call nabto_client_connection_enable_direct_candidates();
 * 2. call nabto_client_connection_connect();
 * 3. call nabto_client_connection_add_direct_candidate();
 * 4. call nabto_client_connection_end_of_direct_candidates();
 * ```
 * @param connection [in]  The connection,
 * @return NABTO_CLIENT_EC_OK  if direct candidates was enabled.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_enable_direct_candidates(NabtoClientConnection* connection);

/**
 * Add a direct candidate.
 *
 * This function can be used to manually add direct device
 * hostnames/ips where the client can make a direct connection to a
 * device. This is normally used in conjunction with local discovery
 * of devices.
 *
 * @param connection [in] The connection
 * @param hostname [in]   Either a dns name or an ip address.
 * @param port [in]       Port to connect to.
 * @retval NABTO_CLIENT_EC_OK if ok.
 * @retval NABTO_CLIENT_EC_INVALID_ARGUMENT if the arguments is obviously invalid. e.g. using port number 0
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_add_direct_candidate(NabtoClientConnection* connection, const char* hostname, uint16_t port);

/**
 * Inform the connection that no more direct endpoints will be added to the connection.
 * @param connection [in]  The connection.
 * @return NABTO_CLIENT_EC_OK if success.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_end_of_direct_candidates(NabtoClientConnection* connection);

/**
 * Connect to a device.
 *
 * If this future returns ok, a connection is created between the
 * client and the device. If the connection is made using a relay
 * channel, the connection will be tried to be upgraded to a p2p
 * connection in the background, after this future is resolved.
 *
 * A connection is made over channels, a channel can be a direct udp
 * connection or a relayed udp connection. If no channel can be
 * established between the client and the device the error
 * NABTO_CLIENT_EC_NO_CHANNEL is returned. This reason for this can be
 * many and to find the specific root cause the function
 * nabto_client_connection_get_info must be consulted.
 *
 * Since we try many different channels for the communication only
 * errors which is not supposed to happen if the software is used
 * appropriately are reported. E.g. If the device is not connected to
 * the server, it is not logged as an error. If the server_key
 * specified is invalid, then it's logged as an error.
 *
 * Future status:
 *  - NABTO_CLIENT_EC_OK iff connection is ok and connected to
 *    the device.
 *  - NABTO_CLIENT_EC_INVALID_STATE if the connection is
 *    missing required options.
 *  - NABTO_CLIENT_EC_NO_CHANNELS if no channels could be created. see
 *    nabto_client_connection_get_local_channel_error_code and
 *    nabto_client_connection_get_remote_channel_error_code or
 *    nabto_client_connection_get_info for what went wrong.
 *  - NABTO_CLIENT_EC_TIMEOUT if the the channel to the device was created but the dtls connection to the device timed out.
 *  - NABTO_CLIENT_EC_DEVICE_INTERNAL_ERROR if the device encountered an internal
 *    error during the dtls connect attempt. This is most likely due to no more
 *    connection resources available in the device.
 *  - NABTO_CLIENT_EC_STOPPED if the connection or the client is stopped.
 *
 * @param connection [in]  The connection.
 * @param future [in]  The future.
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_connection_connect(NabtoClientConnection* connection, NabtoClientFuture* future);

/**
 * Gracefully close a connection (send explicit close to the other peer). Any
 * CoAP requests or streams using the connection are forcefully closed and
 * stopped. Non-graceful close can be made using the stop or free function.
 *
 * Future status:
 *  - NABTO_CLIENT_EC_OK, the connection is closed.
 *  - NABTO_CLIENT_EC_OPERATION_IN_PROGRESS if another close is in progreess.
 *  - NABTO_CLIENT_EC_STOPPED if the connection is closed or stopped or a parent object is stopped. This way nabto_client_future_set_callback2 returns the same value as nabto_client_future_wait when using the future.
 *  - NABTO_CLIENT_EC_NOT_CONNECTED if the connection is not established yet.
 *
 * @param connection [in] the connection to close.
 * @param future [in] the future resolves when the connection is closed.
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_connection_close(NabtoClientConnection* connection, NabtoClientFuture* future);

/**
 * Get error code for the local channel
 *
 * @param connection [in]  The connection on which the local channel is opened for which the error should be retrieved.
 * @retval NABTO_CLIENT_EC_OK if the device was found using mdns.
 * @retval NABTO_CLIENT_EC_NONE if mdns discovery was not enabled for the connection.
 * @retval NABTO_CLIENT_EC_NOT_FOUND if mdns was enabled but the device was not found.
 * @retval NABTO_CLIENT_EC_OPERATION_IN_PROGRESS if scanning is still in progress
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_get_local_channel_error_code(NabtoClientConnection* connection);

/**
 * Get error code for the remote channel
 *
 * @param connection [in]  The connection on which the remote channel is opened for which the error should be retrieved.
 * @retval NABTO_CLIENT_EC_OK  if a remote relay channel was made.
 * @retval NABTO_CLIENT_EC_NONE  if remote relay was not enabled.
 * @retval NABTO_CLIENT_EC_NOT_ATTACHED  if the device is not attached to the basestation
 * @retval NABTO_CLIENT_EC_TIMEOUT  if a timeout occured when connecting to the basestation.
 * @retval NABTO_CLIENT_EC_OPERATION_IN_PROGRESS  if the opening of the channel is still in progress
 * @retval NABTO_CLIENT_EC_FORBIDDEN  if the basestation request is rejected.
 * @retval NABTO_CLIENT_EC_INVALID_STATE if required options is missing for the remote connection.
 * @retval NABTO_CLIENT_EC_TOKEN_REJECTED  if the basestation rejects access to a device based on either a valid formatted JWT token or a valid formatted SCT token.
 * @retval NABTO_CLIENT_EC_DNS  if dns could not be resolved.
 * @retval NABTO_CLIENT_EC_UNKNOWN_SERVER_KEY if the server key is not known by the basestation.
 * @retval NABTO_CLIENT_EC_UNKNOWN_PRODUCT_ID  if the product id is not known by the basestation.
 * @retval NABTO_CLIENT_EC_UNKNOWN_DEVICE_ID  if the device id is not known by the basestation.
 * @retval NABTO_CLIENT_EC_CONNECTION_REFUSED  if the client could not connect to the basestation.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_get_remote_channel_error_code(NabtoClientConnection* connection);

/**
 * Get error code for the direct chandidates channels
 *
 * @param connection [in]  The connection on which the direct channel is opened for which the error should be retrieved.
 * @retval NABTO_CLIENT_EC_OK  if a direct candidate was found.
 * @retval NABTO_CLIENT_EC_NONE  direct candidates was not enabled.
 * @retval NABTO_CLIENT_EC_NOT_FOUND  If no direct candidates resulted in UDP ping responses.
 * @retval NABTO_CLIENT_EC_OPERATION_IN_PROGRESS  if opening of the direct candidate is in progress.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_get_direct_candidates_channel_error_code(NabtoClientConnection* connection);


/**
 * @deprecated
 *
 * Get information about a connection
 *
 * ```
 * {
 *   "MdnsError": NABTO_CLIENT_EC_OK|NABTO_CLIENT_EC_NOT_FOUND,
 *   "UdpRelayError": NABTO_CLIENT_EC_OK|NABTO_CLIENT_EC_NOT_FOUND
 * }
 * ```
 *
 * MdnsError, set if mdns is enabled in the client, it is ok if the
 * device was found locally.
 *
 * UdpRelayError, set a remote udp relay was tried, it's ok if udp
 * relay was created.
 *
 * The returned json needs to be freed with nabto_client_string_free
 *
 * @param connection [in] Connection to get info for
 * @param json [out] Where to put resulting json string
 * @retval NABTO_CLIENT_EC_OK on success
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_get_info(NabtoClientConnection* connection, char** json);

/**
 * Password authenticate, do a password authentication exchange with a
 * device.
 *
 * Password authenticate the client and the device. The password
 * authentication is bidirectional and based on PAKE, such that both
 * the client and the device learns that the other end knows the
 * password, without revealing the password to the other end.
 *
 * A specific use case for the password authentication is to prove the
 * identity of a device which identity is not already known, e.g. in a
 * pairing scenario.
 *
 * Future status:
 *  - NABTO_CLIENT_EC_OK iff the authentication went well.
 *  - NABTO_CLIENT_EC_UNAUTHORIZED iff the username or password is invalid
 *  - NABTO_CLIENT_EC_NOT_FOUND if the password authentication feature is not available on the device.
 *  - NABTO_CLIENT_EC_NOT_CONNECTED if the connection is not established yet.
 *  - NABTO_CLIENT_EC_OPERATION_IN_PROGRESS if a password authentication request is already in progress on the connection.
 *  - NABTO_CLIENT_EC_TOO_MANY_REQUESTS if too many password attempts has been made.
 *  - NABTO_CLIENT_EC_STOPPED if the connection is stopped.
 *
 * @param connection [in]  The connection
 * @param username [in]    The username
 * @param password [in]    The password
 * @param future [in]      The future with the result
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_connection_password_authenticate(NabtoClientConnection* connection, const char* username, const char* password, NabtoClientFuture* future);


/*********************
 * Connection Events *
 *********************/

/**
 * Connection events. Connection events is used to notify an
 * application about events happening on a connection.
 */
typedef int NabtoClientConnectionEvent;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientConnectionEvent NABTO_CLIENT_CONNECTION_EVENT_CONNECTED;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientConnectionEvent NABTO_CLIENT_CONNECTION_EVENT_CLOSED;
NABTO_CLIENT_DECL_PREFIX extern const NabtoClientConnectionEvent NABTO_CLIENT_CONNECTION_EVENT_CHANNEL_CHANGED;

/**
 * Initialize a future for the event listener, the future is resolved
 * when a new connection event is ready or the listener has been
 * stopped.
 *
 * Future status:
 *  - NABTO_CLIENT_EC_OK       if the a connection event is available in the event parameter.
 *  - NABTO_CLIENT_EC_STOPPED  if the listener is stopped.
 *
 * @param listener [in]  The listener.
 * @param future [in]    The future which is resolved when an connection event is ready.
 * @param event [out]     The event which is overwritten when the future resolves with NABTO_CLIENT_EC_OK.
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_listener_connection_event(NabtoClientListener* listener, NabtoClientFuture* future, NabtoClientConnectionEvent* event);

/**
 * Listen for events on a connection. Each time a future is resolved
 * on the listener, the event parameter is set to the current
 * event.
 *
 * @param connection [in]  The connection
 * @param listener [in]    The listener to associate with connection events.
 * @retval NABTO_CLIENT_EC_OK iff ok.
 * @retval NABTO_CLIENT_EC_INVALID_STATE if the listener is already initialized or some other invalid state.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_connection_events_init_listener(NabtoClientConnection* connection, NabtoClientListener* listener);


/*****************
 * Streams API *
 *****************/

/**
 * @intro Streams
 *
 * The Streams api is used to make a reliable stream on top of a connection. The
 * stream is reliable and ensures data is received ordered and complete. If
 * either of these conditions cannot be met, the stream will be closed in such a
 * way that it is detectable.
 *
 * For historic reasons the streaming api have been using abort instead of stop.
 * The ERROR code NABTO_CLIENT_EC_ABORTED is an alias for
 * NABTO_CLIENT_EC_STOPPED. And nabto_client_stream_abort is a synonym for
 * nabto_client_stream_stop.
 */

/**
 * Create a stream.
 *
 * @param connection [in]  The connection to make the stream on, the connection needs
 * to be kept alive until the stream has been freed.
 * @return  NULL if the stream could not be created, non NULL otherwise.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientStream* NABTO_CLIENT_API
nabto_client_stream_new(NabtoClientConnection* connection);

/**
 * Free a stream.
 *
 * @param stream [in] the stream to free
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_stream_free(NabtoClientStream* stream);


/**
 * @deprecated use nabto_client_stream_stop()
 *
 * Abort / stop a stream.
 *
 * @param stream [in]  The stream.
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_stream_abort(NabtoClientStream* stream);

/**
 * Same as nabto_client_stream_abort
 *
 * Stopping a stream does not care about whether there's unacknowledged data,
 * it forces the stream to stop. Outstanding read/write/close callbacks will be
 * resolved as the stream is forcefully stopped. The function is not blocking so
 * the actual callbacks may be resolved after this function returns.
 *
 * @param stream [in]  The stream.
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_stream_stop(NabtoClientStream* stream);

/**
 * Handshake a stream. This function initializes and does a three way
 * handshake on a stream.
 *
 * Future status:
 *  - NABTO_CLIENT_EC_OK if opening went ok.
 *  - NABTO_CLIENT_EC_STOPPED if the stream could not be created, e.g. the handshake
 *   is stopped/aborted or the connection or client context is stopped.
 *  - NABTO_CLIENT_EC_NOT_CONNECTED if the connection is not established yet.
 *
 * @param stream [in]  The stream to connect.
 * @param future [in]  The future.
 * @param port [in]    The listening id/port to use for the stream. This is used to distinguish
 *                     streams in the other end, like a port number.
 *
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_stream_open(NabtoClientStream* stream, NabtoClientFuture* future, uint32_t port);

/**
 * Read exactly n bytes from a stream.
 *
 * If (readLength != bufferLength), the stream has reached a state where the amount of bytes
 * specified by bufferLength could NOT be read. The amount of bytes which could be read is copied to
 * the buffer and readLength is less than bufferLength In any subsequent invocation,
 * NABTO_CLIENT_EC_EOF will be returned.
 *
 * Future status:
 *  - NABTO_CLIENT_EC_OK  if all or some data was read
 *  - NABTO_CLIENT_EC_EOF  if the stream is eof
 *  - NABTO_CLIENT_EC_STOPPED if the stream is stopped
 *  - NABTO_CLIENT_EC_OPERATION_IN_PROGRESS if another read is in progress.
 *
 * @param stream [in]       The stream to read bytes from.
 * @param future [in]       The future that resolves when the read completes or fails.
 * @param buffer [out]      The buffer to put data into. It needs to be kept available until the future resolves.
 * @param bufferLength [in] The length of the output buffer.
 * @param readLength [out]  The actual number of bytes read. It needs to be kept available until the future resolves.
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_stream_read_all(NabtoClientStream* stream, NabtoClientFuture* future, void* buffer, size_t bufferLength, size_t* readLength);

/**
 * Read some bytes from a stream.
 *
 * Read atleast 1 byte from the stream, unless an error occurs or the
 * stream is eof.
 *
 * Future status:
 *  - NABTO_CLIENT_EC_OK if some bytes was read.
 *  - NABTO_CLIENT_EC_EOF if stream is eof.
 *  - NABTO_CLIENT_EC_STOPPED if the stream is stopped.
 *  - NABTO_CLIENT_EC_OPERATION_IN_PROGRESS if another read is in progress.
 *
 * @param stream [in]        The stream to read bytes from
 * @param future [in]        The future that resolves when the read completes or fails.
 * @param buffer [out]       The buffer where bytes is copied to. It needs to be kept available until the future resolves.
 * @param bufferLength [in]  The length of the output buffer.
 * @param readLength [out]   The actual number of read bytes. It needs to be kept available until the future resolves.
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_stream_read_some(NabtoClientStream* stream, NabtoClientFuture* future, void* buffer, size_t bufferLength, size_t* readLength);

/**
 * Write bytes to a stream.
 *
 * When the future resolves the data is only written to the stream,
 * but not neccessary acknowledged. This is why it does not make sense to
 * return a number of actual bytes written in case of error since it
 * says nothing about the number of acked bytes. To ensure that
 * written bytes have been acked, a succesful call to
 * nabto_client_stream_close is neccessary after last call to
 * nabto_client_stream_write.
 *
 * Future status:
 *  - NABTO_CLIENT_EC_OK if write was ok, the buffer is fully copied
 *   into the streaming buffers, but not neccessarily sent or acknowledgeg by the other end yet.
 *  - NABTO_CLIENT_EC_CLOSED if the stream is closed for writing.
 *  - NABTO_CLIENT_EC_STOPPED if the stream is stopped.
 *  - NABTO_CLIENT_EC_OPERATION_IN_PROGRESS if another write is in progress.
 *
 * @param stream [in] The stream to write data to.
 * @param future [in] The future that resolves when the write completes or fails.
 * @param buffer [in] The input buffer with data to write to the stream, the buffer needs to be kept alive until the future returns.
 * @param bufferLenth [in], length of the input data.
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_stream_write(NabtoClientStream* stream, NabtoClientFuture* future, const void* buffer, size_t bufferLength);

/**
 * Close a stream for writing of more data. When a stream has been
 * closed no further data can be written to the stream. Data can
 * however still be read from the stream until the other peer closes
 * the stream and this end sees an end of file error.
 *
 * When close returns all written data has been acknowledged by the
 * other peer. Close cannot be executed at the same time a stream
 * write is in progress.
 *
 * Future status:
 *  - NABTO_CLIENT_EC_OK if the stream is closed for writing.
 *  - NABTO_CLIENT_EC_STOPPED if the stream is stopped.
 *  - NABTO_CLIENT_EC_OPERATION_IN_PROGRESS  if a stream close or stream write is in progress.
 *  - NABTO_CLIENT_EC_INVALID_STATE if the stream is not yet opened.
 *
 * @param stream [in]  The stream to close.
 * @param future [in]  The future.
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_stream_close(NabtoClientStream* stream, NabtoClientFuture* future);


/*****************
 * CoAP API
 *****************/

/**
 * @intro CoAP
 *
 * The CoAP implementation exhanges CoAP messages on top of a Nabto connection between a client and
 * a device.
 *
 * **CoAP example**:
 *
 * ```
 * NabtoClientCoap* coap = nabto_client_coap_new(connection, "GET", "/temperature/living_room");
 * NabtoClientFuture* future = nabto_client_coap_execute(coap);
 * nabto_client_future_wait(future);
 * nabto_client_future_free(future);
 *
 * uint16_t statusCode;
 * uint16_t contentFormat;
 * nabto_client_coap_get_response_status_code(coap, &statusCode);
 * nabto_client_coap_get_response_content_format(coap, &contentFormat);
 * void* responsePayload;
 * size_t responsePayloadLength;
 * nabto_client_coap_get_response_payload(coap, &responsePayload, &responsePayloadLength);
 *
 * Do stuff here with the response.
 *
 * nabto_client_coap_free(request);
 * ```
 */

/**
 * Create a new coap request/response context on the given connection.
 * @param connection [in]  The connection to make the CoAP request on, the connection needs to be kept alive until the request has been freed.
 * @param method [in]      The CoAP method designator string. One of: GET, POST, PUT, DELETE.
 * @param path [in]        The URI path element of the resource being requested. It has to start with a '/' character. The string "/" is the root path.
 * @returns The created CoAP context, NULL if it could not be created (including if method is invalid).
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientCoap* NABTO_CLIENT_API
nabto_client_coap_new(NabtoClientConnection* connection, const char* method, const char* path);

/**
 * Free a coap request. Outstanding futures will be resolved.
 * @param coap [in] The CoAP request to free.
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_coap_free(NabtoClientCoap* coap);

/**
 * Stop a coap request. This stops outstanding
 * nabto_client_coap_execute calls. The request should not be used
 * after it has been stopped.
 *
 * @param coap [in]  The CoAP request.
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_coap_stop(NabtoClientCoap* coap);

/**
 * Set payload and content format for the payload.
 *
 * The payload is copied into the request object.
 *
 * @param coap [in] The CoAP request to set request payload and content format on.
 * @param contentFormat [in] See https://www.iana.org/assignments/core-parameters/core-parameters.xhtml, some often used values are defined in NabtoClientCoapContentFormat.
 * @param payload [in] Data for the request encoded as specified in the `contentFormat` parameter.
 * @param payloadLength [in] Length of the payload in bytes.
 * @return Returns NABTO_CLIENT_OK iff the payload and content format were successfully set.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_coap_set_request_payload(NabtoClientCoap* coap, uint16_t contentFormat, const void* payload, size_t payloadLength);

/**
 * Execute a coap request. After this function has succeeded the
 * response functions can be called.
 *
 * Future status:
 *  - NABTO_CLIENT_EC_OK if the coap request was made and a statusCode exists.
 *  - NABTO_CLIENT_EC_TIMEOUT if the request timed out (took more than 2 minutes.)
 *  - NABTO_CLIENT_EC_STOPPED if the coap request or a parent object is stopped.
 *  - NABTO_CLIENT_EC_NOT_CONNECTED if the connection is not established yet.
 *
 * @param request [in] The CoAP request to execute.
 * @param future [in] The future completes when the CoAP request completes or fails.
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_coap_execute(NabtoClientCoap* request, NabtoClientFuture* future);

/**
 * Get response status. encoded as e.g. 404, 200, 203, 500.
 *
 * @param coap [in] the coap request/response object.
 * @param statusCode [out]  the statusCode for the request
 * @retval NABTO_CLIENT_EC_OK if the status code exists.
 * @retval NABTO_CLIENT_EC_INVALID_STATE if there's no response yet.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_coap_get_response_status_code(NabtoClientCoap* coap, uint16_t* statusCode);

/**
 * Get content type of the payload if one exists.
 *
 * @param coap [in] The coap request/response object.
 * @param contentType [out] The content type if it exists.
 * @retval NABTO_DEVICE_EC_OK iff response has a contentFormat
 * @retval NABTO_DEVICE_EC_NO_DATA if the response does not have a content format
 * @retval NABTO_DEVICE_EC_INVALID_STATE if no response is ready
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_coap_get_response_content_format(NabtoClientCoap* coap, uint16_t* contentType);

/**
 * Get the response data.
 *
 * The payload is available until nabto_client_coap_free is called.
 *
 * @param coap [in] the coap request response object.
 * @param payload [out] start of the payload.
 * @param payloadLength [out] length of the payload
 * @retval NABTO_CLIENT_EC_OK if a payload exists and payload and payloadLength is set appropriately.
 * @retval NABTO_CLIENT_EC_NO_DATA if the response does not have a payload
 * @retval NABTO_CLIENT_EC_INVALID_STATE if no response is ready yet.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_coap_get_response_payload(NabtoClientCoap* coap, void** payload, size_t* payloadLength);

/*****************
 * TCP Tunnelling
 ****************/

/**
 * @intro TCP Tunnelling
 *
 * TCP Tunnels allows tunnelling of tcp connections from a client to a device over a nabto
 * connection. Nabto Streams is used to stream the data reliably over the Nabto Connection.
 *
 * The client opens a TCP listener which listens for incoming TCP connections on the local
 * port. When a connection is accepted by the TCP listener, a new stream is created to the
 * device. When the stream is created on the device, the device opens a tcp connection to the
 * specified service. Once this connection is opened TCP data flows from the TCP Client on the
 * client side to the TCP Server on the device side.
 */

/**
 * Nabto TCP tunnel handle.
 */
typedef struct NabtoClientTcpTunnel_ NabtoClientTcpTunnel;

/**
 * Create a tunnel
 *
 * @param connection [in]  The connection to make the tunnel on, the connection needs
 * to be kept alive until the tunnel has been closed.
 * @return  Tunnel handle if the tunnel could be created, NULL otherwise.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientTcpTunnel* NABTO_CLIENT_API
nabto_client_tcp_tunnel_new(NabtoClientConnection* connection);

/**
 * Free a tunnel.
 *
 * @param tunnel [in] The tunnel to free
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_tcp_tunnel_free(NabtoClientTcpTunnel* tunnel);


/**
 * Stop a tcp tunnel. Stop can be used to cancel async functions like
 * open and close. But the tcp tunnel cannot be used after it has been
 * stopped. So you cannot call open, then stop and then resume the
 * open again.
 *
 * @param tunnel [in]  The tunnel.
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_tcp_tunnel_stop(NabtoClientTcpTunnel* tunnel);

/**
 * Opens a TCP tunnel to a TCP server through a Nabto enabled device
 * connected to earlier. The ip address of the server is configured in
 * the device. Often it is configured to localhost.
 *
 * ```
 * |      +--------+          +-----------+               +--------+
 * |      | nabto  |   nabto  |   nabto   |   tcp/ip      | remote |
 * |   |--+ client +----~~~---+   device  +----~~~-----|--+ server |
 * | port | API    |          |           |          port |        |
 * |      +--------+           +----------+               +--------+
 * ```
 *
 * Future status:
 *  - NABTO_CLIENT_EC_OK if opening went ok
 *  - NABTO_CLIENT_EC_NOT_FOUND if requesting an unknown service
 *  - NABTO_CLIENT_EC_FORBIDDEN if target device did not allow opening a tunnel to specified service for the current client
 *  - NABTO_CLIENT_EC_STOPPED if the tunnel is stopped.
 *  - NABTO_CLIENT_EC_NOT_CONNECTED if the connection is not established yet.
 *  - NABTO_CLIENT_EC_PRIVILEGED_PORT if the connection is not established because the port is privileged and the user does not have access to start a listening socket on that port number.
 *
 * @param tunnel [in]     Tunnel handle crated with nabto_client_tcp_tunnel_new.
 * @param future [in]     The future.
 * @param service [in]    The service on the remote host to connect to.
 * @param localPort [in]  The local TCP port to listen on. If the localPort
 *                        number is 0 the api will choose the port number.
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_tcp_tunnel_open(NabtoClientTcpTunnel* tunnel, NabtoClientFuture* future, const char* service, uint16_t localPort);

/**
 * Close a TCP tunnel.
 *
 * This closes the tcp tunnel.
 *  - The listener is closed.
 *  - Each ongoing tunnelled tcp connection is aborted.
 *
 * Future status:
 *  - NABTO_CLIENT_EC_OK if the tunnel was closed.
 *  - NABTO_CLIENT_EC_STOPPED if the tunnel is stopped.
 *  - NABTO_CLIENT_EC_INVALID_STATE if the tunnel has not been opened yet.
 *
 * @param tunnel [in] the tunnel to close.
 * @param future [in] the future which resolves with the status of the operation.
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_tcp_tunnel_close(NabtoClientTcpTunnel* tunnel, NabtoClientFuture* future);

/**
 * Get the local port the tcp tunnel is bound to. If the port number 0
 * is used when creating the tunnel, this function is used to query
 * what port was choosen.
 *
 * @param tunnel [in]  The tunnel.
 * @param localPort [out]  The port number.
 * @retval NABTO_CLIENT_EC_OK iff ok
 * @retval NABTO_CLIENT_EC_INVALID_STATE if the tunnel is not opened.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_tcp_tunnel_get_local_port(NabtoClientTcpTunnel* tunnel, uint16_t* localPort);


/*****************
 * mDNS API
 ******************/

/**
 * @intro mDNS
 * The mDNS API is used for discovering Nabto Edge devices on the local network.
 */

typedef struct NabtoClientMdnsResult_ NabtoClientMdnsResult;

typedef enum NabtoClientMdnsAction_ {
    /*
     * This action is emitted when a mdns cache item is added.
     */
    NABTO_CLIENT_MDNS_ACTION_ADD = 0,
    /*
     * This action is emitted when an mdns cache item is updated.
     */
    NABTO_CLIENT_MDNS_ACTION_UPDATE = 1,
    /*
     * This action is emitted when an mdns cache item is removed,
     * ie. the ttl has expired for the item.
     */
    NABTO_CLIENT_MDNS_ACTION_REMOVE = 2
} NabtoClientMdnsAction;

/**
 * Init listener as mdns resolver
 *
 * Init a mdns result listener. If the subtype is non null or the non
 * empty string the mDNS subtype <subtype>._sub._nabto._udp.local is
 * located instead of the mDNS service _nabto._udp.local.
 *
 * @param client [in]  The client.
 * @param listener [in]  The listener.
 * @param subtype [in]  The subtype to find.
 * @return NABTO_CLIENT_EC_OK if ok.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_mdns_resolver_init_listener(NabtoClient* client, NabtoClientListener* listener, const char* subtype);

/**
 * Wait for a new mDNS result.
 *
 * Future status:
 *  - NABTO_CLIENT_EC_OK if ok
 *  - NABTO_CLIENT_EC_INVALID_ARGUMENT if provided listener is invalid
 *  - NABTO_CLIENT_EC_STOPPED if the client was stopped
 *
 * @param listener [in] The listener.
 * @param future [in] The future that resolves when new mDNS results are ready.
 * @param mdnsResult [out] The result that is ready when the future resolves.
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_listener_new_mdns_result(NabtoClientListener* listener, NabtoClientFuture* future, NabtoClientMdnsResult** mdnsResult);

/**
 * Free result object
 *
 * @param result [in]  The result to free.
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_mdns_result_free(NabtoClientMdnsResult* result);

/**
 * Get device ID of from result object.
 *
 * @param result [in]  The result
 * @return the device ID or the empty string if not set
 */
NABTO_CLIENT_DECL_PREFIX const char* NABTO_CLIENT_API
nabto_client_mdns_result_get_device_id(NabtoClientMdnsResult* result);

/**
 * Get product ID of from result object.
 *
 * @param result [in]  The result
 * @return the product ID or the empty string if not set
 */
NABTO_CLIENT_DECL_PREFIX const char* NABTO_CLIENT_API
nabto_client_mdns_result_get_product_id(NabtoClientMdnsResult* result);

/**
 * Get the service instance name, this can be used to correlate results.
 * This is never NULL and always defined.
 *
 * @param result [in]  The result
 * @return The service instance name of the result
 */
NABTO_CLIENT_DECL_PREFIX const char* NABTO_CLIENT_API
nabto_client_mdns_result_get_service_instance_name(NabtoClientMdnsResult* result);

/**
 * Get the txt record key value pairs as a json encoded string.
 * The string is owned by the NabtoClientMdnsResult object.
 *
 * The data is encoded as { "key1": "value1", "key2": "value2" }
 *
 * @param result [in]  The result
 * @return The txt records of the result
 */
NABTO_CLIENT_DECL_PREFIX const char* NABTO_CLIENT_API
nabto_client_mdns_result_get_txt_items(NabtoClientMdnsResult* result);

/**
 * Get the NabtoClientMdnsAction action for the result.
 *
 * @param result [in] mDNS result to get action for
 * @return The action of the result.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientMdnsAction NABTO_CLIENT_API
nabto_client_mdns_result_get_action(NabtoClientMdnsResult* result);



/**************
 * Future API
 **************/

/**
 * @intro Futures
 *
 * Nabto Edge uses `Futures` to manage return values and completion of asynchronous API-functions; a
 * future resolves once such function has completed. For more details about this topic, see the
 * [Futures Guide](/developer/guides/platforms/embedded/nabto_futures.html).
 *
 * Futures are introduced to unify the way return values and completion of asynchronous functions
 * are handled and to minimize the number of specialized functions required in the APIs: Instead of
 * having an asynchronous and synchronous version of all functions, the API instead provides a
 * single version returning a future: For asynchronous behavior, a callback can then be configured
 * on the future - for synchronous behavior, the future provides a `wait` function.
 *
 * In addition to futures, asynchronous functions that are expected to be invoked recurringly
 * introduces the concept of `listeners`, also elaborated in the [Futures
 * Guide](/developer/guides/platforms/embedded/nabto_futures.html).
 */

/**
 * Create a future
 *
 * @param context [in]  The Nabto client context
 * @return A new future or NULL
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientFuture* NABTO_CLIENT_API
nabto_client_future_new(NabtoClient* context);

/**
 * Free a future.
 *
 * Free must never be called on an unresolved future. If necessary, first cancel the pending async
 * operation to resolve the future as soon as possible. Use the operation specific close/abort/free
 * function as necessary such as nabto_client_connection_close. Or use nabto_client_stop to cancel
 * all pending operations.
 *
 * @param future [in]  The future to free
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_future_free(NabtoClientFuture* future);

/**
 * @deprecated Use nabto_client_future_error_code instead
 *
 * Query if a future is ready. Deprecate
 *
 * @param future [in] The future.
 * @return NABTO_CLIENT_EC_FUTURE_NOT_RESOLVED if the future is not
 *         resolved yet. If the future is resolved, the return value
 *         is whatever the underlying function returned.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_future_ready(NabtoClientFuture* future);

/**
 * @deprecated use nabto_client_future_set_callback2()
 *
 * Set a callback to be called when the future resolves
 *
 * It is not allowed to call the following functions from the callback
 * as they could either crash the application or lead to the callback
 * thread being blocked.
 *
 * - nabto_client_future_wait
 * - nabto_client_future_timed_wait
 * - nabto_client_stop
 * - nabto_client_free
 *
 * @param future [in]  The future.
 * @param callback [in]  The callback.
 * @param data [in]  User data for the callback.
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_future_set_callback(NabtoClientFuture* future,
    NabtoClientFutureCallback callback,
    void* data);

/**
 * Set a callback to be called when the future resolves
 *
 * It is not allowed to call the following functions from the callback
 * as they could either creash the application or lead to the callback
 * thread being blocked.
 *
 * - nabto_client_future_wait
 * - nabto_client_future_timed_wait
 * - nabto_client_stop
 * - nabto_client_free
 *
 * @param future [in]  The future.
 * @param callback [in]  The callback.
 * @param data [in]  User data for the callback.
 * @return NABTO_CLIENT_EC_OK iff the callback is set
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_future_set_callback2(NabtoClientFuture* future,
    NabtoClientFutureCallback callback,
    void* data);


/**
 * Wait until a future is resolved. The returned error code is that
 * for the underlying operation.
 *
 * @param future [in]  The future.
 * @retval NABTO_CLIENT_EC_* the error code for the underlying operation
 * @retval NABTO_CLIENT_EC_COULD_BLOCK if called from a future callback.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_future_wait(NabtoClientFuture* future);

/**
 * Wait atmost duration milliseconds for the future to be resolved.
 *
 * @param future [in]  The future.
 * @param duration [in]  The duration.
 * @retval NABTO_CLIENT_EC_FUTURE_NOT_RESOLVED if the future is not resolved yet when the timer expires
 * @retval NABTO_CLIENT_EC_* the error code of the async operation if the future is resolved
 * @retval NABTO_CLIENT_EC_COULD_BLOCK if called from a future callback.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_future_timed_wait(NabtoClientFuture* future, nabto_client_duration_t duration);

/**
 * Retrieve error code from a future.
 * @param future [in] the future.
 * @retval NABTO_CLIENT_EC_FUTURE_NOT_RESOLVED if the future is not resolved yet.
 * @retval NABTO_CLIENT_EC_* the error code of the async operation if the future is resolved
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_future_error_code(NabtoClientFuture* future);

/*****************
 * Listener API
 *****************/

/**
 * @intro Listeners
 *
 * Nabto Edge uses `Futures` to manage return values and completion of asynchronous API-functions; a
 * future resolves once such function has completed. Additionally, the Listener API supports
 * asynchronous functions that are expected to be invoked recurringly (see the [Futures
 * Guide](/developer/api-reference/embedded-device-sdk/futures/Introduction.html) for details).
 *
 * Listeners are created and freed through this general API. Once created, a listener is initialized
 * for use with a specific purpose, e.g. to listen for [connection
 * events](/developer/api-reference/plain-c-client-sdk/listeners/nabto_client_listener_connection_event.html),
 */

/**
 * Create a new Listener
 *
 * A Listener is an object which can listen for a type of events. The
 * listener is initialized to the specific type of events later.
 *
 * @param context [in]  The context.
 * @return A new listener.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientListener* NABTO_CLIENT_API
nabto_client_listener_new(NabtoClient* context);

/**
 * Free a listener.
 *
 * @param listener [in] Listener to be freed
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_listener_free(NabtoClientListener* listener);

/**
 * Stop a listener. The stop function is needed such that the listener can be
 * stopped without race conditions. When the listener has been stopped the next
 * event or if there's a current unresolved future will resolve with the status
 * code STOPPED.
 *
 * @param listener [in]  The listener.
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_listener_stop(NabtoClientListener* listener);

/********
 * Misc
 ********/

/**
* @intro Misc
*
* Functions for handling buffers, accessing error details, configuring logging and getting the SDK
* version.
*/

/**
 * Free a string, some functions returns a null terminated const char*
 * string. Once finished with using the string it has to be freed
 * again.
 *
 * @param str [in]  The string to free.
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_string_free(char* str);

/**
 * Return an english description of an error code. The returned string
 * must not be freed.
 *
 * @param error [in]  The error for which a message is wanted.
 * @return the error message.
 */
NABTO_CLIENT_DECL_PREFIX const char* NABTO_CLIENT_API
nabto_client_error_get_message(NabtoClientError error);

/**
 * Return the string representation for an error code. The returned
 * string must not be freed.
 *
 * Sample return value NABTO_CLIENT_EC_OK
 *
 * @param error [in]  The error code
 * @return The error string.
 */
NABTO_CLIENT_DECL_PREFIX const char* NABTO_CLIENT_API
nabto_client_error_get_string(NabtoClientError error);

/**
 * Return the version of the nabto client library. The returned string
 * must not be freed.
 *
 * @return The version of the Nabto Client SDK.
 */
NABTO_CLIENT_DECL_PREFIX const char* NABTO_CLIENT_API
nabto_client_version();

/**
 * Set a log callback.
 *
 * The log callback is called synchronously from the core, this means
 * it's not allowed to call any nabto_client_* functions from the log
 * callback as that would result in a deadlock. If it's needed to
 * react on a log message a queue is needed such that the invocation
 * of the nabto client sdk can occur from another thread.
 *
 * @param context [in]  The NabtoClient context to set the log callback on.
 * @param callback [in] The callback function.
 * @param data [in]     Passed to the callback along with the log data.
 * @return NABTO_CLIENT_EC_OK if ok.
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_set_log_callback(NabtoClient* context, NabtoClientLogCallback callback, void* data);

/**
 * Set the SDK log level.
 *
 * This needs to be set as early as possible to ensure modules are
 * initialised with the correct log settings.
 *
 * The default level is info.
 *
 * Lower case string for the desired log level.
 *
 * Allowed strings:
 *
 * Each severity level includes all the less severe levels.
 *
 * @param context [in] The NabtoClient context to set the log level on.
 * @param level [in]   The log level: error, warn, info, debug or trace
 * @retval NABTO_CLIENT_EC_INVALID_ARGUMENT if invalid level
 * @retval NABTO_CLIENT_EC_OK iff successfully set
 */
NABTO_CLIENT_DECL_PREFIX NabtoClientError NABTO_CLIENT_API
nabto_client_set_log_level(NabtoClient* context, const char* level);

#ifdef __cplusplus
} // extern c
#endif

#endif // NABTO_CLIENT_CLIENT_API_H
