#pragma once
#include "nabto_client.hpp"
#include <nabto/nabto_client.h>
#include <nabto/nabto_client_experimental.h>

#ifdef __ANDROID__
#include <nabto/nabto_client_android.h>
#endif

#include <thread>
#include <mutex>
#include <set>

namespace nabto {
namespace client {

const int Status::OK = NABTO_CLIENT_EC_OK;
const int Status::ABORTED = NABTO_CLIENT_EC_ABORTED;
const int Status::BAD_RESPONSE = NABTO_CLIENT_EC_BAD_RESPONSE;
const int Status::CLOSED = NABTO_CLIENT_EC_CLOSED;
const int Status::DNS = NABTO_CLIENT_EC_DNS;
const int Status::END_OF_FILE = NABTO_CLIENT_EC_EOF;
const int Status::FORBIDDEN =  NABTO_CLIENT_EC_FORBIDDEN;
const int Status::FUTURE_NOT_RESOLVED =  NABTO_CLIENT_EC_FUTURE_NOT_RESOLVED;
const int Status::INVALID_ARGUMENT =  NABTO_CLIENT_EC_INVALID_ARGUMENT;
const int Status::INVALID_STATE =  NABTO_CLIENT_EC_INVALID_STATE;
const int Status::NOT_CONNECTED =  NABTO_CLIENT_EC_NOT_CONNECTED;
const int Status::NOT_FOUND =  NABTO_CLIENT_EC_NOT_FOUND;
const int Status::NOT_IMPLEMENTED =  NABTO_CLIENT_EC_NOT_IMPLEMENTED;
const int Status::NO_CHANNELS =  NABTO_CLIENT_EC_NO_CHANNELS;
const int Status::NO_DATA =  NABTO_CLIENT_EC_NO_DATA;
const int Status::OPERATION_IN_PROGRESS =  NABTO_CLIENT_EC_OPERATION_IN_PROGRESS;
const int Status::PARSE =  NABTO_CLIENT_EC_PARSE;
const int Status::PORT_IN_USE =  NABTO_CLIENT_EC_PORT_IN_USE;
const int Status::STOPPED =  NABTO_CLIENT_EC_STOPPED;
const int Status::TIMEOUT =  NABTO_CLIENT_EC_TIMEOUT;
const int Status::UNKNOWN =  NABTO_CLIENT_EC_UNKNOWN;
const int Status::NONE = NABTO_CLIENT_EC_NONE;
const int Status::NOT_ATTACHED = NABTO_CLIENT_EC_NOT_ATTACHED;
const int Status::TOKEN_REJECTED = NABTO_CLIENT_EC_TOKEN_REJECTED;
const int Status::UNAUTHORIZED = NABTO_CLIENT_EC_UNAUTHORIZED;


const char* Status::getDescription() const {
    return nabto_client_error_get_message(errorCode_);
}

const char* Status::getName() const {
    return nabto_client_error_get_string(errorCode_);
}

bool Status::ok() const {
    return errorCode_ == 0;
}

class FutureBufferImpl : public FutureBuffer, public std::enable_shared_from_this<FutureBufferImpl>
{
 public:
    FutureBufferImpl(NabtoClient* context, std::shared_ptr<std::vector<uint8_t> > data, std::shared_ptr<size_t> transferred)
        : future_(nabto_client_future_new(context)), data_(data), transferred_(transferred)
    {
    }
    FutureBufferImpl(NabtoClientFuture* future, std::shared_ptr<std::vector<uint8_t> > data, std::shared_ptr<size_t> transferred)
        : future_(future), data_(data), transferred_(transferred)
    {
    }
    ~FutureBufferImpl()
    {
        if (!ended_) {
            auto c = std::make_shared<FutureBufferImpl>(future_, data_, transferred_);
            c->callback(std::make_shared<CallbackFunction>([](Status){ /* do nothing */ }));
        } else {
            nabto_client_future_free(future_);
        }
    }

    std::vector<uint8_t> waitForResult()
    {
        nabto_client_future_wait(future_);
        ended_ = true;
        return getResult();
    }
    static void doCallback(NabtoClientFuture* future, NabtoClientError ec, void* data)
    {
        FutureBufferImpl* self = (FutureBufferImpl*)data;
        self->ended_ = true;
        self->cb_->run(Status(ec));
        self->selfReference_ = nullptr;
    }
    void callback(std::shared_ptr<FutureCallback> cb)
    {
        cb_ = cb;
        selfReference_ = shared_from_this();
        nabto_client_future_set_callback(future_,
                                         &doCallback,
                                         this);
    }
    std::vector<uint8_t> getResult() {
        auto ec = nabto_client_future_error_code(future_);
        if (ec) {
            throw NabtoException(ec);
        }
        data_->resize(*transferred_);
        return *data_;
    }
    NabtoClientFuture* getFuture() {
        return future_;
    }
  private:
    NabtoClientFuture* future_;
    std::shared_ptr<std::vector<uint8_t> > data_;
    std::shared_ptr<size_t> transferred_;
    std::shared_ptr<FutureBufferImpl> selfReference_;
    std::shared_ptr<FutureCallback> cb_;
    bool ended_ = false;
};


class MdnsResultImpl : public MdnsResult {
 public:
    MdnsResultImpl(NabtoClientMdnsResult* result)
        : result_(result)
    {
    }
    ~MdnsResultImpl() {
        nabto_client_mdns_result_free(result_);
    }
    virtual std::string getAddress()
    {
        const char* str;
        auto ec = nabto_client_mdns_result_get_address(result_, &str);
        if (ec) {
            throw NabtoException(ec);
        }
        return std::string(str);
    }

    virtual int getPort()
    {
        uint16_t port;
        auto ec = nabto_client_mdns_result_get_port(result_, &port);
        if (ec) {
            throw NabtoException(ec);
        }
        return port;
    }

    virtual std::string getDeviceId()
    {
        const char* str;
        auto ec = nabto_client_mdns_result_get_device_id(result_, &str);
        if (ec) {
            throw NabtoException(ec);
        }
        return std::string(str);
    }

    virtual std::string getProductId()
    {
        const char* str;
        auto ec = nabto_client_mdns_result_get_product_id(result_, &str);
        if (ec) {
            throw NabtoException(ec);
        }
        return std::string(str);
    }
 private:
    NabtoClientMdnsResult* result_;
};


class FutureMdnsResultImpl : public FutureMdnsResult, public std::enable_shared_from_this<FutureMdnsResultImpl>
{
 public:
    FutureMdnsResultImpl(NabtoClient* context)
        : future_(nabto_client_future_new(context))
    {
    }
    FutureMdnsResultImpl(NabtoClientFuture* future)
        : future_(future)
    {
    }
    ~FutureMdnsResultImpl()
    {
        if (!ended_) {
            auto c = std::make_shared<FutureMdnsResultImpl>(future_);
            c->callback(std::make_shared<CallbackFunction>([](Status){ /* do nothing */ }));
        } else {
            nabto_client_future_free(future_);
        }
    }

    std::shared_ptr<MdnsResult> waitForResult()
    {
        nabto_client_future_wait(future_);
        ended_ = true;
        return getResult();
    }
    static void doCallback(NabtoClientFuture* future, NabtoClientError ec, void* data)
    {
        FutureMdnsResultImpl* self = (FutureMdnsResultImpl*)data;
        self->ended_ = true;
        self->cb_->run(Status(ec));
        self->selfReference_ = nullptr;
    }

    void callback(std::shared_ptr<FutureCallback> cb)
    {
        cb_ = cb;
        selfReference_ = shared_from_this();
        nabto_client_future_set_callback(future_,
                                         &doCallback,
                                         this);
    }
    std::shared_ptr<MdnsResult> getResult() {
        auto ec = nabto_client_future_error_code(future_);
        if (ec) {
            throw NabtoException(ec);
        }
        return std::make_shared<MdnsResultImpl>(result_);
    }
    NabtoClientFuture* getFuture() {
        return future_;
    }

    NabtoClientMdnsResult* result_;

  private:
    NabtoClientFuture* future_;
    std::shared_ptr<FutureMdnsResultImpl> selfReference_;
    std::shared_ptr<FutureCallback> cb_;
    bool ended_ = false;
};

class FutureVoidImpl : public FutureVoid, public std::enable_shared_from_this<FutureVoidImpl> {
 public:
    FutureVoidImpl(NabtoClient* context)
        : future_(nabto_client_future_new(context))
    {
    }

    FutureVoidImpl(NabtoClient* context,  std::shared_ptr<std::vector<uint8_t> > data)
        : future_(nabto_client_future_new(context)), data_(data)
    {
    }

    FutureVoidImpl(NabtoClientFuture* future, std::shared_ptr<std::vector<uint8_t> > data)
        : future_(future), data_(data)
    {
    }
    FutureVoidImpl(NabtoClientFuture* future)
        : future_(future)
    {
    }
    ~FutureVoidImpl()
    {
        if (!ended_) {
            auto c = std::make_shared<FutureVoidImpl>(future_, data_);
            c->callback(std::make_shared<CallbackFunction>([](Status){ /* do nothing */ }));
        } else {
            nabto_client_future_free(future_);
        }
    }
    // waitForResult for result.
    void waitForResult() {
        nabto_client_future_wait(future_);
        ended_ = true;
        return getResult();
    }

    static void doCallback(NabtoClientFuture* future, NabtoClientError ec, void* data)
    {
        FutureVoidImpl* self = (FutureVoidImpl*)data;
        self->ended_ = true;
        self->cb_->run(Status(ec));
        self->selfReference_ = nullptr;
    }

    //bool waitFor(int milliseconds) = 0;
    void callback(std::shared_ptr<FutureCallback> cb)
    {
        cb_ = cb;
        selfReference_ = shared_from_this();
        nabto_client_future_set_callback(future_,
                                         &doCallback,
                                         this);
    }
    void getResult() {
        auto ec = nabto_client_future_error_code(future_);
        if (ec) {
            throw NabtoException(ec);
        }
    }

    NabtoClientFuture* getFuture() {
        return future_;
    }
 private:
    NabtoClientFuture* future_;
    std::shared_ptr<std::vector<uint8_t> > data_;
    std::shared_ptr<FutureVoidImpl> selfReference_;
    std::shared_ptr<FutureCallback> cb_;
    bool ended_ = false;
};


class MdnsResolverImpl : public MdnsResolver {
 public:
    MdnsResolverImpl(NabtoClient* context)
        : context_(context)
    {
        resolver_ = nabto_client_listener_new(context);
        nabto_client_mdns_resolver_init_listener(context, resolver_);
    }
    ~MdnsResolverImpl()
    {
        nabto_client_listener_free(resolver_);
    }
    virtual std::shared_ptr<FutureMdnsResult> getResult()
    {
        auto future = std::make_shared<FutureMdnsResultImpl>(context_);
        nabto_client_listener_new_mdns_result(resolver_, future->getFuture(), &future->result_);
        return future;
    }
    virtual void stop() {
        nabto_client_listener_stop(resolver_);
    }
 private:
    NabtoClientListener* resolver_;
    NabtoClient* context_;
};

class CoapImpl : public Coap {
 public:
    CoapImpl(NabtoClient* context, NabtoClientCoap* coap)
        : context_(context)
    {
        request_ = coap;
    }
    ~CoapImpl() {
        nabto_client_coap_free(request_);
    };

    static std::shared_ptr<CoapImpl> create(NabtoClient* context, NabtoClientConnection* connection, const std::string& method, const std::string& path)
    {
        auto request_ = nabto_client_coap_new(connection, method.c_str(), path.c_str());
        if (!request_) {
            return nullptr;
        }
        return std::make_shared<CoapImpl>(context, request_);
    }

    void setRequestPayload(int contentFormat, const std::vector<uint8_t>& payload)
    {
        NabtoClientError ec;
        ec = nabto_client_coap_set_request_payload(request_, contentFormat, payload.data(), payload.size());

        if (ec) {
            throw NabtoException(ec);
        }
    }

    std::shared_ptr<FutureVoid> execute()
    {
        auto future = std::make_shared<FutureVoidImpl>(context_);
        nabto_client_coap_execute(request_, future->getFuture());
        return future;
    }

    int getResponseStatusCode()
    {
        NabtoClientError ec;
        uint16_t statusCode;
        ec = nabto_client_coap_get_response_status_code(request_, &statusCode);
        if (ec) {
            throw NabtoException(ec);
        }
        return statusCode;
    }
    int getResponseContentFormat() {
        NabtoClientError ec;
        uint16_t contentFormat;
        ec = nabto_client_coap_get_response_content_format(request_, &contentFormat);
        if (ec == NABTO_CLIENT_EC_NO_DATA) {
            return -1;
        } else if (ec) {
            throw NabtoException(ec);
        }
        return contentFormat;
    }
    std::vector<uint8_t> getResponsePayload() {
        void* payload;
        size_t payloadLength;
        NabtoClientError ec = nabto_client_coap_get_response_payload(request_, &payload, &payloadLength);
        if (ec != NABTO_CLIENT_EC_OK) {
            return std::vector<uint8_t>();
        }
        const uint8_t* begin = reinterpret_cast<const uint8_t*>(payload);
        const uint8_t* end = begin + payloadLength;
        auto ret = std::vector<uint8_t>(begin, end);
        return ret;
    }

 private:
    NabtoClientCoap* request_;
    NabtoClient* context_;
};


class StreamImpl : public Stream {
 public:
    StreamImpl(NabtoClientConnection* connection, NabtoClient* context)
        : context_(context)
    {
        stream_ = nabto_client_stream_new(connection);
    }
    ~StreamImpl() {
        nabto_client_stream_free(stream_);
    }
    std::shared_ptr<FutureVoid> open(uint32_t contentType)
    {
        auto future = std::make_shared<FutureVoidImpl>(context_);
        nabto_client_stream_open(stream_, future->getFuture(), contentType);
        return future;
    }
    std::shared_ptr<FutureBuffer> readAll(size_t n)
    {
        auto data = std::make_shared<std::vector<uint8_t> >(n);
        auto transferred = std::make_shared<size_t>();
        auto future = std::make_shared<FutureBufferImpl>(context_,data, transferred);
        nabto_client_stream_read_all(stream_, future->getFuture(), data->data(), data->size(), transferred.get());
        return future;
    }
    std::shared_ptr<FutureBuffer> readSome(size_t max)
    {
        auto data = std::make_shared<std::vector<uint8_t> >(max);
        auto transferred = std::make_shared<size_t>();
        auto future = std::make_shared<FutureBufferImpl>(context_, data, transferred);
        nabto_client_stream_read_some(stream_, future->getFuture(), data->data(), data->size(), transferred.get());
        return future;
    }
    std::shared_ptr<FutureVoid> write(const std::vector<uint8_t>& buffer)
    {
        auto data = std::make_shared<std::vector<uint8_t> >(buffer.begin(), buffer.end());
        auto future = std::make_shared<FutureVoidImpl>(context_, data);
        nabto_client_stream_write(stream_, future->getFuture(), data->data(), data->size());
        return future;
    }
    std::shared_ptr<FutureVoid> close()
    {
        auto future = std::make_shared<FutureVoidImpl>(context_);
        nabto_client_stream_close(stream_, future->getFuture());
        return future;
    }
    void abort()
    {
        nabto_client_stream_abort(stream_);
    }
 private:
    NabtoClientStream* stream_;
    NabtoClient* context_;
};

class TcpTunnelImpl : public TcpTunnel {
 public:
    TcpTunnelImpl(NabtoClient* context, NabtoClientConnection* connection)
        : context_(context)
    {
        tcpTunnel_ = nabto_client_tcp_tunnel_new(connection);
    }
    virtual ~TcpTunnelImpl() {
        nabto_client_tcp_tunnel_free(tcpTunnel_);
    };
    virtual std::shared_ptr<FutureVoid> open(const std::string& service, uint16_t localPort)
    {
        auto future = std::make_shared<FutureVoidImpl>(context_);
        nabto_client_tcp_tunnel_open(tcpTunnel_, future->getFuture(), service.c_str(), localPort);
        return future;
    }

    virtual std::shared_ptr<FutureVoid> close()
    {
        auto future = std::make_shared<FutureVoidImpl>(context_);
        nabto_client_tcp_tunnel_close(tcpTunnel_, future->getFuture());
        return future;
    }

    virtual uint16_t getLocalPort()
    {
        uint16_t localPort;
        NabtoClientError ec = nabto_client_tcp_tunnel_get_local_port(tcpTunnel_, &localPort);
        if (ec) {
            throw NabtoException(ec);
        }
        return localPort;
    }
 private:
    NabtoClientTcpTunnel* tcpTunnel_;
    NabtoClient* context_;
};


class ConnectionImpl;

class ConnectionEventsListenerImpl {
 public:
    ConnectionEventsListenerImpl(NabtoClient* context, NabtoClientConnection* connection, std::shared_ptr<ConnectionImpl> connectionImpl);

    void init()
    {
        NabtoClientError ec = nabto_client_connection_events_init_listener(connection_, listener_);
        if (ec) {
            throw NabtoException(ec);
        }
        listen();
    }

    virtual ~ConnectionEventsListenerImpl();

    void listen()
    {
        nabto_client_listener_connection_event(listener_, future_, &event_);
        nabto_client_future_set_callback(future_, ConnectionEventsListenerImpl::futureCallback, this);
    }

    static void futureCallback(NabtoClientFuture* future, NabtoClientError ec, void* data);

    void stop() {
        nabto_client_listener_stop(listener_);
    }

 private:
    NabtoClientConnection* connection_;
    std::weak_ptr<ConnectionImpl> connectionImpl_;
    int event_;
    NabtoClientListener* listener_;
    NabtoClientFuture* future_;
};

class ConnectionImpl : public Connection, public std::enable_shared_from_this<ConnectionImpl> {
 public:
    ConnectionImpl(NabtoClient* context)
        : context_(context)
    {
        connection_ = nabto_client_connection_new(context);
    }
    ~ConnectionImpl() {
        connectionEventsListener_->stop();
        nabto_client_connection_free(connection_);
    }

    void init() {
        connectionEventsListener_ = std::make_shared<ConnectionEventsListenerImpl>(context_, connection_, shared_from_this());
        connectionEventsListener_->init();
    }

    void setProductId(const std::string& productId)
    {
        NabtoClientError ec = nabto_client_connection_set_product_id(connection_, productId.c_str());
        if (ec) {
            throw NabtoException(ec);
        }
    }
    void setDeviceId(const std::string& deviceId)
    {
        NabtoClientError ec = nabto_client_connection_set_device_id(connection_, deviceId.c_str());
        if (ec) {
            throw NabtoException(ec);
        }
    }
    void setServerKey(const std::string& serverKey)
    {
        NabtoClientError ec = nabto_client_connection_set_server_key(connection_, serverKey.c_str());
        if (ec) {
            throw NabtoException(ec);
        }
    }

    void setApplicationName(const std::string& applicationName)
    {
        NabtoClientError ec = nabto_client_connection_set_application_name(connection_, applicationName.c_str());
        if (ec) {
            throw NabtoException(ec);
        }
    }
    void setApplicationVersion(const std::string& applicationVersion)
    {
        NabtoClientError ec = nabto_client_connection_set_application_version(connection_, applicationVersion.c_str());
        if (ec) {
            throw NabtoException(ec);
        }
    }

    void setServerUrl(const std::string& serverUrl)
    {
        NabtoClientError ec = nabto_client_connection_set_server_url(connection_, serverUrl.c_str());
        if (ec) {
            throw NabtoException(ec);
        }
    }
    void setServerJwtToken(const std::string& serverJwtToken)
    {
        NabtoClientError ec = nabto_client_connection_set_server_jwt_token(connection_, serverJwtToken.c_str());
        if (ec) {
            throw NabtoException(ec);
        }
    }
    void setServerConnectToken(const std::string& serverConnectToken)
    {
        NabtoClientError ec = nabto_client_connection_set_server_connect_token(connection_, serverConnectToken.c_str());
        if (ec) {
            throw NabtoException(ec);
        }
    }

    void setPrivateKey(const std::string& privateKey)
    {
        NabtoClientError ec = nabto_client_connection_set_private_key(connection_, privateKey.c_str());
        if (ec) {
            throw NabtoException(ec);
        }
    }

    void setOptions(const std::string& options)
    {
        NabtoClientError ec = nabto_client_connection_set_options(connection_, options.c_str());
        if (ec) {
            throw NabtoException(ec);
        }
    }

    std::string getOptions()
    {
        char* options;
        auto ec = nabto_client_connection_get_options(connection_, &options);
        if (ec) {
            throw NabtoException(ec);
        }
        std::string str(options);
        nabto_client_string_free(options);
        return str;
    }

    std::string getDeviceFingerprintHex()
    {
        char* f;
        auto ec = nabto_client_connection_get_device_fingerprint_hex(connection_, &f);
        if (ec) {
            throw NabtoException(ec);
        }
        auto str = std::string(f);
        nabto_client_string_free(f);
        return str;
    }

    std::string getClientFingerprintHex()
    {
        char* f;
        auto ec = nabto_client_connection_get_client_fingerprint_hex(connection_, &f);
        if (ec) {
            throw NabtoException(ec);
        }
        auto str = std::string(f);
        nabto_client_string_free(f);
        return str;
    }
    std::string getDeviceFingerprintFullHex()
    {
        char* f;
        auto ec = nabto_client_connection_get_device_fingerprint_full_hex(connection_, &f);
        if (ec) {
            throw NabtoException(ec);
        }
        auto str = std::string(f);
        nabto_client_string_free(f);
        return str;
    }

    std::string getClientFingerprintFullHex()
    {
        char* f;
        auto ec = nabto_client_connection_get_client_fingerprint_full_hex(connection_, &f);
        if (ec) {
            throw NabtoException(ec);
        }
        auto str = std::string(f);
        nabto_client_string_free(f);
        return str;
    }

    std::string getInfo()
    {
        char* info;
        auto ec = nabto_client_connection_get_info(connection_, &info);
        if (ec) {
            throw NabtoException(ec);
        }
        auto str = std::string(info);
        nabto_client_string_free(info);
        return str;
    }

    int getLocalChannelErrorCode() {
        return (int)nabto_client_connection_get_local_channel_error_code(connection_);
    }

    int getRemoteChannelErrorCode() {
        return (int)nabto_client_connection_get_remote_channel_error_code(connection_);
    }

    void enableDirectCandidates()
    {
        NabtoClientError ec = nabto_client_connection_enable_direct_candidates(connection_);
        if (ec) {
            throw NabtoException(ec);
        }
    }

    void addDirectCandidate(const std::string& hostname, uint16_t port)
    {
        NabtoClientError ec = nabto_client_connection_add_direct_candidate(connection_, hostname.c_str(), port);
        if (ec) {
            throw NabtoException(ec);
        }
    }

    void endOfDirectCandidates()
    {
        NabtoClientError ec = nabto_client_connection_end_of_direct_candidates(connection_);
        if (ec) {
            throw NabtoException(ec);
        }
    }

    std::shared_ptr<FutureVoid> connect()
    {
        auto future = std::make_shared<FutureVoidImpl>(context_);
        nabto_client_connection_connect(connection_, future->getFuture());
        return future;
    }
    std::shared_ptr<Stream> createStream()
    {
        return std::make_shared<StreamImpl>(connection_, context_);
    }
    std::shared_ptr<FutureVoid> close()
    {
        auto future = std::make_shared<FutureVoidImpl>(context_);
        nabto_client_connection_close(connection_, future->getFuture());
        return future;
    }

    std::shared_ptr<Coap> createCoap(const std::string& method, const std::string& path)
    {
        return CoapImpl::create(context_, connection_, method, path);
    }

    std::shared_ptr<TcpTunnel> createTcpTunnel()
    {
        return std::make_shared<TcpTunnelImpl>(context_, connection_);
    }

    void notifyEvent(int event) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto cb : eventsCallbacks_) {
            cb->onEvent(event);
        }
    }

    void addEventsListener(std::shared_ptr<ConnectionEventsCallback> callback)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        eventsCallbacks_.insert(callback);

    }
    void removeEventsListener(std::shared_ptr<ConnectionEventsCallback> callback)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        eventsCallbacks_.erase(callback);
    }

 private:
    NabtoClientConnection* connection_;
    NabtoClient* context_;
    std::mutex mutex_;
    std::set<std::shared_ptr<ConnectionEventsCallback> > eventsCallbacks_;
    std::shared_ptr<ConnectionEventsListenerImpl> connectionEventsListener_;
};

class LogMessageImpl : public LogMessage {
 public:
    ~LogMessageImpl() {
    }
    LogMessageImpl(const std::string& message, const std::string& severity)
        : LogMessage(message, severity)
    {
    }
};

class LoggerProxy {
 public:
    LoggerProxy(std::shared_ptr<Logger> logger, NabtoClient* context)
        : logger_(logger)
    {
        nabto_client_set_log_callback(context, &LoggerProxy::cLogCallback, this);
    }

    static void cLogCallback(const NabtoClientLogMessage* message, void* userData)
    {
        LoggerProxy* proxy = (LoggerProxy*)userData;
        LogMessageImpl msg = LogMessageImpl(message->message, message->severityString);
        proxy->logger_->log(msg);
    }

 private:
    std::shared_ptr<Logger> logger_;
};

class ContextImpl : public Context {
 public:
    ContextImpl() {
        context_ = nabto_client_new();
    }
    ~ContextImpl() {
        nabto_client_stop(context_);
        nabto_client_free(context_);
    }

    std::shared_ptr<Connection> createConnection() {
        auto ptr = std::make_shared<ConnectionImpl>(context_);
        ptr->init();
        return ptr;
    }

    std::shared_ptr<MdnsResolver> createMdnsResolver() {
        return std::make_shared<MdnsResolverImpl>(context_);
    }

    void setLogger(std::shared_ptr<Logger> logger) {
        // todo test return value.
        loggerProxy_ = std::make_shared<LoggerProxy>(logger, context_);
    }

    void setLogLevel(const std::string& level) {
        NabtoClientError ec = nabto_client_set_log_level(context_, level.c_str());
        if (ec) {
            throw NabtoException(ec);
        }
    }

    std::string createPrivateKey() {
        char* privateKey;
        auto ec = nabto_client_create_private_key(context_, &privateKey);
        if (ec) {
            throw NabtoException(ec);
        }
        auto ret = std::string(privateKey);
        nabto_client_string_free(privateKey);
        return ret;
    }

#ifdef __ANDROID__
    void setAndroidWifiNetworkHandle(uint64_t handle) {
        nabto_client_android_set_wifi_network_handle(context_, handle);
    }
#endif

 private:
    NabtoClient* context_;
    std::shared_ptr<LoggerProxy> loggerProxy_;

};

std::string Context::version() {
    return std::string(nabto_client_version());
}

std::shared_ptr<Context> Context::create()
{
    return std::make_shared<ContextImpl>();
}

void Future::callback(std::function<void (Status status)> cb)
{
    callback(std::make_shared<CallbackFunction>(cb));
}

} } // namespace
