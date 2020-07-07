#pragma once

#include <memory>
#include <functional>
#include <string>
#include <vector>
#include <exception>
#include <cstdint>

namespace nabto {
namespace client {

class Status;

class Status {
 public:

    static const int OK;
    static const int ABORTED;
    static const int BAD_RESPONSE;
    static const int CLOSED;
    static const int DNS;
    static const int END_OF_FILE;
    static const int FORBIDDEN;
    static const int FUTURE_NOT_RESOLVED;
    static const int INVALID_ARGUMENT;
    static const int INVALID_STATE;
    static const int NOT_CONNECTED;
    static const int NOT_FOUND;
    static const int NOT_IMPLEMENTED;
    static const int NO_CHANNELS;
    static const int NO_DATA;
    static const int OPERATION_IN_PROGRESS;
    static const int PARSE;
    static const int PORT_IN_USE;
    static const int STOPPED;
    static const int TIMEOUT;
    static const int UNKNOWN;
    static const int NONE;
    static const int NOT_ATTACHED;
    static const int TOKEN_REJECTED;
    static const int UNAUTHORIZED;

    Status(int errorCode) : errorCode_(errorCode) {}
    bool ok() const;

    /**
     * e.g. Stream has reached "end of file (eof)".
     */
    const char* getDescription() const;

    const char* getName() const;

    int getErrorCode() { return errorCode_; }

 private:
    int errorCode_;
};


class NabtoException : public std::exception
{
 public:
    NabtoException(Status status)
        : status_(status)
    {
    }

    NabtoException(int ec)
        : status_(Status(ec))
    {
    }

    const char* what() const throw()
    {
        return status_.getDescription();
    }

    Status status() const
    {
        return status_;
    }

 private:
    const Status status_;
    std::string w;
};

class LogMessage {
 protected:
    LogMessage(const std::string& message, const std::string& severity)
        : message_(message), severity_(severity)
    {
    }
 public:
    virtual ~LogMessage() {}
    virtual std::string getMessage() { return message_; }
    virtual std::string getSeverity() { return severity_; }
 protected:
    std::string message_;
    std::string severity_;
};

class Logger {
 public:
    virtual ~Logger() {}
    virtual void log(LogMessage message) = 0;
};

class FutureCallback {
 public:
    virtual ~FutureCallback() { }
    virtual void run(Status status) = 0;
};

class Future {
 public:
    virtual ~Future() {}

    virtual void callback(std::shared_ptr<FutureCallback> cb) = 0;
#ifndef SWIGJAVA
    void callback(std::function<void (Status status)> cb);
#endif
};


class FutureVoid : public Future {
 public:
    virtual ~FutureVoid() {}
    virtual void waitForResult() = 0;
    virtual void getResult() = 0;
};

class FutureBuffer : public Future {
 public:
    virtual ~FutureBuffer() {}
    virtual std::vector<uint8_t> waitForResult() = 0;
    virtual std::vector<uint8_t> getResult() = 0;
};

class MdnsResult {
 public:
    virtual ~MdnsResult() {};
    virtual std::string getAddress() = 0;
    virtual int getPort() = 0;
    virtual std::string getDeviceId() = 0;
    virtual std::string getProductId() = 0;
};

class FutureMdnsResult : public Future {
 public:
    virtual ~FutureMdnsResult() {}
    virtual std::shared_ptr<MdnsResult> waitForResult() = 0;
    virtual std::shared_ptr<MdnsResult> getResult() = 0;
};

class MdnsResolver {
 public:
    virtual ~MdnsResolver() {};
    virtual std::shared_ptr<FutureMdnsResult> getResult() = 0;
    virtual void stop() = 0;
};

class Coap {
 public:
    virtual ~Coap() {};
    virtual void setRequestPayload(int contentFormat, const std::vector<uint8_t>& buffer) = 0;
    virtual std::shared_ptr<FutureVoid> execute() = 0;
    virtual int getResponseStatusCode() = 0;
    virtual int getResponseContentFormat() = 0;
    virtual std::vector<uint8_t> getResponsePayload() = 0;
};

class Stream {
 public:
    virtual ~Stream() {};
    virtual std::shared_ptr<FutureVoid> open(uint32_t contentType) = 0;
    virtual std::shared_ptr<FutureBuffer> readAll(size_t n) = 0;
    virtual std::shared_ptr<FutureBuffer> readSome(size_t max) = 0;
    virtual std::shared_ptr<FutureVoid> write(const std::vector<uint8_t>& buffer) = 0;
    virtual std::shared_ptr<FutureVoid> close() = 0;
    virtual void abort() = 0;
};

class TcpTunnel {
 public:
    virtual ~TcpTunnel() {};
    virtual uint16_t getLocalPort() = 0;
    virtual std::shared_ptr<FutureVoid> open(const std::string& service, uint16_t localPort) = 0;
    virtual std::shared_ptr<FutureVoid> close() = 0;
};

class ConnectionEventsCallback {
 public:
    static int CLOSED();
    static int CONNECTED();
    static int CHANNEL_CHANGED();

    virtual ~ConnectionEventsCallback() {}
    virtual void onEvent(int event) {}
};

class Connection {
 public:
    virtual ~Connection() {};
    virtual void setProductId(const std::string& productId) = 0;
    virtual void setDeviceId(const std::string& deviceId) = 0;
    virtual void setApplicationName(const std::string& applicationName) = 0;
    virtual void setApplicationVersion(const std::string& applicationVersion) = 0;
    virtual void setServerUrl(const std::string& serverUrl) = 0;
    virtual void setServerKey(const std::string& serverKey) = 0;
    virtual void setServerJwtToken(const std::string& serverJwtToken) = 0;
    virtual void setServerConnectToken(const std::string& serverConnectToken) = 0;
    virtual void setPrivateKey(const std::string& privateKey) = 0;
    virtual void setOptions(const std::string& options) = 0;
    virtual std::string getOptions() = 0;
    virtual std::string getDeviceFingerprintHex() = 0;
    virtual std::string getClientFingerprintHex() = 0;
    virtual std::string getDeviceFingerprintFullHex() = 0;
    virtual std::string getClientFingerprintFullHex() = 0;
    virtual std::string getInfo() = 0;
    virtual int getLocalChannelErrorCode() = 0;
    virtual int getRemoteChannelErrorCode() = 0;
    virtual void enableDirectCandidates() = 0;
    virtual void addDirectCandidate(const std::string& hostname, uint16_t port) = 0;
    virtual void endOfDirectCandidates() = 0;

    virtual void addEventsListener(std::shared_ptr<ConnectionEventsCallback> callback) = 0;
    virtual void removeEventsListener(std::shared_ptr<ConnectionEventsCallback> callback) = 0;

    virtual std::shared_ptr<FutureVoid> connect() = 0;
    virtual std::shared_ptr<Stream> createStream() = 0;
    virtual std::shared_ptr<FutureVoid> close() = 0;
    virtual std::shared_ptr<Coap> createCoap(const std::string& method, const std::string& path) = 0;
    virtual std::shared_ptr<TcpTunnel> createTcpTunnel() = 0;
};

class Context {
 public:
    // shared_ptr as swig does not understand unique_ptr yet.
    static std::shared_ptr<Context> create();
    virtual ~Context() {};
    virtual std::shared_ptr<Connection> createConnection() = 0;
    virtual std::shared_ptr<MdnsResolver> createMdnsResolver() = 0;
    virtual void setLogger(std::shared_ptr<Logger> logger) = 0;
    virtual void setLogLevel(const std::string& level) = 0;
    virtual std::string createPrivateKey() = 0;
    static std::string version();
#ifdef __ANDROID__
    virtual void setAndroidWifiNetworkHandle(uint64_t handle) = 0;
#endif
};

#ifndef SWIGJAVA
class CallbackFunction : public FutureCallback {
 public:

    CallbackFunction(std::function<void (Status status)> cb)
        : cb_(cb)
    {

    }

    void run(Status status) {

        cb_(status);
    }
 private:
    std::function<void (Status status)> cb_;
};
#endif

} } // namespace
