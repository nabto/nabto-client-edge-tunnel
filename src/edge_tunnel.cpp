#include <nabto_client.hpp>
#include <nabto/nabto_client_experimental.h>

#include "pairing.hpp"
#include "config.hpp"
#include "timestamp.hpp"

#include <3rdparty/cxxopts.hpp>
#include <3rdparty/nlohmann/json.hpp>

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <thread>
#include <future>

using json = nlohmann::json;

enum {
  COAP_CONTENT_FORMAT_APPLICATION_CBOR = 60
};

// TODO reconnect when connection is closed.

class MyLogger : public nabto::client::Logger
{
 public:
    void log(nabto::client::LogMessage message) {
        std::cout << time_in_HH_MM_SS_MMM() << " [" << message.getSeverity() << "] - " << message.getMessage() << std::endl;
    }
};

std::shared_ptr<nabto::client::Connection> connection_;

void signalHandler(int s){
    printf("Caught signal %d\n",s);
    if (connection_) {
        connection_->close()->waitForResult();
    }
}

static void printMissingClientConfig(const std::string& filename)
{
    std::cerr
        << "The example is missing the client configuration file (" << filename << ")." << std::endl
        << "The client configuration file is a json file which contains" << std::endl
        << "a server key which the client uses when it needs to make a" << std::endl
        << "remote connection." << std::endl
        << "{" << std::endl
        << "  \"ServerKey\": \"<server key from the console>\"," << std::endl
        << "  \"ServerUrl\": \"<optional server url if it is not the default one\"" << std::endl
        << "}" <<std::endl;
}

static bool isPaired(std::shared_ptr<nabto::client::Connection> connection);

bool isPaired(std::shared_ptr<nabto::client::Connection> connection)
{
    auto coap = connection->createCoap("GET", "/pairing/is-paired");

    try {
        coap->execute()->waitForResult();

        return (coap->getResponseStatusCode() == 205);

    } catch(...) {
        std::cerr << "Cannot get pairing state" << std::endl;
        exit(1);
    }
}

class CloseListener : public nabto::client::ConnectionEventsCallback {
 public:

    CloseListener() {
    }
    void onEvent(int event) {
        if (event == NABTO_CLIENT_CONNECTION_EVENT_CLOSED) {
            std::cout << "Connection closed, closing application" << std::endl;
            promise_.set_value();
            return;
        }
    }

    void waitForClose() {
        auto future = promise_.get_future();
        future.get();
    }

 private:
    std::promise<void> promise_;
};

std::shared_ptr<nabto::client::Connection> createConnection(std::shared_ptr<nabto::client::Context> context)
{
    Configuration::ConfigInfo Config;
    if (!Configuration::GetConfigInfo(&Config)) {
        printMissingClientConfig(Configuration::GetConfigFilePath());
        return nullptr;
    }

    auto Device = Configuration::GetPairedDevice(0);
    if (!Device)
    {
        std::cerr << "This client is not paired with any devices." << std::endl;
        return nullptr;
    }

    auto connection = context->createConnection();
    connection->setProductId(Device->ProductID);
    connection->setDeviceId(Device->DeviceID);
    if (Config.ServerUrl) {
        connection->setServerUrl(Config.ServerUrl);
    }
    else
    {
        // TODO(as): ServerUrl was not found.
    }
    connection->setServerKey(Config.ServerKey);
    connection->setServerConnectToken(Device->ServerConnectToken);
    connection->setPrivateKey(Device->PrivateKey);
    try {
        connection->connect()->waitForResult();
    } catch (nabto::client::NabtoException& e) {
        if (e.status().getErrorCode() == nabto::client::Status::NO_CHANNELS) {
            auto localStatus = nabto::client::Status(connection->getLocalChannelErrorCode());
            auto remoteStatus = nabto::client::Status(connection->getRemoteChannelErrorCode());
            std::cerr << "Not Connected." << std::endl;
            std::cerr << " The Local status is: " << localStatus.getDescription() << std::endl;
            std::cerr << " The Remote status is: " << remoteStatus.getDescription() << std::endl;
        } else {
            std::cerr << "Connect failed " << e.what() << std::endl;
        }
        return nullptr;
    }

    try {
        if (connection->getDeviceFingerprintFullHex() != Device->DeviceFingerprint) {
            std::cerr << "device fingerprint does not match the paired fingerprint." << std::endl;
            return nullptr;
        }
    } catch (...) {
        std::cerr << "Missing device fingerprint in state, pair with the device again" << std::endl;
        return nullptr;
    }

    if (!isPaired(connection)) {
        std::cerr << "Client is not paired with device, do the pairing again" << std::endl;
        return nullptr;
    }
    return connection;
}

static void get_service(std::shared_ptr<nabto::client::Connection> connection, const std::string& service);
static void print_service(const nlohmann::json& service);


bool list_services(std::shared_ptr<nabto::client::Connection> connection)
{
    auto coap = connection->createCoap("GET", "/tcp-tunnels/services");
    coap->execute()->waitForResult();
    if (coap->getResponseStatusCode() == 205 &&
        coap->getResponseContentFormat() == COAP_CONTENT_FORMAT_APPLICATION_CBOR)
    {
        auto cbor = coap->getResponsePayload();
        auto data = json::from_cbor(cbor);
        if (data.is_array()) {
            for (auto s : data) {
                get_service(connection, s.get<std::string>());
            }
        }
        return true;
    } else {
        std::cerr << "could not get list of services" << std::endl;
        return false;
    }
}

void get_service(std::shared_ptr<nabto::client::Connection> connection, const std::string& service)
{
    auto coap = connection->createCoap("GET", "/tcp-tunnels/services/" + service);
    coap->execute()->waitForResult();
    if (coap->getResponseStatusCode() == 205 &&
        coap->getResponseContentFormat() == COAP_CONTENT_FORMAT_APPLICATION_CBOR)
    {
        auto cbor = coap->getResponsePayload();
        auto data = json::from_cbor(cbor);
        print_service(data);
    }
}

void print_service(const nlohmann::json& service)
{
    std::string id = service["Id"].get<std::string>();
    std::string type = service["Type"].get<std::string>();
    std::string host = service["Host"].get<std::string>();
    uint16_t port = service["Port"].get<uint16_t>();
    std::cout << "Service: " << id << ", Type: " << type << ", Host: " << host << ", Port: " << port << std::endl;
}

bool tcptunnel(std::shared_ptr<nabto::client::Connection> connection, const std::string& service, uint16_t localPort)
{
    std::shared_ptr<nabto::client::TcpTunnel> tunnel;
    try {
        tunnel = connection->createTcpTunnel();
        tunnel->open(service, localPort)->waitForResult();
    } catch (std::exception& e) {
        std::cout << "Could not open a tunnel to the service " << service << " error: " << e.what() << std::endl;
        return false;
    }

    std::cout << "Opened a TCP Tunnel to the service " << service << " Listening on the local port " << tunnel->getLocalPort() << std::endl;


    // wait for ctrl c
    signal(SIGINT, &signalHandler);

    auto closeListener = std::make_shared<CloseListener>();
    connection->addEventsListener(closeListener);
    connection_ = connection;

    closeListener->waitForClose();
    connection_.reset();
    return true;
}

int main(int argc, char** argv)
{
    cxxopts::Options options("Tunnel client", "Nabto tunnel client example.");

    options.add_options("General")
        ("h,help", "Show help")
        ("version", "Show version")
        ("c,config", "Configutation File", cxxopts::value<std::string>()->default_value("client.json"))
        ("s,state", "State File", cxxopts::value<std::string>()->default_value("tcp_tunnel_client_state.json"))
        ("log-level", "Log level (none|error|info|trace)", cxxopts::value<std::string>()->default_value("error"))
        ("pair", "Pair the client with a tcptunnel device interactively")
        ("pair-url", "Pair with a tcptunnel device using an URL", cxxopts::value<std::string>())
        ;

    options.add_options("TCP Tunnelling")
        ("list-services", "List available services on the device")
        ("service", "Create a tunnel to this service", cxxopts::value<std::string>())
        ("local-port", "Local port to bind tcp listener to", cxxopts::value<uint16_t>()->default_value("0"))
        ;


    try {
        auto result = options.parse(argc, argv);
        if (result.count("help"))
        {
            std::cout << options.help() << std::endl;
            return 0;
        }

        if (result.count("version"))
        {
            std::cout << "nabto_client_sdk: " << nabto::client::Context::version() << std::endl;
            return 0;
        }

        Configuration::Initialize(result["config"].as<std::string>(), result["state"].as<std::string>());
        auto context = nabto::client::Context::create();

        context->setLogger(std::make_shared<MyLogger>());
        context->setLogLevel(result["log-level"].as<std::string>());

        std::string userName = "default";
        const char* user = getenv("USER");
        if (user != NULL) {
            userName = std::string(user);
        }

        if (result.count("pair")) {
            if (!interactive_pair(context, userName)) {
                return 1;
            }
            return 0;
        }
        else if (result.count("pair-url")) {
            if (!link_pair(context, userName, result["pair-url"].as<std::string>())) {
                return 1;
            }
            return 0;
        }
        else if (result.count("list-services") ||
                 result.count("service"))
        {
            auto connection = createConnection(context);
            if (!connection) {
                return 1;
            }

            bool status = false;
            if (result.count("list-services")) {
                status = list_services(connection);
            } else if (result.count("service")) {
                status = tcptunnel(connection, result["service"].as<std::string>(), result["local-port"].as<uint16_t>());
            }

            connection->close()->waitForResult();
            if (status) {
                return 0;
            } else {
                return 1;
            }
        } else {
            std::cout << options.help() << std::endl;
            return 0;
        }
    } catch (...) {
        std::cerr << "Invalid Option" << std::endl;
        std::cout << options.help() << std::endl;
        return 1;
    }
}
