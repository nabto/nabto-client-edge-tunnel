#include <nabto_client.hpp>
#include <nabto/nabto_client_experimental.h>

#include "pairing.hpp"
#include "config.hpp"
#include "timestamp.hpp"
#include "iam.h"

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

std::shared_ptr<nabto::client::Connection> createConnection(std::shared_ptr<nabto::client::Context> context, uint32_t SelectedBookmark)
{
    Configuration::ConfigInfo Config;
    if (!Configuration::GetConfigInfo(&Config)) {
        printMissingClientConfig(Configuration::GetConfigFilePath());
        return nullptr;
    }

    auto Device = Configuration::GetPairedDevice(SelectedBookmark);
    if (!Device)
    {
        std::cerr << "This client does not have a device with bookmark index " << SelectedBookmark << std::endl;
        if (SelectedBookmark == 0)
        {
            // If no bookmark was found at index 0, then this client isn't paired with anything.
            std::cerr << "This client has no bookmarked devices, maybe you should try pairing with a device?" << std::endl;
        }
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
        ("H,home", "Override the directory in which configuration files are saved to.", cxxopts::value<std::string>())
        ("log-level", "Log level (none|error|info|trace)", cxxopts::value<std::string>()->default_value("error"))
        ("list-bookmarks", "List bookmarked devices")
        ("b,bookmark", "Select a bookmarked device to use with other commands.", cxxopts::value<uint32_t>()->default_value("0"))
        ("pair", "Pair the client with a tcptunnel device interactively")
        ("pair-url", "Pair with a tcptunnel device using an URL", cxxopts::value<std::string>())
        ;

    options.add_options("IAM")
        ("users", "List all users on selected device.")
        ("roles", "List roles available on device.")
        ("add-role", "Add a role to a user on device.", cxxopts::value<std::string>())
        ("remove-role", "Remove a role from a user on device.", cxxopts::value<std::string>())
        ("role", "Used in conjunction with --add-role and --remove-role.", cxxopts::value<std::string>())
        ("delete-user", "Delete a user on device.", cxxopts::value<std::string>())
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

        if (result.count("home"))
        {
            Configuration::InitializeWithDirectory(result["home"].as<std::string>());
        }
        else
        {
            Configuration::Initialize();
        }

        if (result.count("list-bookmarks"))
        {
            Configuration::PrintBookmarks();
            return 0;
        }

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
                 result.count("service") ||
                 result.count("users") ||
                 result.count("roles") ||
                 result.count("add-role") ||
                 result.count("remove-role") ||
                 result.count("role") ||
                 result.count("delete-user"))
        {
            auto connection = createConnection(context, result["bookmark"].as<uint32_t>());
            if (!connection) {
                // TODO(ahs): Investigate why the connection did not open, and print more appropriate error for the user.
                std::cout << "Could not open connection" << std::endl;
                return 1;
            }

            bool status = false;
            if (result.count("list-services")) {
                status = list_services(connection);
            } else if (result.count("service")) {
                status = tcptunnel(connection, result["service"].as<std::string>(), result["local-port"].as<uint16_t>());
            } else if (result.count("users")) {
                status = IAM::list_users(connection);
            } else if (result.count("roles")) {
                status = IAM::list_roles(connection);
            } else if (result.count("add-role")) {
                if (result.count("role")) {
                    status = IAM::add_role_to_user(connection, result["add-role"].as<std::string>(), result["role"].as<std::string>());
                } else {
                    std::cout
                    << "You've used the --add-role option without specifying which role to add.\n"
                    << "Use --role to specify a role that you want to add to this user."
                    << std::endl;
                }
            } else if (result.count("remove-role")) {
                if (result.count("role")) {
                    status = IAM::remove_role_from_user(connection, result["remove-role"].as<std::string>(), result["role"].as<std::string>());
                } else {
                    std::cout
                    << "You've used the --remove-role option without specifying which role to remove.\n"
                    << "Use the --role option to specify a role that you want to remove from this user."
                    << std::endl;
                }
            } else if (result.count("role")) {
                std::cout
                << "You've used the --role option without specifying a user.\n"
                << "Use --add-role to specify a user that you want to add the role to."
                << "Use --remove-role to specify a user that you want to remove the role from."
                << std::endl;
            } else if (result.count("delete-user")) {
                status = IAM::delete_user(connection, result["delete-user"].as<std::string>());
            }

            connection->close()->waitForResult();
            return status ? 0 : 1;
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
