#include "pairing.hpp"

#include "json_config.hpp"
#include "scanner.hpp"

#include <3rdparty/nlohmann/json.hpp>
#include <iostream>
#include <sstream>

namespace nabto {
namespace examples {
namespace common {

const static int CONTENT_FORMAT_APPLICATION_CBOR = 60; // rfc 7059

enum class PairingMode {
    NONE,
    BUTTON,
    PASSWORD,
    LOCAL
};

std::string pairingModeAsString(PairingMode mode) {
    if (mode == PairingMode::BUTTON) {
        return "Button";
    } else if (mode == PairingMode::PASSWORD) {
        return "Password";
    } else if (mode == PairingMode::LOCAL) {
        return "Local";
    }
    return "unknown";
}

PairingMode get_pairing_mode(std::shared_ptr<nabto::client::Connection> connection)
{

    std::vector<PairingMode> supportedModes;

    auto coap = connection->createCoap("GET", "/pairing");
    coap->execute()->waitForResult();
    if (coap->getResponseStatusCode() != 205) {
        std::string reason;
        auto buffer = coap->getResponsePayload();
        reason = std::string(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::cout << "Could not pair with the device status: " << coap->getResponseStatusCode() << " " << reason << std::endl;
        return PairingMode::NONE;
    }
    {
        auto buffer = coap->getResponsePayload();
        auto j = nlohmann::json::from_cbor(buffer);
        auto modes = j["Modes"];
        if (!modes.is_array()) {
            std::cout << "Invalid response" << std::endl;
            exit(1);
        }
        for (auto mode : modes) {
            std::string stringMode = mode.get<std::string>();
            if (stringMode == "Button") {
                supportedModes.push_back(PairingMode::BUTTON);
            } else if (stringMode == "Password") {
                supportedModes.push_back(PairingMode::PASSWORD);
            } else if (stringMode == "Local") {
                supportedModes.push_back(PairingMode::LOCAL);
            }
        }
    }

    if (supportedModes.size() == 0) {
        std::cout << "cannot pair with the device as there is no supported pairing modes" << std::endl;
        return PairingMode::NONE;
    }

    if (supportedModes.size() == 1) {
        return supportedModes[0];
    }

    std::cout << "Choose a pairing method " << std::endl;
    for (size_t i = 0; i < supportedModes.size(); i++) {
        std::cout << "[" << i << "] " << pairingModeAsString(supportedModes[i]) << std::endl;
    }

    int pairingChoice = -1;
    {
        char input;
        std::cin >> input;
        if (input == 'q') {
            std::cout << "Quitting" << std::endl;
            exit(1);
        }

        pairingChoice = input - '0';
    }
    if (pairingChoice < 0 || pairingChoice >= (int)supportedModes.size()) {
        std::cout << "Invalid choice" << std::endl;
        exit(1);
    }

    return supportedModes[pairingChoice];
}

bool button_pair(std::shared_ptr<nabto::client::Connection> connection, const std::string& name)
{
    auto coap = connection->createCoap("POST", "/pairing/button");
    std::cout << "Waiting for the user to press a button on the device." << std::endl;
    nlohmann::json root;
    root["Name"] = name;
    coap->setRequestPayload(CONTENT_FORMAT_APPLICATION_CBOR, nlohmann::json::to_cbor(root));
    coap->execute()->waitForResult();
    if (coap->getResponseStatusCode() != 201) {
        std::string reason;
        auto buffer = coap->getResponsePayload();
        reason = std::string(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::cout << "Could not pair with the device status: " << coap->getResponseStatusCode() << " " << reason << std::endl;
        return false;
    }
    return true;
}

bool local_pair(std::shared_ptr<nabto::client::Connection> connection, const std::string& name)
{
    nlohmann::json root;
    root["Name"] = name;

    auto coap = connection->createCoap("POST", "/pairing/local");
    coap->setRequestPayload(CONTENT_FORMAT_APPLICATION_CBOR, nlohmann::json::to_cbor(root));
    coap->execute()->waitForResult();
    if (coap->getResponseStatusCode() != 201) {
        std::string reason;
        auto buffer = coap->getResponsePayload();
        reason = std::string(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::cout << "Could not pair with the device status: " << coap->getResponseStatusCode() << " " << reason << std::endl;
        return false;
    }
    return true;
}

bool password_pair_password(std::shared_ptr<nabto::client::Connection> connection, const std::string& name, const std::string& password)
{
    nlohmann::json root;
    root["Password"] = password;
    root["Name"] = name;

    auto coap = connection->createCoap("POST", "/pairing/password");
    coap->setRequestPayload(CONTENT_FORMAT_APPLICATION_CBOR, nlohmann::json::to_cbor(root));
    coap->execute()->waitForResult();
    if (coap->getResponseStatusCode() != 201) {
        std::string reason;
        auto buffer = coap->getResponsePayload();
        reason = std::string(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::cout << "Could not pair with the device status: " << coap->getResponseStatusCode() << " " << reason << std::endl;
        return false;
    }
    return true;
}

bool password_pair(std::shared_ptr<nabto::client::Connection> connection, const std::string& name)
{
    std::string password;
    std::cout << "enter the password which is used to pair with the device." << std::endl;
    std::cin >> password;
    return password_pair_password(connection, name, password);
}




bool interactive_pair(std::shared_ptr<nabto::client::Context> ctx, const std::string& configFile, const std::string& userName)
{
    nlohmann::json config;

    std::cout << "Scanning for local devices for 2 seconds." << std::endl;
    auto devices = Scanner::scan(ctx, std::chrono::milliseconds(2000));
    if (devices.size() == 0) {
        std::cout << "Did not find any local devices, is the device on the same local network as the client?" << std::endl;
        return false;
    }

    std::cout << "Found " << devices.size() << " local devices." << std::endl;
    std::cout << "Choose a device for pairing:" << std::endl;
    std::cout << "[q]: Quit without pairing" << std::endl;
    for (size_t i = 0; i < devices.size(); i++) {
        std::string productId;
        std::string deviceId;
        std::tie(productId,deviceId) = devices[i];
        std::cout << "[" << i << "] ProductId: " << productId << " DeviceId: " << deviceId << std::endl;
    }
    int deviceChoice = -1;
    {
        char input;
        std::cin >> input;
        if (input == 'q') {
            std::cout << "Quitting" << std::endl;
            return false;
        }

        deviceChoice = input - '0';
    }
    if (deviceChoice < 0 || deviceChoice >= (int)devices.size()) {
        std::cout << "Invalid choice" << std::endl;
        return false;
    }
    auto connection = ctx->createConnection();
    {
        std::string productId;
        std::string deviceId;
        std::tie(productId, deviceId) = devices[deviceChoice];
        connection->setProductId(productId);
        connection->setDeviceId(deviceId);
        std::string privateKey = ctx->createPrivateKey();
        connection->setPrivateKey(privateKey);
        json options;
        options["Remote"] = false;
        connection->setOptions(options.dump());

        config["DeviceId"] = deviceId;
        config["ProductId"] = productId;
        config["PrivateKey"] = privateKey;

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
            return false;
        }

        std::cout << "Connected to device ProductId: " <<  productId << " DeviceId: " << deviceId << std::endl;
        std::cout << "Is this the correct fingerprint of the device " << connection->getDeviceFingerprintFullHex() << " [yn]" << std::endl;
    }
    {
        char input;
        std::cin >> input;
        if (input == 'q') {
            std::cout << "Quitting" << std::endl;
            return false;
        } else if (input == 'y') {

        } else if (input == 'n') {
            std::cout << "Rejected device fingerprint, quitting" << std::endl;
            return false;
        } else {
            std::cout << "Invalid choice, quitting" << std::endl;
            return false;
        }
    }
    config["DeviceFingerprint"] = connection->getDeviceFingerprintFullHex();
    std::cout << "Connected to the device" << std::endl;

    PairingMode mode = get_pairing_mode(connection);

    if (mode == PairingMode::NONE) {
        return false;
    } if (mode == PairingMode::BUTTON) {
        if (!button_pair(connection, userName)) {
            return false;
        }
    } else if (mode == PairingMode::PASSWORD) {
        if (!password_pair(connection, userName)) {
            return false;
        }
    } else if (mode == PairingMode::LOCAL) {
        if (!local_pair(connection, userName)) {
            return false;
        }
    }

    auto coap = connection->createCoap("GET", "/pairing/client-settings");
    coap->execute()->waitForResult();
    if (coap->getResponseStatusCode() != 205) {
        std::string reason;
        auto buffer = coap->getResponsePayload();
        reason = std::string(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::cout << "Could not get client settings: " << coap->getResponseStatusCode() << " " << reason << std::endl;
        return false;
    }

    auto buffer = coap->getResponsePayload();
    auto j = nlohmann::json::from_cbor(buffer);
    config["ServerConnectToken"] = j["ServerConnectToken"].get<std::string>();

    std::cout << "Paired with the device, writing configuration to the configuration file" << std::endl;

    if (!json_config_save(configFile, config)) {
        std::cerr << "Failed to write config to " << configFile << std::endl;
        return false;
    }
    return true;
}

static std::vector<std::string> split(const std::string& s, char delimiter)
{
   std::vector<std::string> tokens;
   std::string token;
   std::istringstream tokenStream(s);
   while (std::getline(tokenStream, token, delimiter))
   {
      tokens.push_back(token);
   }
   return tokens;
}

static std::map<std::string, std::string> parseQueryString(const std::string& url)
{
    std::map<std::string, std::string> args;
    auto andArgs = split(url, '?');

    if (andArgs.size() < 2) {
        return args;
    }
    std::string qs = andArgs[1];

    auto pairs = split(qs, '&');

    for (auto p : pairs) {
        auto kv = split(p, '=');
        if (kv.size() >= 2) {
            args[kv[0]] = kv[1];
        }
    }

    return args;
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

bool link_pair(std::shared_ptr<nabto::client::Context> ctx, const std::string& configFile, const std::string& stateFile, const std::string& userName, const std::string& remotePairUrl)
{
    std::map<std::string, std::string> args = parseQueryString(remotePairUrl);
    nlohmann::json config;
    nlohmann::json state;
    if (!json_config_load(configFile, config)) {
        printMissingClientConfig(configFile);
        return false;
    }
    std::string productId = args["p"];
    std::string deviceId = args["d"];
    std::string deviceFingerprint = args["fp"];
    std::string pairingPassword = args["pwd"];
    std::string serverConnectToken = args["sct"];

    auto connection = ctx->createConnection();
    connection->setProductId(productId);
    connection->setDeviceId(deviceId);
    std::string privateKey = ctx->createPrivateKey();
    connection->setPrivateKey(privateKey);
    try {
        std::string url = config["ServerUrl"].get<std::string>();
        connection->setServerUrl(url);
    } catch (...) {
        //Ignore missing server key, api should assign one
    }
    connection->setServerKey(config["ServerKey"].get<std::string>());
    connection->setServerConnectToken(serverConnectToken);
    json options;

    state["DeviceId"] = deviceId;
    state["ProductId"] = productId;
    state["PrivateKey"] = privateKey;

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
        return false;
    }

    std::cout << "Connected to device ProductId: " <<  productId << " DeviceId: " << deviceId << std::endl;

    if (deviceFingerprint != connection->getDeviceFingerprintFullHex()) {
        std::cout << "device fingerprint does not match" << std::endl;
        return false;
    }

    if (!password_pair_password(connection, userName, pairingPassword)) {
        return false;
    }

    state["DeviceFingerprint"] = connection->getDeviceFingerprintFullHex();

    auto coap = connection->createCoap("GET", "/pairing/client-settings");
    coap->execute()->waitForResult();
    if (coap->getResponseStatusCode() != 205) {
        std::string reason;
        auto buffer = coap->getResponsePayload();
        reason = std::string(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::cout << "Could not get client settings: " << coap->getResponseStatusCode() << " " << reason << std::endl;
        return false;
    }

    auto buffer = coap->getResponsePayload();
    auto j = nlohmann::json::from_cbor(buffer);
    state["ServerConnectToken"] = j["ServerConnectToken"].get<std::string>();

    if (!json_config_save(stateFile, state)) {
        std::cerr << "Failed to write state to " << stateFile << std::endl;
        return false;
    }

    std::cout << "Paired with the device and wrote state to file " << stateFile << std::endl;

    return true;
}

} } } // namespace
