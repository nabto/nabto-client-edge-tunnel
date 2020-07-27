#include "pairing.hpp"

#include "config.hpp"
#include "scanner.hpp"

#include <3rdparty/nlohmann/json.hpp>
#include <iostream>
#include <sstream>

using string = std::string;
using json = nlohmann::json;

const static int CONTENT_FORMAT_APPLICATION_CBOR = 60; // rfc 7059
enum class PairingMode {
    NONE,
    BUTTON,
    PASSWORD,
    LOCAL
};

// arg Character should be lowercase.
static bool is_char_case_insensitive(char Subject, char Character) {
    return (Character >= 'a' && Character <= 'z') &&
           Subject == Character || Subject == (Character - 32);
}

static std::string pairingModeAsString(PairingMode mode) {
    if (mode == PairingMode::BUTTON) {
        return "Button";
    } else if (mode == PairingMode::PASSWORD) {
        return "Password";
    } else if (mode == PairingMode::LOCAL) {
        return "Local";
    }
    return "unknown";
}

static PairingMode get_pairing_mode(std::shared_ptr<nabto::client::Connection> connection)
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

static bool button_pair(std::shared_ptr<nabto::client::Connection> connection, const std::string& name)
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

static bool local_pair(std::shared_ptr<nabto::client::Connection> connection, const std::string& name)
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

static bool password_pair_password(std::shared_ptr<nabto::client::Connection> connection, const std::string& name, const std::string& password)
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

static bool password_pair(std::shared_ptr<nabto::client::Connection> connection, const std::string& name)
{
    std::string password;
    std::cout << "enter the password which is used to pair with the device." << std::endl;
    std::cin >> password;
    return password_pair_password(connection, name, password);
}

bool interactive_pair(std::shared_ptr<nabto::client::Context> Context, const string& userName)
{
    Configuration::DeviceInfo DeviceConfig;

    std::cout << "Scanning for local devices for 2 seconds." << std::endl;
    auto devices = nabto::examples::common::Scanner::scan(Context, std::chrono::milliseconds(2000));
    if (devices.size() == 0) {
        std::cout << "Did not find any local devices, is the device on the same local network as the client?" << std::endl;
        return false;
    }

    std::cout << "Found " << devices.size() << " local devices." << std::endl;
    std::cout << "Choose a device for pairing:" << std::endl;
    std::cout << "[q]: Quit without pairing" << std::endl;

    for (size_t i = 0; i < devices.size(); ++i) {
        string ProductID;
        string DeviceID;
        std::tie(ProductID, DeviceID) = devices[i];
        std::cout << "[" << i << "] ProductId: " << ProductID << " DeviceId: " << DeviceID << std::endl;
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

    if (deviceChoice < 0 || deviceChoice >= devices.size()) {
        // TODO(as): Let the user re-try pairing instead of quitting?
        std::cout << "Invalid choice" << std::endl;
        return false;
    }

    auto connection = Context->createConnection();
    {
        string ProductID;
        string DeviceID;
        std::tie(ProductID, DeviceID) = devices[deviceChoice];
        connection->setProductId(ProductID);
        connection->setDeviceId(DeviceID);
        string PrivateKey = Context->createPrivateKey();
        connection->setPrivateKey(PrivateKey);

        json options;
        options["Remote"] = false;
        connection->setOptions(options.dump());

        DeviceConfig.DeviceID = DeviceID;
        DeviceConfig.ProductID = ProductID;
        DeviceConfig.PrivateKey = PrivateKey;

        try {
            connection->connect()->waitForResult();
        }
        catch (nabto::client::NabtoException& e) {
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

        std::cout << "Connected to device ProductId: " <<  ProductID << " DeviceId: " << DeviceID << std::endl;
        std::cout << "Is this the correct fingerprint of the device " << connection->getDeviceFingerprintFullHex() << " [y/n]" << std::endl;
        {
            char input;
            std::cin >> input;
            if (!is_char_case_insensitive(input, 'y')) {
                if (is_char_case_insensitive(input, 'q')) {
                    std::cout << "Quitting" << std::endl;
                }
                else if (is_char_case_insensitive(input, 'n')) {
                    std::cout << "Rejected device fingerprint, quitting" << std::endl;
                }
                else {
                    std::cout << "Invalid choice, quitting" << std::endl;
                }
                return false;
            }
        }
    }

    DeviceConfig.DeviceFingerprint = connection->getDeviceFingerprintFullHex();
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
    DeviceConfig.ServerConnectToken = json::from_cbor(buffer)["ServerConnectToken"].get<std::string>();
    std::cout << "Paired with the device, writing configuration to the configuration file" << std::endl;

    Configuration::AddPairedDeviceToBookmarks(DeviceConfig);
    if (!Configuration::WriteStateFile()) {
        std::cerr << "Failed to write config to " << Configuration::GetStateFilePath() << std::endl;
        return false;
    };
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

bool link_pair(std::shared_ptr<nabto::client::Context> ctx, const string& userName, const string& remotePairUrl)
{
    std::map<std::string, std::string> args = parseQueryString(remotePairUrl);
    Configuration::DeviceInfo Device;
    Configuration::ConfigInfo Config;
    if (!Configuration::GetConfigInfo(&Config)) {
        // TODO(as): print error to the user here.
        return false;
    }

    string productId = args["p"];
    string deviceId = args["d"];
    string deviceFingerprint = args["fp"];
    string pairingPassword = args["pwd"];
    string serverConnectToken = args["sct"];

    auto connection = ctx->createConnection();
    connection->setProductId(productId);
    connection->setDeviceId(deviceId);
    string privateKey = ctx->createPrivateKey();
    connection->setPrivateKey(privateKey);

    if (Config.ServerUrl) {
        connection->setServerUrl(string(Config.ServerUrl));
    }
    else {
        // TODO(as): No server url found.
    }
    connection->setServerKey(string(Config.ServerKey));
    connection->setServerConnectToken(serverConnectToken);
    json options;

    Device.DeviceID = deviceId;
    Device.ProductID = productId;
    Device.PrivateKey = privateKey;

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

    Device.DeviceFingerprint = connection->getDeviceFingerprintFullHex();

    auto coap = connection->createCoap("GET", "/pairing/client-settings");
    coap->execute()->waitForResult();
    if (coap->getResponseStatusCode() != 205) {
        std::string reason;
        auto buffer = coap->getResponsePayload();
        reason = std::string(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::cout << "Could not get client settings: " << coap->getResponseStatusCode() << " " << reason << std::endl;
        return false;
    }

    auto buffer =coap->getResponsePayload();
    auto j = json::from_cbor(buffer);
    Device.ServerConnectToken = j["ServerConnectToken"].get<string>();

    Configuration::AddPairedDeviceToBookmarks(Device);
    if (!Configuration::WriteStateFile()) {
        std::cerr << "Failed to write state to " << Configuration::GetStateFilePath() << std::endl;
        return false;
    }
    std::cout << "Paired with the device and wrote state to file " << Configuration::GetStateFilePath() << std::endl;

    return true;
}
