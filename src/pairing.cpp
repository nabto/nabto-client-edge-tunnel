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


static bool get_client_settings(std::shared_ptr<nabto::client::Connection> connection, Configuration::DeviceInfo& Device);
static bool write_config(Configuration::DeviceInfo& Device);
static bool local_pair_and_write_config(std::shared_ptr<nabto::client::Connection> connection, Configuration::DeviceInfo& Device, const std::string& UserName);
static bool password_pair_and_write_config(std::shared_ptr<nabto::client::Connection> connection, Configuration::DeviceInfo& Device, const std::string& UserName, const std::string& pairingPassword);

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
    root["Name"] = name;


    try {
        connection->passwordAuthenticate("", password)->waitForResult();
    } catch (nabto::client::NabtoException& e) {
        std::cout << "Could not password authenticate with device. Ensure you typed the correct password. The error message is " << e.status().getDescription() << std::endl;
        return false;
    }

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

        string PrivateKey;
        if (!Configuration::GetPrivateKey(Context, PrivateKey)) {
            return false;
        }
        connection->setPrivateKey(PrivateKey);

        json options;
        options["Remote"] = false;
        connection->setOptions(options.dump());

        DeviceConfig.DeviceID = DeviceID;
        DeviceConfig.ProductID = ProductID;

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

static std::map<std::string, std::string> parseStringArgs(const std::string pairingString)
{
    // k1=v1,k2=v2
    std::map<std::string, std::string> args;
    auto pairs = split(pairingString, ',');

    for (auto p : pairs) {
        auto kv = split(p, '=');
        if (kv.size() >= 2) {
            args[kv[0]] = kv[1];
        }
    }

    return args;
}

bool param_pair(std::shared_ptr<nabto::client::Context> ctx, const string& userName, const string& productId, const string& deviceId, const string& password, const string& sct);


bool string_pair(std::shared_ptr<nabto::client::Context> ctx, const string& userName, const string& pairingString)
{
    std::map<std::string, std::string> args = parseStringArgs(pairingString);
    string productId = args["p"];
    string deviceId = args["d"];
    string pairingPassword = args["pwd"];
    string serverConnectToken = args["sct"];
    return param_pair(ctx, userName, productId, deviceId, pairingPassword, serverConnectToken);
}

bool param_pair(std::shared_ptr<nabto::client::Context> ctx, const string& userName, const string& productId, const string& deviceId, const string& pairingPassword, const string& serverConnectToken)
{
    Configuration::DeviceInfo Device;
    Configuration::ConfigInfo Config;
    if (!Configuration::GetConfigInfo(&Config)) {
        // TODO(as): print error to the user here.
        return false;
    }

    auto connection = ctx->createConnection();
    connection->setProductId(productId);
    connection->setDeviceId(deviceId);
    string privateKey;

    if(!Configuration::GetPrivateKey(ctx, privateKey)) {
        return false;
    }

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

    if (!pairingPassword.empty()) {
        return password_pair_and_write_config(connection, Device, userName, pairingPassword);
    } else {
        return local_pair_and_write_config(connection, Device, userName);
    }
}


bool direct_pair(std::shared_ptr<nabto::client::Context> Context, const std::string& UserName, const std::string& host, const std::string& pairingPassword)
{
    auto connection = Context->createConnection();
    string privateKey;

    if(!Configuration::GetPrivateKey(Context, privateKey)) {
        return false;
    }

    uint16_t port = 5592;

    connection->setPrivateKey(privateKey);
    connection->enableDirectCandidates();
    connection->addDirectCandidate(host, port);
    connection->endOfDirectCandidates();

    json options;
    options["Local"] = false;
    options["Remote"] = false;

    std::stringstream o;
    o << options;
    connection->setOptions(o.str());

    try {
        connection->connect()->waitForResult();
    } catch (nabto::client::NabtoException& e) {
        std::cerr << "Could not make a direct connection to the host: " << host << ". The error code is: ";
        if (e.status().getErrorCode() == nabto::client::Status::NO_CHANNELS) {
            auto directCandidatesStatus = nabto::client::Status(connection->getDirectCandidatesChannelErrorCode());
            if (!directCandidatesStatus.ok()) {
                std::cerr << directCandidatesStatus.getDescription();
            }
        } else {
            std::cerr << e.what();
        }
        std::cerr << std::endl;
        return false;
    }

    // We have a connection to a device. we do not know the product id, device id or server connect token.
    Configuration::DeviceInfo Device;
    Device.DirectCandidate = host;

    if (!pairingPassword.empty()) {
        return password_pair_and_write_config(connection, Device, UserName, pairingPassword);
    } else {
        return local_pair_and_write_config(connection, Device, UserName);
    }
}

bool password_pair_and_write_config(std::shared_ptr<nabto::client::Connection> connection, Configuration::DeviceInfo& Device, const std::string& UserName, const std::string& pairingPassword)
{
    if (!password_pair_password(connection, UserName, pairingPassword)) {
        return false;
    }

    if (!get_client_settings(connection, Device)) {
        return false;
    }
    return write_config(Device);
}

bool local_pair_and_write_config(std::shared_ptr<nabto::client::Connection> connection, Configuration::DeviceInfo& Device, const std::string& UserName)
{
    if(!local_pair(connection, UserName)) {
        return false;
    }

    if (!get_client_settings(connection, Device)) {
        return false;
    }

    return write_config(Device);
}


bool get_client_settings(std::shared_ptr<nabto::client::Connection> connection, Configuration::DeviceInfo& Device)
{
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
    if (Device.ProductID.empty()) {
        Device.ProductID = j["ProductId"].get<string>();
    }
    if (Device.DeviceID.empty()) {
        Device.DeviceID = j["DeviceId"].get<std::string>();
    }
    return true;
}

bool write_config(Configuration::DeviceInfo& Device)
{
    Configuration::AddPairedDeviceToBookmarks(Device);
    if (!Configuration::WriteStateFile()) {
        std::cerr << "Failed to write state to " << Configuration::GetStateFilePath() << std::endl;
        return false;
    }
    std::cout << "Paired with the device and wrote state to file " << Configuration::GetStateFilePath() << std::endl;
    return true;
}
