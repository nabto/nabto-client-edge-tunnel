#include "pairing.hpp"

#include "config.hpp"
#include "scanner.hpp"
#include "iam.h"

#include <3rdparty/nlohmann/json.hpp>
#include <iostream>
#include <sstream>

using string = std::string;
using json = nlohmann::json;

static bool write_config(Configuration::DeviceInfo& Device);

// arg Character should be lowercase.
static bool is_char_case_insensitive(char Subject, char Character) {
    return (Character >= 'a' && Character <= 'z') &&
           (Subject == Character || Subject == (Character - 32));
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

    std::unique_ptr<PairingInfo> pi = getPairingInfo(connection);
    if (pi) {
        if (pi->Modes.count(PairingMode::LOCAL)) {
            return PairingMode::LOCAL;
        }

        if (pi->Modes.count(PairingMode::PASSWORD)) {
            return PairingMode::PASSWORD;
        }

        if (pi->Modes.count(PairingMode::BUTTON)) {
            return PairingMode::BUTTON;
        }
    }

    std::cerr << "cannot pair with the device as there is no supported pairing modes" << std::endl;
    return PairingMode::NONE;
}

static bool button_pair(std::shared_ptr<nabto::client::Connection> connection, const std::string& name)
{
    auto coap = connection->createCoap("POST", "/iam/pairing/button");
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

    auto coap = connection->createCoap("POST", "/iam/pairing/local");
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

    auto coap = connection->createCoap("POST", "/iam/pairing/password");
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
    }

    DeviceConfig.DeviceFingerprint = connection->getDeviceFingerprintFullHex();
    std::cout << "Connected to the device" << std::endl;

    auto pi = getPairingInfo(connection);
    if (!pi) {
        std::cerr << "Cannot Get CoAP /iam/pairing" << std::endl;
        return false;
    }
    PairingMode mode = get_pairing_mode(connection);
    if (pi->Modes.count(PairingMode::LOCAL)) {
         if (!local_pair(connection, userName)) {
            return false;
        }
    } else if (pi->Modes.count(PairingMode::PASSWORD)) {
        if (!password_pair(connection, userName)) {
            return false;
        }
    } else if (pi->Modes.count(PairingMode::BUTTON)) {
        if (!button_pair(connection, userName)) {
            return false;
        }
    } else {
        std::cerr << "No supported pairing modes" << std::endl;
        return false;
    }

    // test that pairing succeeded and get missing settings for the client.
    auto user = IAM::get_me(connection);
    if (!user) {
        std::cerr << "Pairing failed" << std::endl;
        return false;
    }

    DeviceConfig.ServerConnectToken = user->getServerConnectToken();

    return write_config(DeviceConfig);
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
    auto Config = Configuration::GetConfigInfo();
    if (!Config) {
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

    if (!Config->getServerUrl().empty()) {
        connection->setServerUrl(Config->getServerUrl());
    }
    else {
        // TODO(as): No server url found.
    }
    connection->setServerKey(Config->getServerKey());
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

    std::unique_ptr<PairingInfo> pi = getPairingInfo(connection);
    if (!pi) {
        std::cerr << "CoAP GET /iam/pairing failed, pairing failed" << std::endl;
    }

    if (pi->Modes.count(PairingMode::LOCAL)) {
        if(!local_pair(connection, userName)) {
            return false;
        }
    } else if (pi->Modes.count(PairingMode::PASSWORD)) {
        if (!password_pair_password(connection, userName, pairingPassword)) {
            return false;
        }
    } else if (pi->Modes.count(PairingMode::BUTTON)) {
        if (!button_pair(connection, userName)) {
            return false;
        }
    } else {
        std::cerr << "No supported pairing mode" << std::endl;
        return false;
    }

    // test that pairing succeeded and get missing settings for the client.
    auto user = IAM::get_me(connection);
    if (!user) {
        std::cerr << "Pairing failed" << std::endl;
        return false;
    }

    Device.ServerConnectToken = user->getServerConnectToken();
    
    return write_config(Device);
}

bool direct_pair(std::shared_ptr<nabto::client::Context> Context, const std::string& userName, const std::string& host)
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

    std::unique_ptr<PairingInfo> pi = getPairingInfo(connection);
    if (!pi) {
        std::cerr << "CoAP GET /iam/pairing failed, pairing failed" << std::endl;
    }

    Device.ProductID = pi->ProductId;
    Device.DeviceID = pi->DeviceId;

    if (pi->Modes.count(PairingMode::LOCAL)) {
        if(!local_pair(connection, userName)) {
            return false;
        }
    } else if (pi->Modes.count(PairingMode::PASSWORD)) {
        if (!password_pair(connection, userName)) {
            return false;
        }
    } else if (pi->Modes.count(PairingMode::BUTTON)) {
        if (!button_pair(connection, userName)) {
            return false;
        }
    } else {
        std::cerr << "No supported pairing mode" << std::endl;
        return false;
    }

    // test that pairing succeeded and get missing settings for the client.
    auto user = IAM::get_me(connection);
    if (!user) {
        std::cerr << "Pairing failed" << std::endl;
        return false;
    }

    Device.ServerConnectToken = user->getServerConnectToken();
    
    return write_config(Device);
}

bool write_config(Configuration::DeviceInfo& Device)
{
    Configuration::AddPairedDeviceToBookmarks(Device);

    std::cout << "The device " << Device.GetFriendlyName() << " has been set into the bookmarks as index " << Device.Index << std::endl;



    if (!Configuration::WriteStateFile()) {
        std::cerr << "Failed to write state to " << Configuration::GetStateFilePath() << std::endl;
        return false;
    }
    return true;
}


void from_json(const json& j, PairingInfo& pi)
{
    try {
        j.at("ProductId").get_to(pi.ProductId);
    } catch (std::exception& e) {}

    try {
        j.at("DeviceId").get_to(pi.DeviceId);
    } catch (std::exception& e) {}

    try {
        j.at("AppName").get_to(pi.AppName);
    } catch (std::exception& e) {}

    try {
        j.at("AppVersion").get_to(pi.AppVersion);
    } catch (std::exception& e) {}

    try {
        j.at("NabtoVersion").get_to(pi.NabtoVersion);
    } catch (std::exception& e) {}

    try {
        std::vector<std::string> modes = j["Modes"].get<std::vector<std::string> >();
        for (auto m : modes) {
            if (m == "Local") {
                pi.Modes.insert(PairingMode::LOCAL);
            } else if (m == "Password") {
                pi.Modes.insert(PairingMode::PASSWORD);
            } else if (m == "Button") {
                pi.Modes.insert(PairingMode::BUTTON);
            }
        }
    } catch (std::exception& e) {}
}

std::unique_ptr<PairingInfo> getPairingInfo(std::shared_ptr<nabto::client::Connection> connection)
{
    auto coap = connection->createCoap("GET", "/iam/pairing");
    try {
        coap->execute()->waitForResult();
    } catch (nabto::client::NabtoException& e) {
        // TODO
    }

    if (coap->getResponseStatusCode() != 205) {
        std::cerr << "CoAP GET /iam/pairing returned non ok status " << coap->getResponseStatusCode() << std::endl;
        return nullptr;
    }

    if (coap->getResponseContentFormat() != CONTENT_FORMAT_APPLICATION_CBOR) {
        std::cerr << "CoAP GET /iam/pairing returned an unsupported content format " << coap->getResponseContentFormat() << std::endl;
        return nullptr;
    }

    std::vector<uint8_t> payload = coap->getResponsePayload();
    try {
        nlohmann::json root = nlohmann::json::from_cbor(payload);
        return std::make_unique<PairingInfo>(root.get<PairingInfo>());
    } catch(std::exception& e) {
        std::cerr << "CoAP GET /iam/pairing returned a non conformant response" << std::endl;
        return nullptr;
    }
}
