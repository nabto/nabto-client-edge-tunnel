#include "pairing.hpp"

#include "config.hpp"
#include "scanner.hpp"
#include "iam.hpp"
#include "iam_interactive.hpp"

#include <3rdparty/nlohmann/json.hpp>
#include <iostream>
#include <sstream>

using string = std::string;
using json = nlohmann::json;

static bool write_config(Configuration::DeviceInfo& Device);

static bool write_config(std::shared_ptr<nabto::client::Connection> connection, const std::string& directCandidate = "");

static bool handle_already_paired(std::shared_ptr<nabto::client::Connection> connection, const std::string& directCandidate = "")
{
    auto device = Configuration::GetPairedDevice(connection->getDeviceFingerprintFullHex());
    if (device) {
        std::cout << "The client is alredy paired with the device the pairing has the bookmark " << device->getIndex() << std::endl;
        return true;
    } else {
        std::cout << "The client is already paired with the device. However the client does not have the state saved, recreating the client state" << std::endl;
        return write_config(connection, directCandidate);
    }
}

// arg Character should be lowercase.
static bool is_char_case_insensitive(char Subject, char Character) {
    return (Character >= 'a' && Character <= 'z') &&
           (Subject == Character || Subject == (Character - 32));
}

static std::string pairingModeAsString(IAM::PairingMode mode) {
    if (mode == IAM::PairingMode::BUTTON) {
        return "Button";
    } else if (mode == IAM::PairingMode::PASSWORD) {
        return "Password";
    } else if (mode == IAM::PairingMode::LOCAL) {
        return "Local";
    }
    return "unknown";
}

static IAM::PairingMode get_pairing_mode(std::shared_ptr<nabto::client::Connection> connection)
{

    IAM::IAMError ec;
    std::unique_ptr<IAM::PairingInfo> pi;
    std::tie(ec, pi) = IAM::get_pairing_info(connection);

    if (ec.ok()) {
        if (pi->getModes().count(IAM::PairingMode::LOCAL)) {
            return IAM::PairingMode::LOCAL;
        }

        if (pi->getModes().count(IAM::PairingMode::PASSWORD)) {
            return IAM::PairingMode::PASSWORD;
        }

        if (pi->getModes().count(IAM::PairingMode::BUTTON)) {
            return IAM::PairingMode::BUTTON;
        }
    }
    ec.printError();
    return IAM::PairingMode::NONE;
}

static bool button_pair(std::shared_ptr<nabto::client::Connection> connection, const std::string& name)
{
    auto coap = connection->createCoap("POST", "/iam/pairing/button");
    std::cout << "Waiting for the user to press a button on the device." << std::endl;
    nlohmann::json root;
    root["Name"] = name;
    coap->setRequestPayload(IAM::CONTENT_FORMAT_APPLICATION_CBOR, nlohmann::json::to_cbor(root));
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
    root["Username"] = name;

    auto coap = connection->createCoap("POST", "/iam/pairing/local");
    coap->setRequestPayload(IAM::CONTENT_FORMAT_APPLICATION_CBOR, nlohmann::json::to_cbor(root));
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
    root["Username"] = name;

    try {
        connection->passwordAuthenticate("", password)->waitForResult();
    } catch (nabto::client::NabtoException& e) {
        std::cout << "Could not password authenticate with device. Ensure you typed the correct password. The error message is " << e.status().getDescription() << std::endl;
        return false;
    }

    auto coap = connection->createCoap("POST", "/iam/pairing/password");
    coap->setRequestPayload(IAM::CONTENT_FORMAT_APPLICATION_CBOR, nlohmann::json::to_cbor(root));
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
        string productId;
        string deviceId;
        std::tie(productId, deviceId) = devices[deviceChoice];
        connection->setProductId(productId);
        connection->setDeviceId(deviceId);

        string PrivateKey;
        if (!Configuration::GetPrivateKey(Context, PrivateKey)) {
            return false;
        }
        connection->setPrivateKey(PrivateKey);

        json options;
        options["Remote"] = false;
        connection->setOptions(options.dump());

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

        std::cout << "Connected to device ProductId: " <<  productId << " DeviceId: " << deviceId << std::endl;
    }

    std::cout << "Connected to the device" << std::endl;

    {
        IAM::IAMError ec;
        std::unique_ptr<IAM::User> user;
        std::tie(ec, user) = IAM::get_me(connection);
        if (user) {
            return handle_already_paired(connection);
        }
    }

    IAM::IAMError ec;
    std::unique_ptr<IAM::PairingInfo> pi;
    std::tie(ec, pi) = IAM::get_pairing_info(connection);
    if (!ec.ok()) {
        std::cerr << "Cannot Get CoAP /iam/pairing" << std::endl;
        return false;
    }
    IAM::PairingMode mode = get_pairing_mode(connection);
    if (pi->getModes().count(IAM::PairingMode::LOCAL)) {
         if (!local_pair(connection, userName)) {
            return false;
        }
    } else if (pi->getModes().count(IAM::PairingMode::PASSWORD)) {
        if (!password_pair(connection, userName)) {
            return false;
        }
    } else if (pi->getModes().count(IAM::PairingMode::BUTTON)) {
        if (!button_pair(connection, userName)) {
            return false;
        }
    } else {
        std::cerr << "No supported pairing modes" << std::endl;
        return false;
    }
    return write_config(connection);
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

    IAM::IAMError ec;
    std::unique_ptr<IAM::User> user;
    std::tie(ec, user) = IAM::get_me(connection);
    if (user) {
        return handle_already_paired(connection);
    }

    std::unique_ptr<IAM::PairingInfo> pi;
    std::tie(ec, pi) = IAM::get_pairing_info(connection);
    if (!pi) {
        std::cerr << "CoAP GET /iam/pairing failed, pairing failed" << std::endl;
    }

    if (pi->getModes().count(IAM::PairingMode::LOCAL)) {
        if(!local_pair(connection, userName)) {
            return false;
        }
    } else if (pi->getModes().count(IAM::PairingMode::PASSWORD)) {
        if (!password_pair(connection, userName)) {
            return false;
        }
    } else if (pi->getModes().count(IAM::PairingMode::BUTTON)) {
        if (!button_pair(connection, userName)) {
            return false;
        }
    } else {
        std::cerr << "No supported pairing mode" << std::endl;
        return false;
    }


    return write_config(connection);
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
    IAM::IAMError ec;
    std::unique_ptr<IAM::User> user;
    std::tie(ec, user) = IAM::get_me(connection);
    if (user) {
        return handle_already_paired(connection, host);
    }

    std::unique_ptr<IAM::PairingInfo> pi;
    std::tie(ec, pi) = IAM::get_pairing_info(connection);
    if (!ec.ok()) {
        std::cerr << "CoAP GET /iam/pairing failed, pairing failed" << std::endl;
        return false;
    }

    if (pi->getModes().count(IAM::PairingMode::LOCAL)) {
        if(!local_pair(connection, userName)) {
            return false;
        }
    } else if (pi->getModes().count(IAM::PairingMode::PASSWORD)) {
        if (!password_pair(connection, userName)) {
            return false;
        }
    } else if (pi->getModes().count(IAM::PairingMode::BUTTON)) {
        if (!button_pair(connection, userName)) {
            return false;
        }
    } else {
        std::cerr << "No supported pairing mode" << std::endl;
        return false;
    }

    return write_config(connection, host);
}

bool write_config(std::shared_ptr<nabto::client::Connection> connection, const std::string& host)
{
    Configuration::DeviceInfo device;

    IAM::IAMError ec;
    std::unique_ptr<IAM::PairingInfo> pi;
    std::tie(ec, pi) = IAM::get_pairing_info(connection);
    if (!ec.ok()) {
        std::cerr << "CoAP GET /iam/pairing failed, pairing failed" << std::endl;
        return false;
    }

    device.productId_ = pi->getProductId();
    device.deviceId_ = pi->getDeviceId();
    device.deviceFingerprint_ = connection->getDeviceFingerprintFullHex();
    if (!host.empty()) {
        device.directCandidate_ = host;
    }

    std::unique_ptr<IAM::User> user;
    std::tie(ec, user) = IAM::get_me(connection);
    if (!ec.ok()) {
        std::cerr << "Pairing failed" << std::endl;
        ec.printError();
        return false;
    }
    device.serverConnectToken_ = user->getServerConnectToken();
    return write_config(device);
}

bool write_config(Configuration::DeviceInfo& device)
{
    Configuration::AddPairedDeviceToBookmarks(device);

    std::cout << "The device " << device.getFriendlyName() << " has been set into the bookmarks as index " << device.getIndex() << std::endl;



    if (!Configuration::WriteStateFile()) {
        std::cerr << "Failed to write state to " << Configuration::GetStateFilePath() << std::endl;
        return false;
    }
    return true;
}

