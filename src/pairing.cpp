#include "pairing.hpp"

#include "config.hpp"
#include "scanner.hpp"
#include "iam.hpp"
#include "iam_interactive.hpp"

#include <3rdparty/nlohmann/json.hpp>
#include <iostream>
#include <sstream>

using json = nlohmann::json;

static bool write_config(Configuration::DeviceInfo& Device);

static bool write_config(std::shared_ptr<nabto::client::Connection> connection, const std::string& directCandidate = "");
static bool interactive_pair_connection(std::shared_ptr<nabto::client::Connection> connection, const std::string& usernameInvite = "", const std::string& password = "");

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

static bool local_pair_open_interactive(std::shared_ptr<nabto::client::Connection> connection)
{
    std::string username;
    std::cout << "The pairing needs a username, the username needs to be unique among the users registered in the device." << std::endl;
    std::cout << "Username: ";
    std::cin >> username;

    nlohmann::json root;
    root["Username"] = username;

    auto coap = connection->createCoap("POST", "/iam/pairing/local-open");
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

static bool local_pair_initial(std::shared_ptr<nabto::client::Connection> connection)
{
    auto coap = connection->createCoap("POST", "/iam/pairing/local-initial");
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

    auto coap = connection->createCoap("POST", "/iam/pairing/password-open");
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



static bool password_pair_open_interactive(std::shared_ptr<nabto::client::Connection> connection, const std::string& passwordIn = "")
{
    std::string username;
    std::string password;

    std::cout << "Open Password Pairing requires a username. The username is a name you choose for the new user, the username has to be unique among the registered users on the device." << std::endl;
    std::cout << "New Username: ";
    std::cin >> username;
    if (passwordIn.empty()) {
        std::cout << "Password: ";
        std::cin >> password;
    } else {
        password = passwordIn;
    }
    return password_pair_password(connection, username, password);
}

static bool password_invite_pair_password(std::shared_ptr<nabto::client::Connection> connection, const std::string& username, const std::string& password)
{
    try {
        connection->passwordAuthenticate(username, password)->waitForResult();
    } catch (nabto::client::NabtoException& e) {
        std::cout << "Could not password authenticate with the device. Ensure you typed the correct password. The error message is " << e.status().getDescription() << std::endl;
        return false;
    }

    auto coap = connection->createCoap("POST", "/iam/pairing/password-invite");
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

static bool password_invite_pair(std::shared_ptr<nabto::client::Connection> connection, const std::string& usernameInvite, const std::string& passwordIn)
{
    std::string password;
    std::string username;
    if (usernameInvite.empty()) {
        std::cout << "Enter the username for the user in the device." << std::endl;
        std::cout << "Username: ";
        std::cin >> username;
    } else {
        username = usernameInvite;
    }

    if (passwordIn.empty()) {
        std::cout << "Enter the password for the user: " << username << std::endl;
        std::cout << "Password: ";
        std::cin >> password;
    } else {
        password = passwordIn;
    }
    return password_invite_pair_password(connection, username, password);
}

bool interactive_pair(std::shared_ptr<nabto::client::Context> Context)
{
    std::cout << "Scanning for local devices for 2 seconds." << std::endl;
    auto devices = nabto::examples::common::Scanner::scan(Context, std::chrono::milliseconds(2000), "tcptunnel");
    if (devices.size() == 0) {
        std::cout << "Did not find any local devices, is the device on the same local network as the client?" << std::endl;
        return false;
    }

    std::cout << "Found " << devices.size() << " local devices." << std::endl;
    std::cout << "Choose a device for pairing:" << std::endl;
    std::cout << "[q]: Quit without pairing" << std::endl;

    for (size_t i = 0; i < devices.size(); ++i) {
        std::string ProductID;
        std::string DeviceID;
        std::tie(ProductID, DeviceID) = devices[i];
        std::cout << "[" << i << "] ProductId: " << ProductID << " DeviceId: " << DeviceID << std::endl;
    }

    int deviceChoice = IAM::interactive_choice("Choose a device: ", 0, devices.size());
    if (deviceChoice == -1) {
        return false;
    }

    auto connection = Context->createConnection();
    {
        std::string productId;
        std::string deviceId;
        std::tie(productId, deviceId) = devices[deviceChoice];
        connection->setProductId(productId);
        connection->setDeviceId(deviceId);

        std::string PrivateKey;
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

        std::cout << "Connected to the device. ProductId: " <<  productId << " DeviceId: " << deviceId << std::endl;
    }
    return interactive_pair_connection(connection);
}

bool interactive_pair_connection(std::shared_ptr<nabto::client::Connection> connection, const std::string& usernameInvite, const std::string& password)
{
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
    std::vector<IAM::PairingMode> modes;
    auto ms = pi->getModes();
    std::copy(ms.begin(), ms.end(), std::back_inserter(modes));

    IAM::PairingMode mode = IAM::PairingMode::NONE;

    if (modes.size() == 0) {
        std::cerr << "No supported pairing modes" << std::endl;
        return false;
    } else if (modes.size() == 1) {
        mode = modes[0];
    } else if (modes.size() > 1) {
        std::cout << "Several pairing modes exists choose one of the following." << std::endl;
        for (size_t i = 0; i < modes.size(); i++) {
            std::cout << "[" << i << "]: " << IAM::pairingModeAsString(modes[i]) << std::endl;
        }
        int choice = IAM::interactive_choice("Choose a pairing mode: ", 0, modes.size());
        if (choice == -1) {
            return false;
        } else {
            mode = modes[choice];
        }
    }

    if (mode == IAM::PairingMode::LOCAL_INITIAL) {
         if (!local_pair_initial(connection)) {
            return false;
        }
    } else if (mode == IAM::PairingMode::LOCAL_OPEN) {
         if (!local_pair_open_interactive(connection)) {
            return false;
        }
    } else if (mode == IAM::PairingMode::PASSWORD_OPEN) {
        if (!password_pair_open_interactive(connection, password)) {
            return false;
        }
    } else if (mode == IAM::PairingMode::PASSWORD_INVITE) {
        if (!password_invite_pair(connection, usernameInvite, password)) {
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

bool param_pair(std::shared_ptr<nabto::client::Context> ctx, const std::string& productId, const std::string& deviceId, const std::string& usernameInvite, const std::string& password, const std::string& sct);


bool string_pair(std::shared_ptr<nabto::client::Context> ctx, const std::string& pairingString)
{
    std::map<std::string, std::string> args = parseStringArgs(pairingString);
    std::string productId = args["p"];
    std::string deviceId = args["d"];
    std::string pairingPassword = args["pwd"];
    std::string sct = args["sct"];
    std::string usernameInvite = args["u"];
    
    return param_pair(ctx, productId, deviceId, usernameInvite, pairingPassword, sct);
}

bool param_pair(std::shared_ptr<nabto::client::Context> ctx, const std::string& productId, const std::string& deviceId, const std::string& usernameInvite, const std::string& pairingPassword, const std::string& sct)
{
    auto Config = Configuration::GetConfigInfo();
    if (!Config) {
        return false;
    }

    auto connection = ctx->createConnection();
    connection->setProductId(productId);
    connection->setDeviceId(deviceId);
    std::string privateKey;

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
    connection->setServerConnectToken(sct);
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

    return interactive_pair_connection(connection, usernameInvite, pairingPassword);
}

bool direct_pair(std::shared_ptr<nabto::client::Context> Context, const std::string& host)
{
    auto connection = Context->createConnection();
    std::string privateKey;

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
    return interactive_pair_connection(connection);
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
    device.sct_ = user->getSct();
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

