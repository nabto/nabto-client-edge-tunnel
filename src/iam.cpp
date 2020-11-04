#include "iam.hpp"
#include <string>
#include <sstream>
#include <iostream>
#include <set>
#include <vector>
#include <random>

#include <3rdparty/nlohmann/json.hpp>

/* IAM module
 * Potential complications:
 * - Most of the functionality in this module must be made available by changing
 *   the device's policies file.
 * Future improvements:
 * - A generic error is printed for the exception catchers, this should
 *   probably be made more user-friendly?
 * - Improve the module API by exposing more CoAP requests (such as getting a user's info).
 */

using json = nlohmann::json;

namespace IAM
{

IAMError::IAMError() : ok_(true) {}
IAMError::IAMError(std::shared_ptr<nabto::client::Coap> coap)
{
    statusCode_ = coap->getResponseStatusCode();
}
IAMError::IAMError(nabto::client::NabtoException e)
{
    if (e.status().ok()) {
        ok_ = true;
    } else {
        message_ = e.what();
    }
}

IAMError::IAMError(std::exception& e)
{
    ok_ = false;
    message_ = e.what();
}

IAMError::IAMError(const std::string& message)
{
    ok_ = false;
    message_ = message;
}

bool IAMError::ok() { return ok_; }

void IAMError::printError()
{
    if (ok_) {
        return;
    }
    if (!message_.empty()) {
        std::cerr << message_ << std::endl;
    }
    if (statusCode_ < 200 || statusCode_ >= 300) {
        std::cerr << "Coap request failed with status code " << statusCode_
                  << std::endl;
    }
}

void from_json(const json &j, User &user) {
    // name is mandatory
    j.at("Username").get_to(user.username_);

    try {
        j.at("Fingerprint").get_to(user.fingerprint_);
    } catch (const std::exception& e) { }
    try {
        j.at("ServerConnectToken").get_to(user.serverConnectToken_);
    } catch (const std::exception& e) { }
    try {
        j.at("Role").get_to(user.role_);
    } catch (const std::exception& e) { }
}

std::unique_ptr<User> User::create(const nlohmann::json& in)
{
    try {
        User user = in.get<User>();
        return std::make_unique<User>(user);
    } catch (std::exception& e) {
        return nullptr;
    }
}

std::pair<IAMError, std::set<std::string> > get_users(std::shared_ptr<nabto::client::Connection> connection)
{
    try {
        auto coap = connection->createCoap("GET", "/iam/users");
        coap->execute()->waitForResult();
        int responseCode = coap->getResponseStatusCode();
        if (responseCode == 205) {
            auto cbor = coap->getResponsePayload();
            std::set<std::string> users;
            json user_list = json::from_cbor(cbor);
            for (auto &user : user_list)
            {
                users.insert(user.get<std::string>());
            }
            return std::make_pair(IAMError(), users);
        }
        return std::make_pair(IAMError(coap), std::set<std::string>());
    } catch (nabto::client::NabtoException& e) {
        return std::make_pair(IAMError(e), std::set<std::string>());
    }
}
std::pair<IAMError, std::unique_ptr<User> > get_user_path(std::shared_ptr<nabto::client::Connection> connection, const std::string& path)
{
    try {
        auto coap = connection->createCoap("GET", path);
        coap->execute()->waitForResult();
        int responseCode = coap->getResponseStatusCode();
        if (responseCode == 205) {
            auto cbor = coap->getResponsePayload();


            json user = json::from_cbor(cbor);
            auto decoded = User::create(user);
            if (decoded != nullptr) {
                return make_pair(IAMError(), std::move(decoded));
            }
        }
        return std::make_pair(IAMError(coap), nullptr);
    } catch (nabto::client::NabtoException& e) {
        return std::make_pair(IAMError(e), nullptr);
    }
}
std::pair<IAMError, std::unique_ptr<User> > get_user(std::shared_ptr<nabto::client::Connection> connection, const std::string& username)
{
    std::string path = "/iam/users/" + username;
    return get_user_path(connection, path);
}

std::pair<IAMError, std::unique_ptr<User> > get_me(std::shared_ptr<nabto::client::Connection> connection)
{
    return get_user_path(connection, "/iam/me");
}

std::pair<IAMError, std::set<std::string> > get_roles(
    std::shared_ptr<nabto::client::Connection> connection)
{
    auto coap = connection->createCoap("GET", "/iam/roles");
    try {
        coap->execute()->waitForResult();
        int responseCode = coap->getResponseStatusCode();
        if (responseCode == 205) {
            auto cbor = coap->getResponsePayload();
            json role_list = json::from_cbor(cbor);
            std::set<std::string> roles;
            for (auto &role : role_list) {
                roles.insert(role.get<std::string>());
            }
            return std::make_pair(IAMError(), roles);
        }
        return std::make_pair(IAMError(coap), std::set<std::string>());
    } catch (nabto::client::NabtoException &e) {
        return std::make_pair(IAMError(e), std::set<std::string>());
    }
}

IAMError set_role(std::shared_ptr<nabto::client::Connection> connection, const std::string &user, const std::string &role)
{
    std::stringstream path;
    path << "/iam/users/" << user << "/role";
    nlohmann::json root;
    root = role;
    std::vector<uint8_t> cbor = nlohmann::json::to_cbor(root);

    try {
        auto coap = connection->createCoap("PUT", path.str());
        coap->setRequestPayload(CONTENT_FORMAT_APPLICATION_CBOR, cbor);
        coap->execute()->waitForResult();
        int responseCode = coap->getResponseStatusCode();
        if(responseCode == 204) {
            return IAMError();
        }
        return IAMError(coap);
    } catch (nabto::client::NabtoException& e) {
        return IAMError(e);
    }
}

IAMError set_password(std::shared_ptr<nabto::client::Connection> connection, const std::string& user, const std::string& password)
{
    std::stringstream path;
    path << "/iam/users/" << user << "/password";
    try {
        auto coap = connection->createCoap("PUT", path.str());
        nlohmann::json root;
        root = password;
        std::vector<uint8_t> cbor = nlohmann::json::to_cbor(root);
        coap->setRequestPayload(CONTENT_FORMAT_APPLICATION_CBOR, cbor);
        coap->execute()->waitForResult();
        int responseCode = coap->getResponseStatusCode();
        if(responseCode == 204) {
            return IAMError();
        }
        return IAMError(coap);
    } catch (nabto::client::NabtoException& e) {
        return IAMError(e);
    }
    
}

std::pair<IAMError, std::unique_ptr<User> > create_user(
    std::shared_ptr<nabto::client::Connection> connection,
    const std::string &username) {
    auto coap = connection->createCoap("POST", "/iam/users");
    nlohmann::json root;
    root["Username"] = username;
    std::vector<uint8_t> cborOut = nlohmann::json::to_cbor(root);
    coap->setRequestPayload(CONTENT_FORMAT_APPLICATION_CBOR, cborOut);

    coap->execute()->waitForResult();
    uint16_t statusCode = coap->getResponseStatusCode();
    if (statusCode == 201) {
        auto cbor = coap->getResponsePayload();

        json user = json::from_cbor(cbor);
                
        std::unique_ptr<User> decoded = User::create(user);
        return std::make_pair(IAMError(), std::move(decoded));
    } else {
        return std::make_pair(IAMError(coap), nullptr);
    }
}


void from_json(const json& j, PairingInfo& pi)
{
    try {
        j.at("ProductId").get_to(pi.productId_);
    } catch (std::exception& e) {}

    try {
        j.at("DeviceId").get_to(pi.deviceId_);
    } catch (std::exception& e) {}

    try {
        j.at("AppName").get_to(pi.appName_);
    } catch (std::exception& e) {}

    try {
        j.at("AppVersion").get_to(pi.appVersion_);
    } catch (std::exception& e) {}

    try {
        j.at("NabtoVersion").get_to(pi.nabtoVersion_);
    } catch (std::exception& e) {}

    try {
        std::vector<std::string> modes = j["Modes"].get<std::vector<std::string> >();
        for (auto m : modes) {
            if (m == "LocalOpen") {
                pi.modes_.insert(PairingMode::LOCAL_OPEN);
            } else if (m == "PasswordOpen") {
                pi.modes_.insert(PairingMode::PASSWORD_OPEN);
            } else if (m == "ButtonOpen") {
                pi.modes_.insert(PairingMode::BUTTON_OPEN);
            } else if (m == "PasswordInvite") {
                pi.modes_.insert(PairingMode::PASSWORD_INVITE);
            }
        }
    } catch (std::exception& e) {}
}

std::pair<IAMError, std::unique_ptr<PairingInfo> > get_pairing_info(
    std::shared_ptr<nabto::client::Connection> connection)
{
    auto coap = connection->createCoap("GET", "/iam/pairing");
    try {
        coap->execute()->waitForResult();
        int statusCode = coap->getResponseStatusCode();
        int contentFormat = coap->getResponseContentFormat();
        if (statusCode == 205 &&
            contentFormat == CONTENT_FORMAT_APPLICATION_CBOR) {
            std::vector<uint8_t> payload = coap->getResponsePayload();
            nlohmann::json root = nlohmann::json::from_cbor(payload);
            return std::make_pair(IAMError(), std::make_unique<PairingInfo>(root.get<PairingInfo>()));
        }

        return std::make_pair(IAMError(coap), nullptr);
    } catch (nabto::client::NabtoException& e) {
        return std::make_pair(IAMError(e), nullptr);
    } catch (nlohmann::json::exception& e) {
        return std::make_pair(IAMError(e), nullptr);
    }
}

}
