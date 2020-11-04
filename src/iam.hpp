#pragma once
#include "config.hpp"
#include <memory>
#include <nabto_client.hpp>
#include <nabto/nabto_client_experimental.h>
#include <string>
#include <iostream>
#include <set>

#include <nlohmann/json.hpp>

namespace IAM {

class IAMError {
 public:
    IAMError();
    IAMError(std::shared_ptr<nabto::client::Coap> coap);
    IAMError(nabto::client::NabtoException e);
    IAMError(std::exception& e);
    IAMError(const std::string& message);

    bool ok();
    void printError();

 private:
    bool ok_ = false;
    uint16_t statusCode_ = 0;
    std::string message_;
};

class User {
 public:
    static std::unique_ptr<User> create(const nlohmann::json& in);
    std::string getUsername() { return username_; }
    std::string getRole() { return role_; }
    std::string getServerConnectToken() { return serverConnectToken_; }
    std::string getFingerprint() { return fingerprint_; }
    void print() {
        std::cout << "Username: " << username_ << ", Role: " << role_ << ", SCT: " << serverConnectToken_ << ", Fingerprint " << fingerprint_ << std::endl;
    }
 public:
    std::string username_;
    std::string role_;
    std::string serverConnectToken_;
    std::string fingerprint_;
};

const static int CONTENT_FORMAT_APPLICATION_CBOR = 60; // rfc 7059

enum class PairingMode {
    NONE,
    BUTTON_OPEN,
    PASSWORD_OPEN,
    LOCAL_OPEN,
    PASSWORD_INVITE
};

class PairingInfo {
 public:
    std::string getNabtoVersion() { return nabtoVersion_; }
    std::string getAppVersion() { return appVersion_; }
    std::string getAppName() { return appName_; }
    std::string getProductId() { return productId_; }
    std::string getDeviceId() { return deviceId_; }
    std::set<PairingMode> getModes() { return modes_; }
    std::string nabtoVersion_;
    std::string appVersion_;
    std::string appName_;
    std::string productId_;
    std::string deviceId_;
    std::set<PairingMode> modes_;
};

std::pair<IAMError, std::unique_ptr<PairingInfo> > get_pairing_info(std::shared_ptr<nabto::client::Connection> connection);
std::pair<IAMError, std::set<std::string> > get_users(std::shared_ptr<nabto::client::Connection> connection);
std::pair<IAMError, std::unique_ptr<User> > get_user(std::shared_ptr<nabto::client::Connection> connection, const std::string& username);
std::pair<IAMError, std::set<std::string> > get_roles(std::shared_ptr<nabto::client::Connection> connection);
IAMError set_role(std::shared_ptr<nabto::client::Connection> connection, const std::string &user, const std::string &role);
IAMError set_password(std::shared_ptr<nabto::client::Connection> connection, const std::string& user, const std::string& password);
std::pair<IAMError, std::unique_ptr<User> > create_user(std::shared_ptr<nabto::client::Connection> connection, const std::string &username);
std::pair<IAMError, std::unique_ptr<User> > get_me(std::shared_ptr<nabto::client::Connection> connection);
std::pair<IAMError, std::unique_ptr<PairingInfo> > get_pairing_info(std::shared_ptr<nabto::client::Connection> connection);

} // namespace