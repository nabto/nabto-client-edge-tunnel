#include "config.hpp"
#include <memory>
#include <nabto_client.hpp>
#include <nabto/nabto_client_experimental.h>
#include <string>
#include <iostream>

#include <nlohmann/json.hpp>

namespace IAM {

class User {
 public:
    static std::unique_ptr<User> create(const nlohmann::json& in);
    std::string getId() { return id_; }
    std::string getName() { return name_; }
    std::string getRole() { return role_; }
    std::string getServerConnectToken() { return serverConnectToken_; }
    std::string getFingerprint() { return fingerprint_; }
    void print() {
        std::cout << "User Id: " << id_ << ", Name: " << name_ << ", Role: " << role_ << ", SCT: " << serverConnectToken_ << ", Fingerprint " << fingerprint_ << std::endl;
    }
 public:
    std::string id_;
    std::string name_;
    std::string role_;
    std::string serverConnectToken_;
    std::string fingerprint_;
};

bool list_users(std::shared_ptr<nabto::client::Connection> connection);
bool list_roles(std::shared_ptr<nabto::client::Connection> connection);
bool set_role(std::shared_ptr<nabto::client::Connection> connection,
              const std::string &user, const std::string &role);
bool delete_user(std::shared_ptr<nabto::client::Connection> connection,
                 const std::string &user);
std::unique_ptr<User> get_user(std::shared_ptr<nabto::client::Connection> connection, const std::string& userId);
std::unique_ptr<User> get_me(std::shared_ptr<nabto::client::Connection> connection);

} // namespace
