#pragma once

#include "iam.hpp"

namespace IAM {

bool list_users(std::shared_ptr<nabto::client::Connection> connection);
bool list_roles(std::shared_ptr<nabto::client::Connection> connection);
bool set_role_interactive(std::shared_ptr<nabto::client::Connection> connection,
              const std::string &user, const std::string &role);
bool delete_user(std::shared_ptr<nabto::client::Connection> connection,
                 const std::string &user);
std::unique_ptr<User> get_user_interactive(std::shared_ptr<nabto::client::Connection> connection, const std::string& username);
bool create_user_interactive(std::shared_ptr<nabto::client::Connection> connection);

}