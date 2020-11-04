#pragma once

#include "iam.hpp"

namespace IAM {

int interactive_choice(const std::string message, size_t min, size_t maxPlusOne);
bool list_users(std::shared_ptr<nabto::client::Connection> connection);
bool list_roles(std::shared_ptr<nabto::client::Connection> connection);
bool set_role_interactive(std::shared_ptr<nabto::client::Connection> connection);
bool delete_user_interactive(std::shared_ptr<nabto::client::Connection> connection);
bool get_user_interactive(std::shared_ptr<nabto::client::Connection> connection);
bool get_me_interactive(std::shared_ptr<nabto::client::Connection> connection);
bool create_user_interactive(std::shared_ptr<nabto::client::Connection> connection);

}