#include "config.hpp"
#include <memory>
#include <nabto_client.hpp>
#include <nabto/nabto_client_experimental.h>
#include <string>



namespace IAM {

bool list_users(std::shared_ptr<nabto::client::Connection> connection);
bool list_roles(std::shared_ptr<nabto::client::Connection> connection);
bool set_role(std::shared_ptr<nabto::client::Connection> connection,
              const std::string &user, const std::string &role);
bool delete_user(std::shared_ptr<nabto::client::Connection> connection,
                 const std::string &user);
bool get_user(std::shared_ptr<nabto::client::Connection> connection, const std::string& userId);
bool get_me(std::shared_ptr<nabto::client::Connection> connection);

} // namespace
