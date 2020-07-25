#include <memory>
#include <nabto_client.hpp>
#include <nabto/nabto_client_experimental.h>
#include <string>

namespace IAM
{
    bool list_users(std::shared_ptr<nabto::client::Connection> connection);
    bool list_roles(std::shared_ptr<nabto::client::Connection> connection);
    bool add_role_to_user(std::shared_ptr<nabto::client::Connection> connection, const std::string &user, const std::string &role);
    bool remove_role_from_user(std::shared_ptr<nabto::client::Connection> connection, const std::string &user, const std::string &role);
    bool delete_user(std::shared_ptr<nabto::client::Connection> connection, const std::string &user);
}
