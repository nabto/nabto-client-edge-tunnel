#include <memory>
#include <nabto_client.hpp>
#include <nabto/nabto_client_experimental.h>
#include <string>

namespace IAM
{
    bool list_users(std::shared_ptr<nabto::client::Connection> connection, uint32_t device);
    bool list_roles(std::shared_ptr<nabto::client::Connection> connection, uint32_t device);
    bool add_role_to_user(std::shared_ptr<nabto::client::Connection> connection,
                          const std::string &user, const std::string &role, uint32_t device);
    bool remove_role_from_user(std::shared_ptr<nabto::client::Connection> connection,
                               const std::string &user, const std::string &role, uint32_t device);
    bool delete_user(std::shared_ptr<nabto::client::Connection> connection,
                     const std::string &user, uint32_t device);
}
