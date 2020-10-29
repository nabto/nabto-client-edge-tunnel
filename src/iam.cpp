#include "iam.h"
#include <string>
#include <sstream>
#include <iostream>

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
bool yn_prompt(const std::string &message)
{
    char answer = 0;
    do
    {
        std::cout << message << " [y/n]: ";
        std::cin >> answer;
    }
    while (!std::cin.fail() && answer != 'y' && answer != 'n');

    return answer == 'y';
}


void print_coap_error(const std::string &path, int responseCode)
{
    std::cout << "The CoAP request to " << path << " returned response code: "
              << responseCode << std::endl;
}

void print_error_access_denied()
{
    std::cout
        << "This is potentially due to insufficient privileges,\n"
        << "check the IAM policies file if you are the owner of this device."
        << std::endl;
}

bool list_users(std::shared_ptr<nabto::client::Connection> connection)
{
    bool result = false;
    std::string path = "/iam/users";
    auto coap = connection->createCoap("GET", path);

    try
    {
        coap->execute()->waitForResult();
        int responseCode = coap->getResponseStatusCode();
        switch (responseCode)
        {
            case 205:
            {
                auto cbor = coap->getResponsePayload();
                std::cout << "Listing all users on the device ..." << std::endl;
                json user_list = json::from_cbor(cbor);
                int i = 1;
                for (auto &user : user_list)
                {
                    std::cout << "[" << i++ << "] UserID: " << user.get<std::string>() << std::endl;;
                }
                result = true;
                break;
            }

            case 403:
            {
                std::cout
                    << "The request to list users (" << path << ")"
                    << " was denied." << std::endl;
                print_error_access_denied();
                break;
            }

            default:
            {
                print_coap_error(path, responseCode);
                break;
            }
        }
    }
    catch (...)
    {
        std::cerr << "Cannot get IAM user list" << std::endl;
    }

    return result;
}

bool get_user(std::shared_ptr<nabto::client::Connection> connection, const std::string& userId)
{
    bool result = false;
    std::string path = "/iam/users/" + userId;
    auto coap = connection->createCoap("GET", path);

    try
    {
        coap->execute()->waitForResult();
        int responseCode = coap->getResponseStatusCode();
        switch (responseCode)
        {
            case 205:
            {
                auto cbor = coap->getResponsePayload();

                json user = json::from_cbor(cbor);
                std::cout << user.dump(4) << std::endl;
                result = true;
                break;
            }

            case 403:
            {
                std::cout
                    << "The request to list roles (" << path << ")"
                    << " was denied." << std::endl;
                print_error_access_denied();
                break;
            }

            default:
            {
                print_coap_error(path, responseCode);
                break;
            }
        }
    }
    catch (...)
    {
        std::cerr << "Cannot get the user " << userId << std::endl;
    }
    return result;
}


bool get_me(std::shared_ptr<nabto::client::Connection> connection)
{
    bool result = false;
    std::string path = "/iam/me";
    auto coap = connection->createCoap("GET", path);

    try
    {
        coap->execute()->waitForResult();
        int responseCode = coap->getResponseStatusCode();
        switch (responseCode)
        {
            case 205:
            {
                auto cbor = coap->getResponsePayload();

                json user = json::from_cbor(cbor);
                std::cout << user.dump(4) << std::endl;
                result = true;
                break;
            }

            case 403:
            {
                std::cout
                    << "The request to (" << path << ")"
                    << " was denied." << std::endl;
                print_error_access_denied();
                break;
            }

            default:
            {
                print_coap_error(path, responseCode);
                break;
            }
        }
    }
    catch (...)
    {
        std::cerr << "Cannot get the user which is associated with the connection " << std::endl;
    }
    return result;
}



bool list_roles(std::shared_ptr<nabto::client::Connection> connection)
{
    bool result = false;
    std::string path = "/iam/roles";
    auto coap = connection->createCoap("GET", path);

    try
    {
        coap->execute()->waitForResult();
        int responseCode = coap->getResponseStatusCode();
        switch (responseCode)
        {
            case 205:
            {
                auto cbor = coap->getResponsePayload();
                std::cout << "Listing available roles on the device ..." << std::endl;
                json role_list = json::from_cbor(cbor);
                int i = 1;
                for (auto &role : role_list)
                {
                    std::cout << "[" << i++ << "]: " << role.get<std::string>() << std::endl;;
                }
                result = true;
                break;
            }

            case 403:
            {
                std::cout
                    << "The request to list roles (" << path << ")"
                    << " was denied." << std::endl;
                print_error_access_denied();
                break;
            }

            default:
            {
                print_coap_error(path, responseCode);
                break;
            }
        }
    }
    catch (...)
    {
        std::cerr << "Cannot get IAM role list" << std::endl;
    }
    return result;
}

bool set_role(std::shared_ptr<nabto::client::Connection> connection,
              const std::string &user, const std::string &role)
{
    std::stringstream pathStream{};
    pathStream << "/iam/users/" << user << "/role/" << role;
    const std::string &path = pathStream.str();

    char answer;
    std::stringstream message{};
    message << "Assign the role \"" << role << "\" to the user \"" << user << "\"? ";
    bool yes = yn_prompt(message.str());

    if (yes)
    {
        bool status = false;
        auto coap = connection->createCoap("PUT", path);
        try
        {
            coap->execute()->waitForResult();
            int responseCode = coap->getResponseStatusCode();
            switch (responseCode)
            {
                case 204:
                {
                    std::cout << "Success. Assigned the role: " << role << " to the user with the id: " << user << std::endl;
                    status = true;
                    break;
                }

                case 403:
                {
                    std::cout << "The request was denied." << std::endl;
                    print_error_access_denied();
                    break;
                }
                case 404:
                {
                    std::cout << "The user or role does not exists" << std::endl;
                    break;
                }

                case 500:
                {
                    std::cout
                        << "The request returned error 500.\n"
                        << "Are you sure you typed in the right role id and user id?"
                        << std::endl;
                    break;
                }

                default:
                {
                    print_coap_error(path, responseCode);
                    break;
                }
            }
        }
        catch (...)
        {
            std::cerr << "An unknown error occurred." << std::endl;
        }

        return status;
    }
    else
    {
        std::cout << "Action cancelled." << std::endl;
        return true;
    }
}

bool delete_user(std::shared_ptr<nabto::client::Connection> connection,
                 const std::string &user)
{
    std::stringstream pathStream{};
    pathStream << "/iam/users/" << user;
    const std::string &path = pathStream.str();

    std::stringstream message{};
    message << "Delete the user \"" << user << "\"? ";
    bool yes = yn_prompt(message.str());
    if (yes)
    {
        bool status = false;
        auto coap = connection->createCoap("DELETE", path);
        try
        {
            coap->execute()->waitForResult();
            int responseCode = coap->getResponseStatusCode();
            switch(responseCode)
            {
                case 202:
                {
                    std::cout << "Success." << std::endl;
                    status = true;
                    break;
                }

                case 403:
                {
                    std::cout
                        << "The request to DELETE from"
                        << path << "was denied."
                        << std::endl;
                    print_error_access_denied();
                    break;
                }

                default:
                {
                    print_coap_error(path, responseCode);
                    break;
                }
            }
        }
        catch (...)
        {
            std::cerr << "An unknown error occurred." << std::endl;
        }
        return status;
    }
    else
    {
        std::cout << "Action cancelled." << std::endl;
        return true;
    }
    return false;
}
}
