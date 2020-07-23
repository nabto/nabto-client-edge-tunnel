#include "iam.h"
#include <string>
#include <sstream>
#include <iostream>

#include <3rdparty/nlohmann/json.hpp>

using json = nlohmann::json;

namespace IAM
{
    void print_coap_error(std::string &path, int responseCode)
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
                    // TODO(ahs): pretty print the list instead of dumping json directly.
                    auto cbor = coap->getResponsePayload();
                    std::cout << json::from_cbor(cbor).dump(2);
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
                    // TODO(ahs): pretty print the list instead of dumping json directly.
                    auto cbor = coap->getResponsePayload();
                    std::cout << json::from_cbor(cbor).dump(2);
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

    bool add_role_to_user(std::shared_ptr<nabto::client::Connection> connection,
                          const std::string &user, const std::string &role)
    {
        std::stringstream pathStream{};
        pathStream << "/iam/users/" << user << "/roles/" << role;

        std::string &path = pathStream.str();

        char Answer = 0;
        do
        {
            std::cout << "Really add role \"" << role << "\" to user \"" << user <<"\"? [y/n]" << std::endl;
            std::cin >> Answer;
        }
        while (!std::cin.fail() && Answer != 'y' && Answer != 'n');

        if (Answer == 'y')
        {
            bool status = false;
            auto coap = connection->createCoap("PUT", path);
            try
            {
                coap->execute()->waitForResult();
                int responseCode = coap->getResponseStatusCode();
                switch (responseCode)
                {
                    case 201:
                    {
                        std::cout << "Success." << std::endl;
                        status = true;
                        break;
                    }

                    case 403:
                    {
                        std::cout << "The request was denied." << std::endl;
                        print_error_access_denied();
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
                // TODO(ahs): this should be expanded on to let the user know what's going on.
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

    // TODO(ahs): implement these.
    bool remove_role_from_user(std::shared_ptr<nabto::client::Connection> connection,
                               const std::string &user, const std::string &role)
    {
        return false;
    }

    bool delete_user_with_prompt(std::shared_ptr<nabto::client::Connection> connection,
                                 const std::string &user)
    {
        return false;
    }
}
