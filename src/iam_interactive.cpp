#include "iam_interactive.hpp"
#include <nlohmann/json.hpp>

#include <random>

namespace IAM {

std::pair<IAMError, std::string> pick_role_interactive(std::shared_ptr<nabto::client::Connection> connection, const std::string& message);
std::pair<IAMError, std::string> pick_user_interactive(std::shared_ptr<nabto::client::Connection> connection, const std::string& message);


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
                nlohmann::json user_list = nlohmann::json::from_cbor(cbor);
                int i = 1;
                for (auto &user : user_list)
                {
                    std::cout << "[" << i++ << "] Username: " << user.get<std::string>() << std::endl;;
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

std::unique_ptr<User> get_user_interactive(std::shared_ptr<nabto::client::Connection> connection, const std::string& username)
{
    bool result = false;
    std::string path = "/iam/users/" + username;
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


                nlohmann::json user = nlohmann::json::from_cbor(cbor);
                auto decoded = User::create(user);
                return decoded;

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
        std::cerr << "Cannot get the user " << username << std::endl;
    }
    return nullptr;
}

bool list_roles(std::shared_ptr<nabto::client::Connection> connection)
{
    bool result = false;
    std::string path = "/iam/roles";
    auto coap = connection->createCoap("GET", path);

    IAMError ec;
    std::set<std::string> roles;
    std::tie(ec, roles) = get_roles(connection);
    if (ec.ok()) {
        size_t i = 1;
        for (auto role : roles) {
            std::cout << "[" << i << "]: " << role << std::endl;
            i++;
        }
        return true;
    } else {
        ec.printError();
    }
    return false;
}


std::string random_string(size_t n)
{
    const std::string characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distribution(0, characters.size() - 1);

    std::string randomString;

    for (std::size_t i = 0; i < n; ++i)
    {
        randomString += characters[distribution(generator)];
    }

    return randomString;
}


bool set_role_interactive(std::shared_ptr<nabto::client::Connection> connection)
{
    IAMError ec;
    std::string username;
    std::string role;

    std::tie(ec, username) = pick_user_interactive(connection, "Choose a user to assign a role");

    if (!ec.ok()) {
        ec.printError();
        return false;
    }

    std::tie(ec, role) = pick_role_interactive(connection, "Choose a role to assign to the user " + username);
    if (!ec.ok()) {
        ec.printError();
        return false;
    }



    std::stringstream path;
    path << "/iam/users/" << username << "/role/" << role;

    char answer;
    std::stringstream message{};
    message << "Assign the role \"" << role << "\" to the user \"" << username << "\"? ";
    bool yes = yn_prompt(message.str());

    if (yes)
    {
        IAMError ec = set_role(connection, username, role);
        if (ec.ok()) {
            std::cout << "Success. Assigned the role: " << role << " to the user with the id: " << username << std::endl;
            return true;
        }
        ec.printError();
        return false;
    }
    else
    {
        std::cout << "Action cancelled." << std::endl;
        return true;
    }
}


std::pair<IAMError, std::string> pick_user_interactive(std::shared_ptr<nabto::client::Connection> connection, const std::string& message)
{
    std::set<std::string> users;
    IAMError ec;
    std::tie(ec, users) = get_users(connection);
    if (!ec.ok()) {
        return std::make_pair(ec, "");
    } else {
        std::vector<std::string> us;
        std::copy(users.begin(), users.end(), std::back_inserter(us));
        std::cout << message << std::endl;
        for (size_t i = 0; i < us.size(); i++) {
            std::cout << "[" << i << "] " << us[i] << std::endl;
        }
        size_t choice = 0;
        while (true) {
            std::cout << "User: ";
            std::cin >> choice;
            if (choice < us.size()) {
                break;
            } else {
                std::cout << "Invalid choice" << std::endl;
            }
        }
        return std::make_pair(IAMError(), us[choice]);
    }
}

bool delete_user_interactive(std::shared_ptr<nabto::client::Connection> connection)
{

    IAMError ec;
    std::string username;
    std::tie(ec, username) = pick_user_interactive(connection, "Pick a user to delete");
    if (!ec.ok()) {
        ec.printError();
        return false;
    }
    std::stringstream path;
    path << "/iam/users/" << username;

    std::stringstream message{};
    message << "Delete the user \"" << username << "\"? ";
    bool yes = yn_prompt(message.str());
    if (yes)
    {
        bool status = false;
        auto coap = connection->createCoap("DELETE", path.str());
        try
        {
            coap->execute()->waitForResult();
            int responseCode = coap->getResponseStatusCode();
            if (responseCode == 202) {
                std::cout << "Success." << std::endl;
                return true;
            }
            // failed
            IAMError ec(coap);
            ec.printError();
        }
        catch (...)
        {
            std::cerr << "An unknown error occurred." << std::endl;
        }
        return false;
    }
    else
    {
        std::cout << "Action cancelled." << std::endl;
        return true;
    }
    return false;
}


std::pair<IAMError, std::string> pick_role_interactive(std::shared_ptr<nabto::client::Connection> connection, const std::string& message)
{
    std::set<std::string> roles;
    IAMError ec;
    std::tie(ec, roles) = get_roles(connection);
    if (!ec.ok()) {
        return std::make_pair(ec, "");
    } else {
        if (roles.size() == 0) {
            std::cerr << "No roles available" << std::endl;
            // todo
            return std::make_pair(IAMError(), "");
        }
        std::vector<std::string> rs;
        std::copy(roles.begin(), roles.end(), std::back_inserter(rs));
        std::cout << message << std::endl;

        for (size_t i = 0; i < rs.size(); i++) {
            std::cout << "[" << i << "] " << rs[i] << std::endl;
        }
        size_t role = 0;
        while (true) {
            size_t max = rs.size() - 1;
            std::cout << "Role 0 - " << max << ": ";
            std::cin >> role;
            if (role < rs.size()) {
                break;
            } else {
                std::cerr << role << " is not a valid choice" << std::endl;
            }
        }
        return std::make_pair(IAMError(), rs[role]);
    }
}


bool create_user_interactive(std::shared_ptr<nabto::client::Connection> connection)
{
    std::string password = random_string(12);

    std::cout << "Choose a username for the new user." << std::endl;
    std::string username;
    std::cout << "Username: ";
    std::cin >> username;
    std::string role;
    {
        IAMError ec;
        std::tie(ec, role) = pick_role_interactive(connection, "Pick a role for the user");
    }
    {
        IAMError ec;
        std::unique_ptr<IAM::User> user;
        std::tie(ec,user) = create_user(connection, username);
        if (!ec.ok()) {
            std::cerr << "Could not create the user " << username << std::endl;
            ec.printError();
            return false;
        }
    }
    {
        IAMError ec;
        ec = set_role(connection, username, role);
        if (!ec.ok()) {
            std::cerr << "Could not assign the role " << role << " to the user " << username << std::endl;
            ec.printError();
            return false;
        }
    }
    {
        IAMError ec;
        ec = set_password(connection, username, password);
        if(!ec.ok()) {
            std::cerr << "Could not set password" << std::endl;
            ec.printError();
            return false;
        }
    }
    {
        IAMError ec;
        std::unique_ptr<User> user;
        std::tie(ec, user) = get_user(connection, username);
        if (!ec.ok()) {
            std::cerr << "Could not retrieve the newly created user" << std::endl;
            ec.printError();
            return false;
        }

        std::unique_ptr<PairingInfo> pi;
        std::tie(ec, pi) = get_pairing_info(connection);

        std::stringstream pairingString;
        pairingString << "p=" << pi->getProductId() << ",d=" << pi->getDeviceId() << ",n=" << user->getUsername() << ",pwd=" << password << ",sct=" << user->getServerConnectToken();

        std::cout << "Created a new user in the system" << std::endl;
        std::cout << "Username:        " << user->getUsername() << std::endl;
        std::cout << "Role:            " << user->getRole() << std::endl;
        std::cout << "SCT:             " << user->getServerConnectToken() << std::endl;
        std::cout << "Password:        " << password << std::endl;
        std::cout << "Pairing String:  " << pairingString.str() << std::endl;
    }

    return true;
}


}