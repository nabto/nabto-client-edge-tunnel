#pragma once
#include <nabto_client.hpp>
#include <string>
#include <memory>

bool interactive_pair(std::shared_ptr<nabto::client::Context> Context, const std::string& FriendlyName);
bool link_pair(std::shared_ptr<nabto::client::Context> Context, const std::string& UserName, const std::string& RemotePairURL);
bool string_pair(std::shared_ptr<nabto::client::Context> Context, const std::string& UserName, const std::string& RemotePairURL);
bool direct_pair(std::shared_ptr<nabto::client::Context> Context, const std::string& UserName, const std::string& );
