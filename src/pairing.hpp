#pragma once
#include <nabto_client.hpp>
#include <string>
#include <memory>
#include <set>

bool interactive_pair(std::shared_ptr<nabto::client::Context> Context, const std::string& UserName);
bool string_pair(std::shared_ptr<nabto::client::Context> Context, const std::string& UserName, const std::string& RemotePairURL);
bool direct_pair(std::shared_ptr<nabto::client::Context> Context, const std::string& userName, const std::string& host);


