#pragma once
#include <nabto_client.hpp>
#include <string>
#include <memory>
#include <set>

bool interactive_pair(std::shared_ptr<nabto::client::Context> Context);
bool string_pair(std::shared_ptr<nabto::client::Context> Context, const std::string& pairString);
bool direct_pair(std::shared_ptr<nabto::client::Context> Context, const std::string& host);


