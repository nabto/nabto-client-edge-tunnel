#pragma once

#include <nabto_client.hpp>

#include <string>

#include <memory>

namespace nabto {
namespace examples {
namespace common {

bool interactive_pair(std::shared_ptr<nabto::client::Context> ctx, const std::string& configFile, const std::string& friendlyName);
bool link_pair(std::shared_ptr<nabto::client::Context> ctx, const std::string& configFile, const std::string& stateFile, const std::string& userName, const std::string& remotePairUrl);

} } } // namespace
