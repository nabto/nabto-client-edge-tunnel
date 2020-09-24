#pragma once
#include <nabto_client.hpp>
#include <string>
#include <memory>
#include <set>

const static int CONTENT_FORMAT_APPLICATION_CBOR = 60; // rfc 7059

enum class PairingMode {
    NONE,
    BUTTON,
    PASSWORD,
    LOCAL
};

struct PairingInfo {
    std::string NabtoVersion;
    std::string AppVersion;
    std::string AppName;
    std::string ProductId;
    std::string DeviceId;
    std::set<PairingMode> Modes;
};

bool interactive_pair(std::shared_ptr<nabto::client::Context> Context, const std::string& UserName);
bool string_pair(std::shared_ptr<nabto::client::Context> Context, const std::string& UserName, const std::string& RemotePairURL);
bool direct_pair(std::shared_ptr<nabto::client::Context> Context, const std::string& userName, const std::string& host);

std::unique_ptr<PairingInfo> getPairingInfo(std::shared_ptr<nabto::client::Connection> connection);
