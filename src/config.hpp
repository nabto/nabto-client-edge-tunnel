#pragma once
#include <string>
#include <memory>

#include <sstream>

namespace nabto {
namespace client {

class Context;

} }



namespace Configuration
{

const std::string defaultServerKey = "sk-9c826d2ebb4343a789b280fe22b98305";
#if defined(_WIN32)
const std::string homeDirEnvVariable = "APPDATA";
const std::string nabtoFolder = "nabto";
#else
const std::string homeDirEnvVariable = "HOME";
const std::string nabtoFolder = ".nabto";
#endif

const std::string ClientFileName = "config/tcp_tunnel_client_config.json";
const std::string StateFileName = "config/tcp_tunnel_client_state.json";
const std::string KeyFileName = "keys/client.key";


class DeviceInfo
{
 public:

    std::string getFriendlyName() const
    {
        std::stringstream ss;
        ss << "[" << index_ << "] " << productId_ << "." << deviceId_;
        return ss.str();
    }

    std::string getDeviceId() { return deviceId_; }
    std::string getProductId() { return productId_; }
    std::string getDeviceFingerprint() { return deviceFingerprint_; }
    std::string getSct() { return sct_; }
    std::string getDirectCandidate() { return directCandidate_; }
    int getIndex() { return index_; }

    int index_;
    std::string deviceId_;
    std::string productId_;
    std::string deviceFingerprint_;
    std::string sct_;
    std::string directCandidate_;
};

class ClientConfiguration {
 public:
    ClientConfiguration(const std::string serverKey, const std::string serverUrl)
        : serverKey_(serverKey), serverUrl_(serverUrl)
    {
    }
    std::string getServerUrl() { return serverUrl_; }
    std::string getServerKey() { return serverKey_; }
 private:
    std::string serverKey_;
    std::string serverUrl_;
};

void InitializeWithDirectory(const std::string &HomePath);
std::unique_ptr<ClientConfiguration> GetConfigInfo();
const char* GetConfigFilePath();
const char* GetStateFilePath();
bool WriteStateFile();
std::unique_ptr<DeviceInfo> GetPairedDevice(int Index);
std::unique_ptr<DeviceInfo> GetPairedDevice(const std::string& fingerprint);
bool HasNoBookmarks();
// insert info into bookmarks, and set the index into the info
void AddPairedDeviceToBookmarks(DeviceInfo& Info);
bool GetPrivateKey(std::shared_ptr<nabto::client::Context> Context, std::string& PrivateKey);
void PrintBookmarks();
bool DeleteBookmark(const uint32_t& bookmark);

bool makeDirectories(const std::string& in);
std::string getDefaultHomeDir();

} // namespace
