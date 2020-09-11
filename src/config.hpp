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

class DeviceInfo
{
 public:

    std::string GetFriendlyName() const
    {
        std::stringstream ss;
        ss << "[" << Index << "] " << ProductID << "." << DeviceID;
        return ss.str();
    }

    int Index;
    std::string DeviceID;
    std::string ProductID;
    std::string DeviceFingerprint;
    std::string ServerConnectToken;
    std::string DirectCandidate;
};

    struct ConfigInfo
    {
        const char* ServerKey;
        const char* ServerUrl;
    };

    void InitializeWithDirectory(const std::string &HomePath);
    void Initialize();
    bool GetConfigInfo(ConfigInfo *Info);
    const char* GetConfigFilePath();
    const char* GetStateFilePath();
    bool WriteStateFile();
    std::unique_ptr<DeviceInfo> GetPairedDevice(int Index);
    bool HasNoBookmarks();
    void AddPairedDeviceToBookmarks(DeviceInfo Info);
    bool GetPrivateKey(std::shared_ptr<nabto::client::Context> Context, std::string& PrivateKey);
    void PrintBookmarks();
}
