#pragma once
#include <string>
#include <memory>

namespace nabto {
namespace client {

class Context;

} }

namespace Configuration
{
    struct DeviceInfo
    {
        std::string DeviceID;
        std::string ProductID;
        std::string DeviceFingerprint;
        std::string ServerConnectToken;
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
    DeviceInfo *GetPairedDevice(int Index);
    void AddPairedDeviceToBookmarks(DeviceInfo Info);
    bool GetPrivateKey(std::shared_ptr<nabto::client::Context> Context, std::string& PrivateKey);
    void PrintBookmarks();
}
