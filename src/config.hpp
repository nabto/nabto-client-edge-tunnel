#pragma once
#include <string>

namespace Configuration
{
    struct DeviceInfo
    {
        std::string DeviceID;
        std::string ProductID;
        std::string PrivateKey;
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
    void PrintBookmarks();
}
