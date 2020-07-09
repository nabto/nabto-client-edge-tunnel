#pragma once
#include <string>

namespace Configuration {
    struct DeviceInfo {
        std::string DeviceID;
        std::string ProductID;
        std::string PrivateKey;
        std::string DeviceFingerprint;
        std::string ServerConnectToken;
    };

    struct ConfigInfo {
        const char* ServerKey;
        const char* ServerUrl;
    };

    void Initialize(std::string ConfigFilePath, std::string StateFilePath);
    bool GetConfigInfo(ConfigInfo *Info);
    const char* GetConfigFilePath();
    const char* GetStateFilePath();
    bool WriteStateFile();
    DeviceInfo *GetPairedDevice(int Index);
    void AddPairedDeviceToBookmarks(DeviceInfo Info);
    void PrintBookmarks();
}
