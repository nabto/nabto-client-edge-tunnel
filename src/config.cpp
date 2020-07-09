#include "config.hpp"

#include <3rdparty/nlohmann/json.hpp>
#include <vector>
#include <fstream>
#include <cstdio>
#include <iostream>
#include <iomanip>

using json = nlohmann::json;
using string = std::string;

// TODO(as): Implement OS platform layer for a smoother experience?
// Instead of using the C++ std stuff (which won't be perfect across platforms)
// have a WriteStringToFile() and LoadEntireFile() which calls the relevant POSIX/win32 functions
// and use C++ std as a fallback.
namespace Configuration
{
    void to_json(json& j, const DeviceInfo& d)
    {
        j = json({
            {"DeviceFingerprint", d.DeviceFingerprint},
            {"DeviceId", d.DeviceID},
            {"PrivateKey", d.PrivateKey},
            {"ProductId", d.ProductID},
            {"ServerConnectToken", d.ServerConnectToken}
        });
    }

    void from_json(const json& j, DeviceInfo& d)
    {
        j.at("DeviceFingerprint").get_to(d.DeviceFingerprint);
        j.at("DeviceId").get_to(d.DeviceID);
        j.at("PrivateKey").get_to(d.PrivateKey);
        j.at("ProductId").get_to(d.ProductID);
        j.at("ServerConnectToken").get_to(d.ServerConnectToken);
    }

    static struct
    {
        string ConfigFilePath;
        string StateFilePath;
        std::vector<DeviceInfo> Bookmarks;

        bool HasLoadedConfigFile;
        string ServerUrl;
        string ServerKey;
    } Configuration;

    void Initialize(std::string ConfigFilePath, std::string StateFilePath)
    {
        Configuration.ConfigFilePath.assign(ConfigFilePath);
        Configuration.StateFilePath.assign(StateFilePath);
        Configuration.HasLoadedConfigFile = false;
        Configuration.ServerUrl = "";
        Configuration.ServerKey = "";

        json StateContents;
        try
        {
            std::ifstream StateFile(StateFilePath);
            StateFile >> StateContents;
        }
        catch (...)
        {
            // NOTE(as): State file wasn't found, it'll probably be created later.
        }

        try
        {
            for(auto Device : StateContents["devices"])
            {
                DeviceInfo Info = Device.get<DeviceInfo>();
                Configuration.Bookmarks.push_back(Info);
            }
        }
        catch (...)
        {
            // NOTE(as): Corrupted state file.
            // TODO(as): Analyze the file and let the user know where exactly it went wrong?
            std::cerr << "IMPORTANT: Your state file (" << StateFilePath << ") seems to be incorrect.\n" <<
            "As a result no paired devices were loaded from it." << std::endl;
            Configuration.Bookmarks.clear();
        }
    }

    static void InitConfigInfoStruct(ConfigInfo *Info) {
        Info->ServerKey = Configuration.ServerKey.c_str();
        Info->ServerUrl = Configuration.ServerUrl.c_str();
    }

    bool GetConfigInfo(ConfigInfo *Info)
    {
        if (Configuration.HasLoadedConfigFile) {
            InitConfigInfoStruct(Info);
            return true;
        }

        json Contents;
        try
        {
            std::ifstream ConfigFileStream(Configuration.ConfigFilePath);
            ConfigFileStream >> Contents;
        }
        catch (...)
        {
            // TODO(as): We don't have a config file or it's invalid, what now?
            // * Print an error and ask the user to supply a proper config file.
            // * Let the user input the required config details, and create the config file from the input.
            return false;
        }

        if (Contents.find("ServerUrl") != Contents.end()) {
            Configuration.ServerUrl = Contents["ServerUrl"].get<string>();
        }

        if (Contents.find("ServerKey") == Contents.end()) {
            return false;
        }

        Configuration.ServerKey = Contents["ServerKey"].get<string>();
        Configuration.HasLoadedConfigFile = true;
        InitConfigInfoStruct(Info);
        return true;
    }

    const char* GetConfigFilePath()
    {
        return Configuration.ConfigFilePath.c_str();
    }

    const char* GetStateFilePath()
    {
        return Configuration.StateFilePath.c_str();
    }

    bool WriteStateFile()
    {
        json BookmarksArray = json::array();
        for (auto Bookmark : Configuration.Bookmarks) {
            BookmarksArray.push_back(Bookmark);
        }
        json Contents = { {"devices", BookmarksArray} };

        const char* TemporaryFileName = "tcp_state_file_temporary.json";
        bool Status = false;
        std::remove(TemporaryFileName);
        try {
            std::ofstream StateFile(TemporaryFileName);
            StateFile << Contents.dump(2);
        }
        catch (...) {
            // TODO(as): error-checking.
        }

        try {
            std::remove(Configuration.StateFilePath.c_str());
            std::rename(TemporaryFileName, Configuration.StateFilePath.c_str());
            Status = true;
        }
        catch (...) {
            // TODO(as): error-checking.
        }

        try {
            std::remove(TemporaryFileName);
        }
        catch (...) {
            // TODO(as): error-checking.
        }

        return Status;
    }

    DeviceInfo *GetPairedDevice(int Index)
    {
        if (Index >= 0 && Configuration.Bookmarks.size() > Index)
        {
            return &Configuration.Bookmarks[Index];
        }
        else
        {
            return nullptr;
        }
    }

    void AddPairedDeviceToBookmarks(DeviceInfo Info)
    {
        for (size_t Index = 0; Index < Configuration.Bookmarks.size(); ++Index)
        {
            if (Configuration.Bookmarks[Index].DeviceID == Info.DeviceID)
            {
                Configuration.Bookmarks[Index] = Info;
                return;
            }
        }
        Configuration.Bookmarks.push_back(Info);
    }

    void PrintBookmarks()
    {
        if (Configuration.Bookmarks.empty())
        {
            std::cout << "No bookmarked devices were found. Maybe you should pair with a few devices?" << std::endl;
            return;
        }

        int Index = 0;
        std::cout << "The following devices are saved in your bookmarks:" << std::endl;
        for (auto Bookmark : Configuration.Bookmarks)
        {
            std::cout << "[" << Index << "] ProductId: " << Bookmark.ProductID << " DeviceId: " << Bookmark.DeviceID << std::endl;
            Index++;
        }
    }
}
