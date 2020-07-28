#include "config.hpp"

#include <3rdparty/nlohmann/json.hpp>
#include <vector>
#include <fstream>
#include <cstdio>
#include <iostream>
#include <iomanip>
#include <algorithm>

using json = nlohmann::json;
using string = std::string;

namespace Configuration
{
#if defined(_WIN32)
    static const char *HomeDirEnvVariable = "APPDATA";
    static const char *NabtoFolder = "/nabto/edge/";
#else
    static const char *HomeDirEnvVariable = "HOME";
    static const char *NabtoFolder = "/.nabto/edge/";
#endif

    static const char *ClientFileName = "config/client.json";
    static const char *StateFileName = "config/tcp_tunnel_client_state.json";
    static const char *KeysFileName = "keys/client.key";

    static struct
    {
        string ConfigFilePath;
        string StateFilePath;
        std::vector<DeviceInfo> Bookmarks;

        bool HasLoadedConfigFile;
        string ServerUrl;
        string ServerKey;
    } Configuration;

    struct FileContents
    {
        size_t Size;
        char *Buffer;
    };

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

    bool WriteStringToFile(const string& String, const string& Filename)
    {
        bool Status = false;
        string TemporaryFileName = Filename + ".tmp";
        std::remove(TemporaryFileName.c_str());
        try {
            std::ofstream StateFile(TemporaryFileName);
            StateFile << String;
        }
        catch (...) {
            std::cout << "Could not open file stream to " << TemporaryFileName << std::endl;
        }

        try {
            std::remove(Filename.c_str());
            std::rename(TemporaryFileName.c_str(), Filename.c_str());
            std::remove(TemporaryFileName.c_str());
            Status = true;
        }
        catch (...) {
            std::cout << "Could not replace file " << Filename << " with " << TemporaryFileName << std::endl;
        }

        return Status;
    }

    void FreeFileMemory(FileContents *File)
    {
        if (File->Buffer) {
            delete[] File->Buffer;
            File->Buffer = nullptr;
        }
    }

    FileContents ReadEntireFileZeroTerminated(const string& Filename)
    {
        FileContents Result = {};

        std::ifstream InputStream(Filename);
        if (InputStream) {
            bool Success = true;
            InputStream.seekg(0, std::ios::end);
            Result.Size = InputStream.tellg();
            InputStream.seekg(0, std::ios::beg);
            Result.Buffer = new (std::nothrow) char[Result.Size + 1]();

            if (Result.Buffer) {
                InputStream.read(Result.Buffer, Result.Size);
                if (!InputStream && !InputStream.eof()) {
                    Success = false;
                    std::cout << "Could not read input stream for file " << Filename << std::endl;
                }
            } else {
                std::cout << "Could not allocate memory for loading file " << Filename << std::endl;
                Success = false;
            }

            InputStream.close();

            if (!Success) {
                FreeFileMemory(&Result);
                Result.Size = 0;
                Result.Buffer = nullptr;
            }
        } else {
            std::cout << "Could not open input stream for file " << Filename << std::endl;
        }

        return Result;
    }

    void CommonInit()
    {
        Configuration.HasLoadedConfigFile = false;
        Configuration.ServerUrl = "";
        Configuration.ServerKey = "";

        json StateContents;
        try
        {
            std::ifstream StateFile(Configuration.StateFilePath);
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
            std::cerr << "IMPORTANT: Your state file (" << Configuration.StateFilePath << ") seems to be incorrect.\n" <<
            "As a result no paired devices were loaded from it." << std::endl;
            Configuration.Bookmarks.clear();
        }
    }

    string NormalizePath(const char *Path)
    {
        string Result;
        Result.assign(Path);
#if defined(_WIN32)
        std::replace(Result.begin(), Result.end(), '\\', '/');
#endif
        return Result;
    }

    void InitializeWithDirectory(const string &HomePath)
    {
        std::string NormalizedHomePath = NormalizePath(HomePath.c_str());

        Configuration.ConfigFilePath.assign(NormalizedHomePath);
        Configuration.StateFilePath.assign(NormalizedHomePath);
        char LastCharacter = NormalizedHomePath.back();
        if (LastCharacter != '/')
        {
            Configuration.ConfigFilePath.append("/");
            Configuration.StateFilePath.append("/");
        }

        Configuration.ConfigFilePath.append(ClientFileName);
        Configuration.StateFilePath.append(StateFileName);
        
        CommonInit();
    }

    void Initialize()
    {
        string HomePath = NormalizePath(getenv(HomeDirEnvVariable));

        Configuration.ConfigFilePath.assign(HomePath);
        Configuration.ConfigFilePath.append(NabtoFolder);
        Configuration.ConfigFilePath.append(ClientFileName);

        Configuration.StateFilePath.assign(HomePath);
        Configuration.StateFilePath.append(NabtoFolder);
        Configuration.StateFilePath.append(StateFileName);

        CommonInit();
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

        FileContents ConfigFile = ReadEntireFileZeroTerminated(Configuration.ConfigFilePath);

        if (!ConfigFile.Buffer) {
            return false;
        }

        json Contents = json::parse(ConfigFile.Buffer);
        FreeFileMemory(&ConfigFile);

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

        return WriteStringToFile(Contents.dump(2), Configuration.StateFilePath);
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
