#include "config.hpp"

#include <nabto_client.hpp>

#include <3rdparty/nlohmann/json.hpp>
#include <vector>
#include <fstream>
#include <cstdio>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <memory>

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
    static const char *KeyFileName = "keys/client.key";

    static struct
    {
        string ConfigFilePath;
        string StateFilePath;
        string KeyFilePath;
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
            {"ProductId", d.ProductID},
            {"ServerConnectToken", d.ServerConnectToken}
        });
        if (!d.DirectCandidate.empty()) {
            j["DirectCandidate"] = d.DirectCandidate;
        }
    }

    void from_json(const json& j, DeviceInfo& d)
    {
        j.at("DeviceFingerprint").get_to(d.DeviceFingerprint);
        j.at("DeviceId").get_to(d.DeviceID);
        j.at("ProductId").get_to(d.ProductID);
        j.at("ServerConnectToken").get_to(d.ServerConnectToken);
        try {
            j.at("DirectCandidate").get_to(d.DirectCandidate);
        } catch (const std::exception& e) {
            // no direct candidate, fine
        }
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

    bool ReadEntireFileZeroTerminated(const string& Filename, string& Out)
    {
        bool Success = false;
        std::ifstream InputStream(Filename);
        if (InputStream) {

            InputStream.seekg(0, std::ios::end);
            size_t size = InputStream.tellg();
            InputStream.seekg(0, std::ios::beg);
            std::vector<char> Buffer(size);

            InputStream.read(Buffer.data(), Buffer.size());
            if (!InputStream && !InputStream.eof()) {
                Success = false;
                std::cout << "Could not read input stream for file " << Filename << std::endl;
            } else {
                Success = true;
            }

            InputStream.close();

            if (Success) {
                Out = string(Buffer.data(), Buffer.size());
            }
        } else {
            std::cout << "Could not open input stream for file " << Filename << std::endl;
        }

        return Success;
    }

    bool FileExists(const string& Filename)
    {
        std::ifstream f(Filename.c_str());
        return f.good();
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
        Configuration.KeyFilePath.assign(NormalizedHomePath);

        char LastCharacter = NormalizedHomePath.back();
        if (LastCharacter != '/')
        {
            Configuration.ConfigFilePath.append("/");
            Configuration.StateFilePath.append("/");
            Configuration.KeyFilePath.append("/");
        }

        Configuration.ConfigFilePath.append(ClientFileName);
        Configuration.StateFilePath.append(StateFileName);
        Configuration.KeyFilePath.append(KeyFileName);

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

        Configuration.KeyFilePath.assign(HomePath);
        Configuration.KeyFilePath.append(NabtoFolder);
        Configuration.KeyFilePath.append(KeyFileName);

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

        std::string config;
        if (!ReadEntireFileZeroTerminated(Configuration.ConfigFilePath, config)) {
            return false;
        }

        json Contents = json::parse(config);

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

    bool CreatePrivateKeyFile(std::shared_ptr<nabto::client::Context> Context)
    {
        std::string PrivateKey = Context->createPrivateKey();
        return WriteStringToFile(PrivateKey, Configuration.KeyFilePath);
    }

    bool GetPrivateKey(std::shared_ptr<nabto::client::Context> Context, string& Out)
    {
        if (!FileExists(Configuration.KeyFilePath)) {
            if (!CreatePrivateKeyFile(Context)) {
                std::cerr << "The private key file " << Configuration.KeyFilePath << " does not exists and could not be generated. " << std::endl;
                return false;
            }
        }
        return ReadEntireFileZeroTerminated(Configuration.KeyFilePath, Out);
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
