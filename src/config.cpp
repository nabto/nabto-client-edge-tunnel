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
#include <list>

#if defined(_WIN32)
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

using json = nlohmann::json;
using string = std::string;

namespace Configuration
{

static struct
{
    string ConfigFilePath;
    string StateFilePath;
    string KeyFilePath;
    std::map<int, DeviceInfo> Bookmarks;

    bool HasLoadedConfigFile;
    string ServerUrl;
    string ServerKey;
} Configuration;

void to_json(json& j, const DeviceInfo& d)
{
    j = json({
            {"DeviceFingerprint", d.deviceFingerprint_},
            {"DeviceId", d.deviceId_},
            {"ProductId", d.productId_},
            {"Sct", d.sct_}
        });
    if (!d.directCandidate_.empty()) {
        j["DirectCandidate"] = d.directCandidate_;
    }
}

void from_json(const json& j, DeviceInfo& d)
{
    j.at("DeviceFingerprint").get_to(d.deviceFingerprint_);
    j.at("DeviceId").get_to(d.deviceId_);
    j.at("ProductId").get_to(d.productId_);
    j.at("Sct").get_to(d.sct_);
    try {
        j.at("DirectCandidate").get_to(d.directCandidate_);
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
            Configuration.Bookmarks[Configuration.Bookmarks.size()] = Info;
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

bool CreateClientConfigurationFile()
{
    nlohmann::json root;
    root["ServerKey"] = defaultServerKey;
    std::string clientConfig = root.dump(4);
    return WriteStringToFile(clientConfig, Configuration.ConfigFilePath);
}

std::unique_ptr<ClientConfiguration> GetConfigInfo()
{
    if (!FileExists(Configuration.ConfigFilePath)) {
        if (!CreateClientConfigurationFile()) {
            std::cerr << "The client configuration file " << Configuration.ConfigFilePath << " does not exists and could not be generated. " << std::endl;
            return nullptr;
        }
    }

    std::string config;
    if (!ReadEntireFileZeroTerminated(Configuration.ConfigFilePath, config)) {
        return nullptr;
    }

    json Contents = json::parse(config);

    std::string serverUrl;
    std::string serverKey;

    try {
        serverUrl = Contents["ServerUrl"].get<string>();
    } catch (std::exception& e) {
        // fine the server url is optional.
    }

    try {
        serverKey = Contents["ServerKey"].get<string>();
    } catch (std::exception& e) {
        // not fine, the serverkey is required.
        std::cerr << "The client configuration file " << Configuration.ConfigFilePath << " is missing the required ServerKey configuration parameter" << std::endl;
        return nullptr;
    }

    return std::make_unique<ClientConfiguration>(serverKey, serverUrl);
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
        BookmarksArray.push_back(Bookmark.second);
    }
    json Contents = { {"devices", BookmarksArray} };

    return WriteStringToFile(Contents.dump(2), Configuration.StateFilePath);
}

std::unique_ptr<DeviceInfo> GetPairedDevice(int index)
{
    if (index >= 0 && Configuration.Bookmarks.size() > index)
    {
        auto device = std::make_unique<DeviceInfo>(Configuration.Bookmarks[index]);
        device->index_ = index;
        return device;
    }
    else
    {
        return nullptr;
    }
}

std::unique_ptr<DeviceInfo> GetPairedDevice(const std::string& deviceFingerprint)
{
    for (auto& bookmark : Configuration.Bookmarks) {
        if (bookmark.second.getDeviceFingerprint() == deviceFingerprint ) {
            auto device = std::make_unique<DeviceInfo>(bookmark.second);
            device->index_ = bookmark.first;
            return device;
        }
    }
    return nullptr;
}

bool HasNoBookmarks()
{
    return Configuration.Bookmarks.empty();
}

void AddPairedDeviceToBookmarks(DeviceInfo& Info)
{
    for (auto b : Configuration.Bookmarks) {
        if (b.second.getDeviceId() == Info.getDeviceId() && b.second.getProductId() == Info.getProductId()) {
            Configuration.Bookmarks[b.first] = Info;
            Info.index_ = b.first;
            return;
        }
    }

    size_t index = Configuration.Bookmarks.size();
    Configuration.Bookmarks[index] = Info;
    Info.index_ = index;
    return;
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

    int index = 0;
    std::cout << "The following devices are saved in your bookmarks:" << std::endl;
    for (auto Bookmark : Configuration.Bookmarks)
    {
        std::cout << "[" << index << "] ProductId: " << Bookmark.second.getProductId() << " DeviceId: " << Bookmark.second.getDeviceId() << std::endl;
        index++;
    }
}


bool DeleteBookmark(const uint32_t& bookmark)
{
    if (Configuration.Bookmarks.find(bookmark) == Configuration.Bookmarks.end()) {
        std::cerr << "The bookmark " << bookmark << " does not exists" << std::endl;
        return false;
    }
    Configuration.Bookmarks.erase(bookmark);
    return WriteStateFile();
}

bool makeDirectory(const std::string& directory)
{
#if defined(_WIN32)
    _mkdir(directory.c_str());
#else
    mkdir(directory.c_str(), 0777);
#endif
    return true;
}

bool makeDirectories(const std::string& in)
{
    std::string homeDir;
    if (in.empty()) {
        char* tmp = getenv(homeDirEnvVariable.c_str());
        if (tmp == NULL) {
            return false;
        }
        std::string homeEnv = std::string(tmp);
        makeDirectory(homeEnv + "/" + nabtoFolder);
        makeDirectory(homeEnv + "/" + nabtoFolder + "/edge");
        homeDir = homeEnv + "/" + nabtoFolder + "/edge";
    } else {
        homeDir = in;
        makeDirectory(homeDir);
    }

    makeDirectory(homeDir+"/config");
    makeDirectory(homeDir+"/state");
    makeDirectory(homeDir+"/keys");
    return true;
}

std::string getDefaultHomeDir() {
    char* tmp = getenv(homeDirEnvVariable.c_str());
    if (tmp == NULL) {
        return ".";
    }
    std::string homeEnv = std::string(tmp);
    return homeEnv + "/" + nabtoFolder + "/edge";
}

}
