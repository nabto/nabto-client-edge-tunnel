#pragma once
#include <string>

namespace Platform
{
    struct FileContents
    {
        size_t Size;
        char *Buffer;
    };

    bool WriteStringToFile(const std::string& String, const std::string& Filename);
    void FreeFileMemory(FileContents *File);
    FileContents ReadEntireFileZeroTerminated(const std::string& Filename);
}
