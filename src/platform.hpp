#pragma once
#include <string>

namespace Platform
{
    struct FileContents
    {
        size_t Size;
        char *Buffer;
    };

    bool WriteStringToFile(std::string& String, std::string& Filename);
    void FreeFileMemory(FileContents *File);
    FileContents ReadEntireFileZeroTerminated(std::string& Filename);
}
