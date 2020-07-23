#include "platform.hpp"
#include <string>
#include <iostream>
#include <fstream>

using std::string;

namespace Platform
{
    bool WriteStringToFile(string& String, string& Filename)
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
        if (File->Buffer)
        {
            delete[] File->Buffer;
            File->Buffer = nullptr;
        }
    }

    FileContents ReadEntireFileZeroTerminated(string& Filename)
    {
        FileContents Result = {};

        std::ifstream InputStream(Filename);
        if (InputStream)
        {
            InputStream.seekg(0, std::ios::end);
            Result.Size = InputStream.tellg();
            InputStream.seekg(0, std::ios::beg);
            Result.Buffer = new (std::nothrow) char[Result.Size + 1];
            if (Result.Buffer)
            {
                InputStream.read(Result.Buffer, Result.Size);
                if (!InputStream)
                {
                    FreeFileMemory(&Result);
                    // TODO(as): Logging.
                }

                Result.Buffer[Result.Size] = 0;
            }
            else
            {
                FreeFileMemory(&Result);
                // TODO(as): Logging.
            }
            InputStream.close();
        }

        return Result;
    }
}
