#include "platform.hpp"
#include <windows.h>
#include <string>
#include <iostream>

using std::string;

namespace Platform
{
    bool WriteStringToFile(const string& String, const string& Filename)
    {
        HANDLE File;
        DWORD BytesToWrite = String.length();
        DWORD BytesWritten = 0;
        string TemporaryFilename = Filename + ".tmp";

        File = CreateFile(
            TemporaryFilename.c_str(),
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (File == INVALID_HANDLE_VALUE)
        {
            std::cout << "Unable to create temporary file " << TemporaryFilename << " for writing to." << std::endl;
            return false;
        }

        BOOL WriteSuccess = WriteFile(
            File,
            String.c_str(),
            BytesToWrite,
            &BytesWritten,
            NULL
        );

        bool TemporaryFileCreated = true;
        if (WriteSuccess)
        {
            if (BytesWritten != BytesToWrite)
            {
                std::cout << "Not all data was written to " << TemporaryFilename << "correctly." << std::endl;
                std::cout << "(Bytes written: " << BytesWritten << ", bytes to write: " << BytesToWrite << std::endl;
                TemporaryFileCreated = false;
            }
        }
        else
        {
            std::cout << "Unable to write to " << TemporaryFilename << std::endl;
            TemporaryFileCreated = false;
        }

        CloseHandle(File);
        bool Success = false;
        if (TemporaryFileCreated)
        {
            BOOL ReplaceSuccess = MoveFileEx(
                TemporaryFilename.c_str(),
                Filename.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH
            );

            if (ReplaceSuccess)
            {
                Success = true;
            }
            else
            {
                std::cout << "Failed to replace file. (" << TemporaryFilename << " ==> " << Filename << ")" << std::endl;
            }

        }

        return Success;
    }

    void FreeFileMemory(FileContents *File)
    {
        if (File->Buffer)
        {
            VirtualFree(File->Buffer, 0, MEM_RELEASE);
            File->Buffer = NULL;
        }
    }

    FileContents ReadEntireFileZeroTerminated(const string& Filename)
    {
        FileContents Result = {};
        HANDLE File = CreateFile(Filename.c_str(),
                                 GENERIC_READ,
                                 FILE_SHARE_READ,
                                 NULL,
                                 OPEN_EXISTING,
                                 0,
                                 NULL);

        if (File != INVALID_HANDLE_VALUE)
        {
            LARGE_INTEGER FileSize;
            if (GetFileSizeEx(File, &FileSize))
            {
                Result.Size = FileSize.QuadPart + 1;
                Result.Buffer = (char*)VirtualAlloc(0, Result.Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

                if (Result.Buffer)
                {
                    DWORD BytesRead;
                    if (ReadFile(File, Result.Buffer, FileSize.QuadPart, &BytesRead, NULL))
                    {
                        Result.Buffer[Result.Size-1] = 0;
                    }
                    else
                    {
                        std::cout << "Could not read file " << Filename << std::endl;
                        FreeFileMemory(&Result);
                    }
                }
                else
                {
                    std::cout << "Could not allocate memory for file " << Filename << std::endl;
                }

            }
            else
            {
                std::cout << "Could not read the file size of " << Filename << std::endl;
            }
        }
        else
        {
            std::cout << "Could not open file " << Filename << std::endl;
        }

        return Result;
    }
}
