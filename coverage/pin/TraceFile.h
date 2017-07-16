#ifndef TRACEFILE_H_
#define TRACEFILE_H_

#include <string>
#include <cstdio>
#include <cstdlib>
#include <iostream>

class TraceFile {
public:
    TraceFile(const std::string& filename)
    {
        m_file = fopen(filename.c_str(), "w+");
        if (!m_file) {
            std::cerr << "Could not open the log file." << std::endl;
            std::abort();
        }
    }

    ~TraceFile()
    {
        if (fclose(m_file) != 0) {
            std::cerr << "Could not close the log file." << std::endl;
            std::abort();
        }
    }

    void write_binary(const void* ptr, size_t size)
    {
        if (fwrite(ptr, size, 1, m_file) != 1) {
            std::cerr << "Could not log to the log file." << std::endl;
            std::abort();
        }
    }

    void write_string(const char* format, ...)
    {
        va_list args;
        va_start(args, format);
        if (vfprintf(m_file, format, args) < 0) {
            std::cerr << "Could not log to the log file." << std::endl;
            std::abort();
        }
        va_end(args);
    }

private:
    FILE* m_file;
};

#endif /* TRACEFILE_H_ */
