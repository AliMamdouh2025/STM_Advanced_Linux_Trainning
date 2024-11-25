
# HTTP Server in C

## Overview
This project implements a basic HTTP server in C that supports the following functionalities:
- Accepts connections from web browsers or HTTP clients.
- Reads and parses HTTP requests.
- Processes requests based on the requested resource:
  1. **Directory**: Lists its contents in an HTML format.
  2. **Regular File**: Sends the file's contents as plain text.
  3. **CGI Script**: Executes the script and returns its output.
  4. **Non-existent Resource**: Returns a proper HTTP error message.
- Constructs and sends appropriate HTTP responses.
- Supports **concurrent access** using process forking.


## Features
### Core Functionalities
1. **Request Handling**
   - Handles `GET` requests and parses the HTTP request line.
   - Serves directory listings, file contents, and CGI script execution.

2. **Error Responses**
   - Returns proper HTTP status codes (e.g., `404 Not Found`, `500 Internal Server Error`).

3. **Concurrent Access**
   - Utilizes `fork()` to allow multiple clients to connect simultaneously.

4. **Platform Independence**
   - Runs on POSIX-compliant systems, making it suitable for Unix-like environments.


## Configuration
### Port
- The server listens on **port 8080** by default. Modify the `PORT` macro in the code if a different port is required.

### Buffer Size
- The maximum buffer size for request/response is defined as `BUFFER_SIZE` (default: 4096 bytes).



## Usage
### Build
Compile the program using `gcc`:
```bash
gcc -o http_server http_server.c
```

### Run
Execute the server binary:
```bash
./http_server
```

The server will listen on port 8080 and handle incoming HTTP requests.


## How It Works
### Request Handling
1. The server reads the client's HTTP request and parses the method, path, and version.
2. Based on the path:
   - **Directory**: Lists its contents as an HTML page.
   - **File**: Sends the file's contents.
   - **CGI Script**: Executes the script and sends its output.
   - **Non-existent Resource**: Sends a `404 Not Found` error.

3. Responses are constructed with appropriate HTTP headers and sent to the client.

### Concurrent Access
- The server creates a child process for each incoming connection using `fork()`.
- The parent process continues listening for new connections, while the child handles the client's request.

### Signal Handling
- Implements a `SIGCHLD` handler to clean up terminated child processes, preventing zombie processes.

---

## Example Usage
1. Accessing a directory:
   - URL: `http://<server_ip>:8080/`
   - Response: HTML page with directory listing.

2. Accessing a file:
   - URL: `http://<server_ip>:8080/file.txt`
   - Response: Plain text content of `file.txt`.

3. Executing a CGI script:
   - URL: `http://<server_ip>:8080/script.cgi`
   - Response: Output of the `script.cgi`.

4. Non-existent resource:
   - URL: `http://<server_ip>:8080/missing.txt`
   - Response: `404 Not Found` error.

---

## Code Structure
- **`main` function**: Initializes the server, accepts connections, and forks processes.
- **`handle_client` function**: Reads and processes HTTP requests.
- **Helper functions**:
  - `send_response`: Constructs and sends HTTP responses.
  - `send_directory_listing`: Generates HTML for directory contents.
  - `send_file_contents`: Reads and sends file content.
  - `execute_cgi_script`: Runs a CGI script and returns its output.
  - `send_error_response`: Sends appropriate error responses.

---

