/**
 *===================================================================================
 * @file           : http_server.c
 * @author         : Ali Mamdouh
 * @brief          : source file to implement HTTP server
 * @Reviewer       : Eng Reda
 * @Version        : 1.0.0
 *===================================================================================
 * 
 *===================================================================================
 */




/*============================================================================
 ******************************  Includes  ***********************************
 ============================================================================*/ 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <errno.h>


/*============================================================================
 ***************************** Configrations *********************************
 ============================================================================*/
#define PORT 8080
#define BUFFER_SIZE 4096






/*============================================================================
 ***********************  Functions Decleration ******************************
 ============================================================================*/
void handle_client(int client_socket);
void send_response(int client_socket, const char *status, const char *content_type, const char *body);
void send_directory_listing(int client_socket, const char *path);
void send_file_contents(int client_socket, const char *path);
void execute_cgi_script(int client_socket, const char *path);
void send_error_response(int client_socket, const char *status, const char *message);





/*============================================================================
 ***********************  Functions Definitions ******************************
 ============================================================================*/
// Signal handler to reap child processes to prevent zombies
void sigchld_handler(int sig) 
{
    // Reap all dead child processes
    while (waitpid(-1, NULL, WNOHANG) > 0) 
    {
        // This will collect all terminated child processes, WNOHANG option is a must to make waitpid unblockable
    }
}



int main() 
{
    // Set up SIGCHLD handler to automatically reap children(To eleminate zombies)
    signal(SIGCHLD, sigchld_handler);

    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) 
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) 
    {
        perror("Bind failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 10) < 0) 
    {
        perror("Listen failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("HTTP Server is listening on port %d...\n", PORT);

    while (1) 
    {
        int client_socket = accept(server_socket, NULL, NULL);
        if (client_socket < 0) 
        {
            perror("Accept failed");
            continue;
        }

        if (fork() == 0) 
        { // Child process
            close(server_socket); // Child doesn't need the listening socket
            handle_client(client_socket);
            close(client_socket);
            exit(0);
        }

        // Parent process
        close(client_socket); // Parent doesn't need the client socket
    }

    close(server_socket);
    return 0;
}











void handle_client(int client_socket) 
{
    // Read HTTP request
    char buffer[BUFFER_SIZE] = {0};
    read(client_socket, buffer, sizeof(buffer) - 1);

    // Parse the request line
    char method[16], path[256], version[16];
    sscanf(buffer, "%s %s %s", method, path, version);

    // Remove the leading '/' from the path
    if (path[0] == '/') 
    {
        memmove(path, path + 1, strlen(path));
    }
    if (strlen(path) == 0) 
    {
        strcpy(path, "."); // Default to current directory
    }

    struct stat path_stat;
    if (stat(path, &path_stat) == 0) 
    {
        if (S_ISDIR(path_stat.st_mode)) 
        {
            send_directory_listing(client_socket, path);
        } else if (S_ISREG(path_stat.st_mode)) 
        {
            if (strstr(path, ".cgi")) 
            {
                execute_cgi_script(client_socket, path);
            } else 
            {
                send_file_contents(client_socket, path);
            }
        } else 
        {
            send_error_response(client_socket, "403 Forbidden", "Resource is not accessible.");
        }
    } else 
    {
        send_error_response(client_socket, "404 Not Found", "The requested resource does not exist.");
    }
}





void send_response(int client_socket, const char *status, const char *content_type, const char *body) 
{
    char header[BUFFER_SIZE];
    snprintf(header, sizeof(header),
             "HTTP/1.1 %s\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %ld\r\n"
             "\r\n",
             status, content_type, strlen(body));
    send(client_socket, header, strlen(header), 0);
    send(client_socket, body, strlen(body), 0);
}





void send_directory_listing(int client_socket, const char *path) 
{
    DIR *dir = opendir(path);
    if (!dir) 
    {
        send_error_response(client_socket, "500 Internal Server Error", "Failed to open directory.");
        return;
    }

    char body[BUFFER_SIZE] = "<html><body><h1>Directory Listing</h1><ul>";
    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) 
    {
        char line[256];
        snprintf(line, sizeof(line), "<li><a href=\"%s\">%s</a></li>", entry->d_name, entry->d_name);
        strncat(body, line, sizeof(body) - strlen(body) - 1);
    }

    strncat(body, "</ul></body></html>", sizeof(body) - strlen(body) - 1);
    closedir(dir);

    send_response(client_socket, "200 OK", "text/html", body);
}





void send_file_contents(int client_socket, const char *path) 
{
    FILE *file = fopen(path, "r");
    if (!file) 
    {
        send_error_response(client_socket, "500 Internal Server Error", "Failed to open file.");
        return;
    }

    char body[BUFFER_SIZE];
    size_t bytes_read = fread(body, 1, sizeof(body) - 1, file);
    fclose(file);

    body[bytes_read] = '\0';
    send_response(client_socket, "200 OK", "text/plain", body);
}





void execute_cgi_script(int client_socket, const char *path) 
{
    int pipefd[2];
    pid_t pid;

    // Create a pipe for communication between parent and child processes
    if (pipe(pipefd) == -1) 
    {
        send_error_response(client_socket, "500 Internal Server Error", "Failed to create pipe.");
        return;
    }

    // Fork a child process to execute the CGI script
    pid = fork();
    if (pid == -1) 
    {
        close(pipefd[0]);
        close(pipefd[1]);
        send_error_response(client_socket, "500 Internal Server Error", "Fork failed.");
        return;
    }

    if (pid == 0) 
    {  // Child process
        // Close read end of the pipe
        close(pipefd[0]);

        // Redirect stdout to pipe's write end
        if (dup2(pipefd[1], STDOUT_FILENO) == -1) 
        {
            perror("dup2 failed");
            exit(EXIT_FAILURE);
        }

        // Close the write end of the pipe
        close(pipefd[1]);

        // Prepare arguments for execv
        char *argv[2];
        argv[0] = (char *)path;  // Path to the CGI script
        argv[1] = NULL;  // Null-terminate the argument list

        // Execute the CGI script
        execv(path, argv);

        // If execv fails
        perror("execv failed");
        exit(EXIT_FAILURE);
    } 
    else 
    {  // Parent process
        // Close write end of the pipe
        close(pipefd[1]);

        // Read output from the pipe
        char body[BUFFER_SIZE];
        ssize_t bytes_read = read(pipefd[0], body, sizeof(body) - 1);
        close(pipefd[0]);

        // Wait for child process to finish
        int status;
        waitpid(pid, &status, 0);

        // Check if child process exited successfully
        if (bytes_read > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0) 
        {
            body[bytes_read] = '\0';
            send_response(client_socket, "200 OK", "text/plain", body);
        } 
        else 
        {
            send_error_response(client_socket, "500 Internal Server Error", "CGI script execution failed.");
        }
    }
}




void send_error_response(int client_socket, const char *status, const char *message) 
{
    char body[BUFFER_SIZE];
    snprintf(body, sizeof(body), "<html><body><h1>%s</h1><p>%s</p></body></html>", status, message);
    send_response(client_socket, status, "text/html", body);
}
