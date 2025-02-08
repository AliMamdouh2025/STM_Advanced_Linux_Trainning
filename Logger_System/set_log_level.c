/* set_log_level.c
 *
 * This program reads a desired log level from the command line (e.g., "error", "info")
 * and sends a real-time signal (SIGRTMIN) with the corresponding integer payload to the logger
 * application. It assumes that the logger's PID is stored in the file "logger.pid".
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

// Define the log levels (same values as in the logger application).
typedef enum {
    LOG_LEVEL_DISABLE = 0,
    LOG_LEVEL_ERROR   = 1,
    LOG_LEVEL_WARNING = 2,
    LOG_LEVEL_INFO    = 3,
    LOG_LEVEL_DEBUG   = 4
} LogLevel;

// Convert a string to the corresponding log level.
LogLevel parse_log_level(const char *level_str) {
    if (strcmp(level_str, "disable") == 0)
        return LOG_LEVEL_DISABLE;
    else if (strcmp(level_str, "error") == 0)
        return LOG_LEVEL_ERROR;
    else if (strcmp(level_str, "warning") == 0)
        return LOG_LEVEL_WARNING;
    else if (strcmp(level_str, "info") == 0)
        return LOG_LEVEL_INFO;
    else if (strcmp(level_str, "debug") == 0)
        return LOG_LEVEL_DEBUG;
    else {
        fprintf(stderr, "Invalid log level: %s\n", level_str);
        exit(EXIT_FAILURE);
    }
}

// Read the PID from a file.
pid_t get_logger_pid(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (f == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }
    pid_t pid;
    if (fscanf(f, "%d", &pid) != 1) {
        fprintf(stderr, "Failed to read PID from file %s\n", filename);
        fclose(f);
        exit(EXIT_FAILURE);
    }
    fclose(f);
    return pid;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <log_level>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Convert the input argument to a log level.
    LogLevel new_level = parse_log_level(argv[1]);

    // Retrieve the PID of the logger application from "logger.pid".
    pid_t target_pid = get_logger_pid("logger.pid");

    // Prepare the signal payload.
    union sigval sv;
    sv.sival_int = new_level;

    // Send the real-time signal (SIGRTMIN) to the logger process.
    if (sigqueue(target_pid, SIGRTMIN, sv) == -1) {
        perror("sigqueue");
        exit(EXIT_FAILURE);
    }
    printf("Sent signal to process %d to set log level to %d\n", target_pid, new_level);
    return 0;
}
