/* logger_main.c
 *
 * This program implements a logger module with four logging functions.
 * It registers a handler for a real-time signal (SIGRTMIN) that adjusts
 * the logging level at runtime. The program writes its PID to "logger.pid"
 * so that the control program can locate and signal it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>

// Define the log levels.
typedef enum {
    LOG_LEVEL_DISABLE = 0,
    LOG_LEVEL_ERROR   = 1,
    LOG_LEVEL_WARNING = 2,
    LOG_LEVEL_INFO    = 3,
    LOG_LEVEL_DEBUG   = 4
} LogLevel;

// Global log level variable. Declared volatile because it is modified in a signal handler.
volatile sig_atomic_t current_log_level = LOG_LEVEL_DEBUG;  // Default to most verbose

// The logger function. It prints the message if the current log level allows it.
void log_message(LogLevel level, const char *fmt, ...) {
    // Do not print if logging is disabled or the message's level is above the current threshold.
    if (current_log_level < level || current_log_level == LOG_LEVEL_DISABLE)
        return;

    va_list args;
    va_start(args, fmt);

    // Create a timestamp string.
    time_t now = time(NULL);
    char timebuf[26];
    if (ctime_r(&now, timebuf) == NULL) {
        perror("ctime_r");
        va_end(args);
        return;
    }
    timebuf[strcspn(timebuf, "\n")] = '\0';  // Remove newline

    // Print the timestamp and the log message.
    fprintf(stdout, "[%s] ", timebuf);
    vfprintf(stdout, fmt, args);
    fflush(stdout);
    va_end(args);
}

// Convenience macros for logging at each level.
#define LOG_ERROR(fmt, ...)   log_message(LOG_LEVEL_ERROR, "ERROR: " fmt "\n", ##__VA_ARGS__)
#define LOG_WARNING(fmt, ...) log_message(LOG_LEVEL_WARNING, "WARNING: " fmt "\n", ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)    log_message(LOG_LEVEL_INFO, "INFO: " fmt "\n", ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...)   log_message(LOG_LEVEL_DEBUG, "DEBUG: " fmt "\n", ##__VA_ARGS__)

// Signal handler for the real-time signal used to update log level.
void log_level_handler(int signo, siginfo_t *info, void *context) {

    if (info != NULL) {
        int new_level = info->si_value.sival_int;
        current_log_level = new_level;
        /* Use write() since it is async-signal-safe.
         * (Note: write() outputs raw bytes; here we use it only for a simple message.)
         */
        const char *msg = "Log level updated via signal.\n";
        if (write(STDOUT_FILENO, msg, strlen(msg)) == -1) {
            /* In a signal handler, we cannot do much if write fails. */
        }
    }
}

// Helper function to write the process PID to a file.
int write_pid_to_file(const char *filename) 
{
    FILE *f = fopen(filename, "w");
    if (f == NULL) {
        perror("fopen");
        return -1;
    }
    if (fprintf(f, "%d\n", getpid()) < 0) {
        perror("fprintf");
        fclose(f);
        return -1;
    }
    if (fclose(f) != 0) {
        perror("fclose");
        return -1;
    }
    return 0;
}

int main(void) 
{
    // Write the current PID to a file so the control application can find us.
    if (write_pid_to_file("logger.pid") != 0) 
    {
        fprintf(stderr, "Failed to write PID file.\n");
        exit(EXIT_FAILURE);
    }

    // Set up the signal handler for SIGRTMIN.
    struct sigaction sa;
    sa.sa_sigaction = log_level_handler;
    sa.sa_flags = SA_SIGINFO  | SA_RESTART;  // We want to receive extra signal information.
    if (sigemptyset(&sa.sa_mask) == -1) 
    {
        perror("sigemptyset");
        exit(EXIT_FAILURE);
    }
    if (sigaction(SIGRTMIN, &sa, NULL) == -1) 
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    // Main loop: log messages periodically.
    int counter = 0;
    while (1) 
    {
        LOG_ERROR("This is an error message, counter = %d", counter);
        LOG_WARNING("This is a warning message, counter = %d", counter);
        LOG_INFO("This is an info message, counter = %d", counter);
        LOG_DEBUG("This is a debug message, counter = %d", counter);
        counter++;
        sleep(5);  // Wait for 5 seconds between log outputs.
    }

    return 0;
}
