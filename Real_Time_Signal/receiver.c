#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

// Signal handler
void realtime_signal_handler(int signum, siginfo_t *info, void *context) 
{
    printf("Received real-time signal %d\n", signum);

    // Access the payload
    int data = info->si_value.sival_int;

    if (data == 0) 
    {
        printf("Action: Terminate gracefully.\n");
        exit(0); // Graceful termination
    } else if (data == 1) 
    {
        printf("Action: Abort with core dump.\n");
        abort(); // Core dump
    } else 
    {
        printf("Invalid signal data: %d\n", data);
    }
}

int main() 
{
    struct sigaction sa;

    // Set up the signal handler
    sa.sa_sigaction = realtime_signal_handler;
    sa.sa_flags = SA_SIGINFO; // Use extended handler
    sigemptyset(&sa.sa_mask);

    // Register the signal handler for SIGRTMIN
    if (sigaction(SIGRTMIN, &sa, NULL) == -1) 
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    printf("Receiver PID: %d\n", getpid());
    printf("Waiting for real-time signals...\n");

    // Wait indefinitely
    while (1) 
    {
        pause();
    }

    return 0;
}
