#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void send_signal(pid_t target_pid, int action) 
{
    union sigval value;
    value.sival_int = action; // Payload: 0 for terminate, 1 for abort

    if (sigqueue(target_pid, SIGRTMIN, value) == -1) 
    {
        perror("sigqueue");
        exit(EXIT_FAILURE);
    }

    printf("Sent SIGRTMIN to PID %d with data %d\n", target_pid, action);
}

int main(int argc, char *argv[]) 
{
    if (argc != 3) 
    {
        fprintf(stderr, "Usage: %s <pid> <action>\n", argv[0]);
        fprintf(stderr, "Action: 0 = Terminate, 1 = Abort\n");
        exit(EXIT_FAILURE);
    }

    pid_t target_pid = atoi(argv[1]);
    int action = atoi(argv[2]);

    if (action != 0 && action != 1) 
    {
        fprintf(stderr, "Invalid action. Use 0 for terminate or 1 for abort.\n");
        exit(EXIT_FAILURE);
    }

    send_signal(target_pid, action);

    return 0;
}
