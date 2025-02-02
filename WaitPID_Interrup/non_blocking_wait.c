#include <stdlib.h>     
#include <unistd.h>    
#include <signal.h>  
#include <stdio.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>

/**
 * @brief Default signal handler for SIGCHLD signal.
 *        This handler processes child termination events.
 * @param signo Signal number (unused but required for signal handler signature)
 */
void default_handle_sigchld(int signo) 
{
    int wstatus;
    pid_t pid;
    
    // Non-blocking wait for all terminated child processes
    while ((pid = waitpid(-1, &wstatus, WNOHANG)) > 0) 
    {
        if (WIFEXITED(wstatus)) 
        {
            printf("Child PID %d terminated normally with exit status %d\n",
                   pid, WEXITSTATUS(wstatus));
        } 
        else if (WIFSIGNALED(wstatus)) 
        {
            printf("Child PID %d terminated by signal %d (%s)\n",
                   pid, WTERMSIG(wstatus), strsignal(WTERMSIG(wstatus)));
        }
        else if (WIFSTOPPED(wstatus)) 
        {
            printf("Child PID %d stopped by signal %d (%s)\n",
                   pid, WSTOPSIG(wstatus), strsignal(WSTOPSIG(wstatus)));
        }
        else if (WIFCONTINUED(wstatus)) 
        {
            printf("Child PID %d continued\n", pid);
        }
    }
    
    if (pid == -1 && errno != ECHILD) 
    {
        perror("waitpid failed");
    }
}

/**
 * @brief Activates signal handling for interrupted child processes.
 *
 * @param handler A pointer to a custom signal handler function for SIGCHLD.
 *                If NULL, the default handler handle_sigchld is used.
 * @return 0 on success, -1 on failure (with error printed).
 */
int Activate_Asynch_Wait(void (*handler)(int)) 
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));  // Initialize structure to zero
    
    // Select the handler
    sa.sa_handler = (handler != NULL) ? handler : default_handle_sigchld;
    
    // Block all signals during handler execution
    sigfillset(&sa.sa_mask);
    
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    
    if (sigaction(SIGCHLD, &sa, NULL) == -1) 
    {
        perror("sigaction failed");
        return -1;
    }
    return 0;
}

/**
 * @brief Creates a child process that demonstrates different termination scenarios
 * @param scenario 1: normal exit, 2: signal termination, 3: loop forever
 * @return pid of created child, -1 on error
 */
pid_t create_test_child(int scenario) 
{
    pid_t pid = fork();
    
    if (pid == -1) 
    {
        perror("fork failed");
        return -1;
    }
    
    if (pid == 0) 
    {  // Child process


        switch (scenario) {
            case 1:  // Normal exit
                sleep(2);
                exit(48);
            case 2:  // Will be terminated by signal
                sleep(3);
                while(1) {
                    // Will be killed by parent
                    sleep(1);
                }
            case 3:  // Loop forever (potential zombie if not handled)
                sleep(4);
                while(1) 
                {
                    sleep(1);
                }
            default:
                exit(1);
        }
    }
    
    return pid;
}





int main() 
{
    printf("Parent PID: %d\n", getpid());
    
    // Activate the signal handler
    if (Activate_Asynch_Wait(NULL) == -1) 
    {
        fprintf(stderr, "Failed to set up signal handler\n");
        return 1;
    }
    
    // Create multiple children with different scenarios
    pid_t child1 = create_test_child(1);  // Will exit normally
    pid_t child2 = create_test_child(2);  // Will be terminated by signal
    pid_t child3 = create_test_child(3);  // Will run forever unless terminated
    
    printf("Created children: %d, %d, %d\n", child1, child2, child3);
    
    // Give some time for child1 to exit normally
    sleep(3);
    
    // Send termination signal to child2
    printf("Sending SIGTERM to child2 (PID: %d)\n", child2);
    kill(child2, SIGTERM);
    
    // Send termination signal to child3
    sleep(2);
    printf("Sending SIGKILL to child3 (PID: %d)\n", child3);
    kill(child3, SIGKILL);
    
    // Wait a bit to ensure all signals are processed
    sleep(1);
    
    printf("Parent exiting\n");
    return 0;
}