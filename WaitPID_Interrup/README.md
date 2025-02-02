**Child Process Signal Handling Demonstration**  
**A Robust Example of SIGCHLD Handling and Zombie Prevention**

---

### **Overview**
This program demonstrates proper handling of child process termination signals (`SIGCHLD`) in Linux/Unix systems. It showcases non-blocking process reaping, prevention of zombie processes, and detailed status reporting for various termination scenarios (normal exit, signal termination, stopped/continued states).

---

### **Key Features**
- **Non-Blocking Signal Handling**: Uses `waitpid()` with `WNOHANG` to efficiently reap child processes without blocking.
- **Comprehensive Status Reporting**: Detects and reports:
  - Normal exits with custom status codes
  - Terminations by signals (e.g., `SIGTERM`, `SIGKILL`)
  - Stopped/continued states (`SIGSTOP`/`SIGCONT`)
- **Zombie Prevention**: Guarantees no lingering processes through proper signal handling.
- **Error-Resilient Design**: Robust error checking for system calls and edge cases.
- **Modular Architecture**: Separates signal handling setup, child creation, and test logic.

---

### **Code Structure**
| Component                  | Purpose                                                                 |
|----------------------------|-------------------------------------------------------------------------|
| `handle_sigchld()`         | Default SIGCHLD handler that processes child status changes            |
| `Activate_Interrupted_Wait()` | Configures SIGCHLD handling with custom/nested signal safety           |
| `create_test_child()`      | Generates child processes with configurable termination scenarios      |
| `main()`                   | Orchestrates test workflow and demonstrates all functionality          |

---

### **Build & Run**
**1. Compile the Program**  
```bash
gcc -Wall -o process_demo non_blocking_wait.c
```

**2. Execute the Demo**  
```bash
./process_demo
```

**3. Verify No Zombies** (While Program Runs)  
```bash
ps -ef | grep defunct
```

---

### **Expected Output**
```
Parent PID: 12345
Created children: 12346, 12347, 12348
Child PID 12346 terminated normally with exit status 42
Sending SIGTERM to child2 (PID: 12347)
Child PID 12347 terminated by signal 15 (Terminated)
Sending SIGKILL to child3 (PID: 12348)
Child PID 12348 terminated by signal 9 (Killed)
Parent exiting
```

---

### **Test Scenarios**
1. **Normal Termination**  
   Child exits with status code 42 after 2 seconds.

2. **Graceful Signal Termination**  
   Child receives `SIGTERM` (signal 15) from parent after 3 seconds.

3. **Forced Termination**  
   Child receives `SIGKILL` (signal 9) after 4 seconds, demonstrating unhandled kills.

---

### **Technical Highlights**
- **Signal Safety**: Blocks all signals during handler execution using `sigfillset()`
- **Portable Design**: Uses POSIX-standard `strsignal()` for signal descriptions
- **Race Condition Prevention**: Implements `SA_RESTART` to protect interrupted syscalls
- **Resource Cleanup**: Guarantees child process reaping through `WNOHANG` looping

---

