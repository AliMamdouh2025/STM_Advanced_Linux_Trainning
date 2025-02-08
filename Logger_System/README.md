
# Dynamic Logger Module with Real-Time Signal Control

This project implements a dynamically configurable logger module in C that supports four logging levels (error, warning, info, and debug) and allows the logging level to be adjusted at runtime via real-time signals. A separate control application sends a signal to update the logging level, making it possible to change verbosity without restarting the application.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [File Structure](#file-structure)
- [Requirements](#requirements)
- [Installation and Compilation](#installation-and-compilation)
- [Usage](#usage)
- [Design Details](#design-details)
- [Error Handling](#error-handling)
- [Video Link](#Video-Link)

## Overview

The project consists of two main programs:

1. **Logger Application (`logger_main.c`):**  
   Implements the logging module with four logging functions:
   - `LOG_ERROR`
   - `LOG_WARNING`
   - `LOG_INFO`
   - `LOG_DEBUG`  
   It periodically outputs log messages and writes its process ID (PID) to a file (`logger.pid`). It also registers a signal handler that listens for a real-time signal (`SIGRTMIN`) to update the current logging level at runtime.

2. **Control Application (`set_log_level.c`):**  
   Reads a command-line argument to set a desired logging level (e.g., `disable`, `error`, `warning`, `info`, `debug`). It retrieves the logger’s PID from `logger.pid` and sends a real-time signal with the appropriate log level value as its payload.

## Features

- **Dynamic Logging:**  
  Change logging verbosity on the fly using external signals.
  
- **Multiple Log Levels:**  
  Support for error, warning, info, and debug messages.

- **Real-Time Signal Integration:**  
  Uses `SIGRTMIN` to safely and dynamically adjust logging levels.

- **Robust Error Handling:**  
  Checks the return values of system calls and library functions to ensure reliability.

- **PID File:**  
  The logger application writes its PID to a file (`logger.pid`), enabling inter-process communication.

## File Structure

```
.
├── logger_main.c        # Logger application with dynamic logging and signal handling
├── set_log_level.c      # Control application for changing log level via signals
└── README.md            # Project documentation (this file)
```


## Installation and Compilation


1. **Compile the Logger Application:**

   ```bash
   gcc -o logger_main logger_main.c
   ```

2. **Compile the Control Application:**

   ```bash
   gcc -o set_log_level set_log_level.c
   ```

## Usage

### Running the Logger Application

Start the logger application in one terminal. It will write its PID to `logger.pid` and begin logging messages every 5 seconds:

```bash
./logger_main
```

### Adjusting the Log Level

Open another terminal and use the control application to change the logging level. For example, to only log error messages:

```bash
./set_log_level error
```

To disable all logging:

```bash
./set_log_level disable
```

The logger application will receive the signal, update its internal logging level, and adjust the output accordingly.

## Design Details

- **Signal Handling:**  
  The logger registers a signal handler for `SIGRTMIN`. The signal handler uses the `siginfo_t` structure to obtain the new log level value sent by the control application.

- **Atomic Operations:**  
  The global variable `current_log_level` is declared as `volatile sig_atomic_t` to ensure safe updates in the presence of asynchronous signal delivery.

- **Variadic Logging Functions:**  
  The logger uses standard variadic functions (`va_list`, `va_start`, and `va_end`) along with `vfprintf` to handle dynamic log messages.

- **Timestamping:**  
  Each log entry is prefixed with a timestamp generated using `ctime_r` for thread-safe conversion.

## Error Handling

- All system calls and library functions (e.g., `sigemptyset()`, `sigaction()`, `fopen()`, `ctime_r()`, etc.) are checked for errors.  
- In case of failure, appropriate error messages are printed using `perror()` and the program exits or handles the error gracefully.


## Video Link
https://drive.google.com/file/d/1c5hD18sjhX1NNrMg1wGgl8S1kOqi4XKX/view?usp=sharing
