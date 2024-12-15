# Real-Time Signal Task: Simulate Terminate and Abort Signals

This project demonstrates how to use real-time signals to simulate **terminate** and **abort** signals in a Linux environment. The two applications in this project—**Sender** and **Receiver**—utilize the real-time signal mechanism to communicate with each other, triggering specific actions based on the sent data.

## Table of Contents
- [Overview](#overview)
- [Installation](#installation)
- [Usage](#usage)
- [Code Explanation](#code-explanation)
- [Core Dump Configuration](#core-dump-configuration)
- [License](#license)

## Overview
In this task, the following actions are simulated:
- **Terminate (Graceful Termination)**: If the sent signal carries a payload of `0`, the receiver application will terminate gracefully.
- **Abort (Core Dump)**: If the sent signal carries a payload of `1`, the receiver application will abort, generating a core dump.

### Components:
1. **Receiver**: The receiver application listens for real-time signals (`SIGRTMIN`) and takes actions based on the payload carried by the signal.
2. **Sender**: The sender application sends signals to the receiver with a payload indicating whether the receiver should terminate or abort.

## Installation
To build and run this project, follow these steps:


 **Compile the applications**:
    ```bash
    gcc receiver.c -o receiver
    gcc sender.c -o sender
    ```

### Core Dump Configuration
To ensure that a core dump is generated, the following settings need to be configured before anything:

1. **Enable core dumps**:
    ```bash
    ulimit -c unlimited
    ```

2. **Disable Apport (Ubuntu's core dump service)**:
    ```bash
    sudo service apport stop
    ```

## Usage

This configuration allows the system to generate core dumps in the current working directory when the receiver is aborted.



### 1. Start the **Receiver** application:
The receiver waits for signals and handles them based on the payload.

```bash
./receiver
```

This will output the receiver’s PID and wait for real-time signals.

### 2. Send a real-time signal using the **Sender** application:
The sender application will send a signal to the receiver with a payload. The payload can be either `0` (terminate) or `1` (abort).

To **terminate** the receiver:
```bash
./sender <receiver_pid> 0
```

To **abort** (cause a core dump) the receiver:
```bash
./sender <receiver_pid> 1
```

- `<receiver_pid>` is the PID of the receiver application, which you can get from the output of the receiver or by using the `ps` command.

## Code Explanation

### Receiver Code:
The receiver listens for real-time signals (starting from `SIGRTMIN`) and processes them based on the payload.


- **Signal Handler**: The handler `realtime_signal_handler()` processes the real-time signal and performs an action based on the payload (`0` for termination, `1` for abort).
- **Signal Registration**: The `sigaction()` function is used to set up the handler for the `SIGRTMIN` signal, which is the base for real-time signals.

### Sender Code:
The sender sends a signal to the receiver with a payload indicating whether to terminate or abort.



- **Sending Signal**: The `send_signal()` function sends a signal (`SIGRTMIN`) to the target process with the specified action (either `0` or `1`).


## Video Demonstration
A video demonstration is provided to show the design, code, and execution of the real-time signal task. It illustrates how the sender and receiver communicate using real-time signals and how they handle termination and abortion.
[Link](https://drive.google.com/file/d/1hIIe1Soj_LvrCfcx7d0hCyt5I1Fh6hmY/view?usp=sharing)

