

---

# Clothing Shop Simulation

## Overview
This project is a multi-process C++ application simulating a clothing shop, designed to demonstrate efficient inter-process communication (IPC) using POSIX message queues. It consists of three distinct processes—Shop, Customer, and Inventory Manager—that work together to manage inventory, process customer orders, and handle restocking and price updates. The implementation prioritizes high performance, maintainability, and modularity, leveraging modern C++ features and robust error handling.

## System Design
![image](https://github.com/user-attachments/assets/1380c76e-bd00-4876-91af-3591e15df92d)

### Key Features
- **Shop Process**: Loads initial inventory from a file, manages stock, processes requests, and periodically prints inventory every 10 seconds.
- **Customer Process**: Interactively accepts user orders and communicates with the Shop process to confirm or reject them.
- **Inventory Manager Process**: Interactively handles restocking and price updates, coordinating with the Shop process.
- **IPC**: Uses POSIX message queues for efficient, reliable communication between processes.
- **Performance**: Employs `std::unordered_map` for O(1) inventory lookups and updates.
- **Maintainability**: Features modular code with clear separation of concerns and comprehensive error handling.

---

## Project Structure
- **`common.h`**: Shared definitions, including constants and the `Item` struct.
- **`shop.cpp`**: Source code for the Shop process.
- **`customer.cpp`**: Source code for the Customer process.
- **`inventory.cpp`**: Source code for the Inventory Manager process.
- **`inventory.txt`**: Sample initial inventory file.

---

## Prerequisites
- **Operating System**: Linux or any POSIX-compliant system (e.g., Ubuntu, CentOS).
- **Compiler**: GCC or any C++11-compatible compiler (e.g., `g++`).
- **Libraries**: POSIX real-time library (`-lrt`) for message queue support.

---

## Compilation Instructions
To compile the project, use the following commands in a terminal:

```bash
g++ -o shop shop.cpp -lrt
g++ -o customer customer.cpp -lrt
g++ -o inventory inventory.cpp -lrt
```

### Notes
- The `-lrt` flag links the real-time library required for POSIX message queues.
- Ensure all source files (`shop.cpp`, `customer.cpp`, `inventory.cpp`) and `common.h` are in the same directory.

---

## Running the Application
1. **Prepare the Inventory File**:
   - Create an `inventory.txt` file with initial inventory data in the format: `item_name count price`.
   - Example:
     ```
     shirt 10 19.99
     pants 15 29.99
     jacket 5 49.99
     ```

2. **Launch the Processes**:
   - Open three separate terminal windows.
   - Run each process in its own terminal:
     ```bash
     ./shop
     ```
     ```bash
     ./customer
     ```
     ```bash
     ./inventory
     ```

3. **Interact with the Processes**:
   - **Shop**: Automatically prints inventory every 10 seconds and processes incoming requests.
   - **Customer**: Enter orders in the format `item:quantity` (e.g., `shirt:2 pants:1`) or type `quit` to exit.
   - **Inventory Manager**: Choose actions (1 for restock, 2 for set price, 3 to quit) and provide inputs as prompted.

4. **Cleanup**:
   - After terminating the processes (e.g., with `Ctrl+C` or `quit`), message queues persist. Remove them manually if needed:
     ```bash
     mq_unlink /shop_queue
     mq_unlink /customer_queue
     mq_unlink /inventory_queue
     ```

---

## Example Output
### Shop Terminal
```
Inventory:
shirt: 10 units, $19.99
pants: 15 units, $29.99
jacket: 5 units, $49.99

[After 10 seconds and customer order]
Inventory:
shirt: 8 units, $19.99
pants: 14 units, $29.99
jacket: 5 units, $49.99
```

### Customer Terminal
```
Customer process started.
Enter order (e.g., shirt:2 pants:1) or 'quit': shirt:2 pants:1
Response: SUCCESS
Enter order (e.g., shirt:2 pants:1) or 'quit': jacket:10
Response: FAILURE Not enough stock
```

### Inventory Manager Terminal
```
Inventory Manager process started.
Choose action: 1. Restock 2. Set Price 3. Quit: 1
Enter item and quantity (e.g., shirt 5): jacket 10
Response: SUCCESS
Choose action: 1. Restock 2. Set Price 3. Quit: 2
Enter item and new price (e.g., shirt 19.99): shirt 24.99
Response: SUCCESS
```

---

## Design Choices
- **Data Structure**: `std::unordered_map<std::string, Item>` is used for inventory management, providing O(1) average-time complexity for lookups and updates.
- **IPC Mechanism**: POSIX message queues ensure efficient, atomic communication between processes, avoiding the complexity of shared memory or pipes.
- **Modularity**: Separate files for each process and a shared header (`common.h`) enhance readability and maintainability.
- **Error Handling**: System calls (e.g., `mq_open`, `mq_send`) are checked, with errors reported via `perror` for debugging ease.
- **Periodic Printing**: A simple time-based check in the Shop’s main loop balances responsiveness and simplicity without additional threads or signals.

---

## Dependencies
- **C++ Standard Library**: Used for `unordered_map`, `string`, `sstream`, etc.
- **POSIX Libraries**: `<mqueue.h>` for message queues, `<unistd.h>` for system utilities.

---

## Troubleshooting
- **Message Queue Errors**: If queues fail to open, ensure no existing queues remain (`mq_unlink` commands above) and verify permissions.
- **Inventory File Issues**: Ensure `inventory.txt` exists and follows the correct format.
- **Compilation Failures**: Confirm the `-lrt` flag is included and a C++11-compatible compiler is used.

---
