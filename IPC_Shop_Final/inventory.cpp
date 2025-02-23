/**
 *===================================================================================
 * @file           : inventory.cpp
 * @author         : Ali Mamdouh
 * @brief          : Main file for the Inventory Manager process in the Clothing Shop Simulation project.
 *                   This process provides an interactive interface for updating the shop's inventory.
 *                   It allows the user to either restock an item or set a new price for an item.
 *                   The process sends messages to the Shop process via a POSIX message queue and
 *                   receives acknowledgments on a separate queue.
 * @Reviewer       : Eng Karim
 * @Version        : 1.0.0
 *===================================================================================
 */





/*============================================================================
 ******************************  Includes  ***********************************
 ============================================================================*/
#include <iostream>
#include <sstream>
#include <mqueue.h>
#include <cstring>
#include "common.hpp"






/*============================================================================
 *******************************  Main Function  *******************************
 ============================================================================*/

/**
 * @brief Entry point for the Inventory Manager process.
 *
 * This function opens the necessary POSIX message queues for sending updates to the
 * Shop process and receiving responses. It then enters an interactive loop where the
 * user can choose to restock an item or set a new price. Based on the user's input,
 * it constructs the appropriate message ("RESTOCK" or "SETPRICE") and sends it to the
 * Shop process. The response from the Shop is then received and displayed.
 *
 * @return int Exit status of the program.
 */
int main() 
{
    //============================================================================
    // Open POSIX message queues.
    //============================================================================
    // shop_queue: Used to send update messages (restock/set price) to the Shop process.
    mqd_t shop_queue = mq_open(SHOP_QUEUE.c_str(), O_WRONLY);
    // inventory_queue: Used to receive responses/acknowledgments from the Shop process.
    mqd_t inventory_queue = mq_open(INVENTORY_QUEUE.c_str(), O_RDONLY);
    
    // Check if the queues were successfully opened.
    if (shop_queue == (mqd_t)-1 || inventory_queue == (mqd_t)-1) 
    {
        perror("mq_open");
        exit(1);
    }

    std::cout << "Inventory Manager process started.\n";

    //============================================================================
    // Main interactive loop for processing inventory updates.
    //============================================================================
    while (true) 
    {
        std::cout << "Choose action: 1. Restock 2. Set Price 3. Quit: ";
        int choice;
        std::cin >> choice;
        std::cin.ignore(); // Clear the input buffer

        // Exit the loop if the user chooses to quit.
        if (choice == 3) break;

        std::string item, message;
        // Process the "Restock" action.
        if (choice == 1) 
        {
            int qty;
            std::cout << "Enter item and quantity (e.g., shirt 5): ";
            std::cin >> item >> qty;
            // Construct the RESTOCK message with the format: "RESTOCK item:qty"
            message = "RESTOCK " + item + ":" + std::to_string(qty);
        }
        // Process the "Set Price" action.
        else if (choice == 2) 
        {
            double price;
            std::cout << "Enter item and new price (e.g., shirt 19.99): ";
            std::cin >> item >> price;
            // Construct the SETPRICE message with the format: "SETPRICE item:price"
            message = "SETPRICE " + item + ":" + std::to_string(price);
        }
        else 
        {
            std::cout << "Invalid choice.\n";
            std::cin.ignore(); // Clear any residual input
            continue;
        }
        std::cin.ignore(); // Clear the input buffer after processing

        //============================================================================
        // Send the constructed message to the Shop process.
        //============================================================================
        if (mq_send(shop_queue, message.c_str(), message.size(), 0) < 0) 
        {
            perror("mq_send");
            continue;
        }

        //============================================================================
        // Wait for and process the acknowledgment from the Shop process.
        //============================================================================
        char buffer[MSG_SIZE];
        ssize_t bytes_read = mq_receive(inventory_queue, buffer, MSG_SIZE, nullptr);
        if (bytes_read < 0) 
        {
            perror("mq_receive");
            continue;
        }
        // Convert the received message into a string and display it.
        std::string response(buffer, bytes_read);
        std::cout << "Response: " << response << std::endl;
    }

    //============================================================================
    // Cleanup: Close all message queues before exiting.
    //============================================================================
    mq_close(shop_queue);
    mq_close(inventory_queue);
    return 0;
}
