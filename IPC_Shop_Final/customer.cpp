/**
 *===================================================================================
 * @file           : customer.cpp
 * @author         : Ali Mamdouh
 * @brief          : Main file for the Customer process in the Clothing Shop Simulation project.
 *                   This process accepts interactive orders from the user, sends the orders to
 *                   the Shop process via a POSIX message queue, and receives responses back.
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
 * @brief Entry point for the Customer process.
 *
 * This function opens the necessary POSIX message queues for sending orders to the
 * Shop process and receiving responses. It then enters an interactive loop where
 * the user can enter orders. Each order is sent as a message prefixed with "ORDER ".
 * The process waits for a response from the Shop process and displays it to the user.
 *
 * @return int Exit status of the program.
 */
int main() 
{
    //============================================================================
    // Open POSIX message queues.
    //============================================================================
    // shop_queue: Used to send orders to the Shop process.
    mqd_t shop_queue = mq_open(SHOP_QUEUE.c_str(), O_WRONLY);
    // customer_queue: Used to receive responses from the Shop process.
    mqd_t customer_queue = mq_open(CUSTOMER_QUEUE.c_str(), O_RDONLY);
    
    // Check if the queues were successfully opened.
    if (shop_queue == (mqd_t)-1 || customer_queue == (mqd_t)-1) 
    {
        perror("mq_open");
        exit(1);
    }

    std::cout << "Customer process started.\n";
    
    //============================================================================
    // Main interactive loop for processing user orders.
    //============================================================================
    while (true) 
    {
        std::cout << "Enter order (e.g., shirt:2 pants:1) or 'quit': ";
        std::string input;
        std::getline(std::cin, input);

        // Exit the loop if the user types "quit".
        if (input == "quit") break;

        // Prepend the order type "ORDER " to the user's input.
        std::string message = "ORDER " + input;

        // Send the order message to the Shop process.
        if (mq_send(shop_queue, message.c_str(), message.size(), 0) < 0) 
        {
            perror("mq_send");
            continue;
        }

        // Buffer to store the response from the Shop process.
        char buffer[MSG_SIZE];
        // Receive the response from the Shop process.
        ssize_t bytes_read = mq_receive(customer_queue, buffer, MSG_SIZE, nullptr);
        if (bytes_read < 0) 
        {
            perror("mq_receive");
            continue;
        }
        // Construct a string from the received buffer.
        std::string response(buffer, bytes_read);
        std::cout << "Response: " << response << std::endl;
    }

    //============================================================================
    // Cleanup: Close the message queues before exiting.
    //============================================================================
    mq_close(shop_queue);
    mq_close(customer_queue);
    return 0;
}
