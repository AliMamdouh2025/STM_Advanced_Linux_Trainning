/**
 *===================================================================================
 * @file           : shop.cpp
 * @author         : Ali Mamdouh
 * @brief          : Main file for the Clothing Shop Simulation project.
 *                   This file contains functions for loading the inventory from a file,
 *                   processing customer orders, handling restock and price update messages,
 *                   and periodically printing the current inventory.
 *                   Communication between processes is implemented using POSIX message queues.
 * @Reviewer       : Eng Karim
 * @Version        : 1.0.0
 *===================================================================================
 */





 

/*============================================================================
 ******************************  Includes  ***********************************
 ============================================================================*/
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <utility>
#include <ctime>
#include <cstring>
#include <mqueue.h>
#include <unistd.h>
#include "common.hpp"








/*============================================================================
 ***********************  Function Declarations  *****************************
 ============================================================================*/

/**
 * @brief Loads the initial inventory from a specified file.
 *
 * Each line in the file should contain an item name, available count, and price,
 * separated by whitespace (e.g., "shirt 10 20.0"). The function populates the
 * provided inventory map with these values.
 *
 * @param filename The path to the inventory file.
 * @param inventory The unordered_map to store the inventory data.
 */
void load_inventory(const std::string& filename, std::unordered_map<std::string, Item>& inventory) 
{
    std::ifstream file(filename);
    if (!file.is_open()) 
    {
        std::cerr << "Failed to open inventory file: " << filename << std::endl;
        exit(1);
    }
    std::string line;
    // Read the file line by line.
    while (std::getline(file, line)) 
    {
        std::istringstream iss(line);
        std::string name;
        int count;
        double price;
        // Extract item details from each line.
        if (iss >> name >> count >> price) 
        {
            inventory[name] = {count, price};
        } else 
        {
            std::cerr << "Invalid line in inventory file: " << line << std::endl;
        }
    }
    file.close();
}

/**
 * @brief Prints the current inventory to the standard output.
 *
 * Iterates over the inventory map and displays each item's name, available count,
 * and price in a human-readable format.
 *
 * @param inventory The unordered_map containing the inventory data.
 */
void print_inventory(const std::unordered_map<std::string, Item>& inventory) 
{
    std::cout << "Inventory:\n";
    for (const auto& [item, details] : inventory) 
    {
        std::cout << item << ": " << details.count << " units, $" << details.price << std::endl;
    }
    std::cout << std::endl;
}

/**
 * @brief Parses an order message and extracts item-quantity pairs.
 *
 * The expected format for the order message is "ORDER item1:qty1 item2:qty2 ...".
 * This function skips the "ORDER " prefix and extracts each item and its requested quantity.
 *
 * @param message The complete order message string.
 * @return A vector of pairs, where each pair contains the item name and the requested quantity.
 */
std::vector<std::pair<std::string, int>> parse_order(const std::string& message) 
{
    std::vector<std::pair<std::string, int>> order;
    // Skip the "ORDER " prefix (first 6 characters).
    std::istringstream iss(message.substr(6));
    std::string pairStr;
    // Process each token in the format "item:qty".
    while (iss >> pairStr)
    {
        size_t colon = pairStr.find(':');
        if (colon != std::string::npos) 
        {
            std::string item = pairStr.substr(0, colon);
            int qty = std::stoi(pairStr.substr(colon + 1));
            order.push_back({item, qty});
        }
    }
    return order;
}

/**
 * @brief Processes a customer's order by checking inventory availability and updating stock.
 *
 * The function verifies that all requested items are available in sufficient quantity.
 * If so, it deducts the requested quantities from the inventory.
 *
 * @param order A vector of item-quantity pairs representing the customer's order.
 * @param inventory The inventory map that will be updated if the order is fulfilled.
 * @return true if the order was successfully processed; false if there is insufficient stock.
 */
bool process_order(const std::vector<std::pair<std::string, int>>& order, 
                     std::unordered_map<std::string, Item>& inventory) 
{
    // Validate that each requested item is available in sufficient quantity.
    for (const auto& [item, qty] : order) 
    {
        auto it = inventory.find(item);
        if (it == inventory.end() || it->second.count < qty) 
        {
            return false;  // Item not found or insufficient stock.
        }
    }
    // Deduct the ordered quantities from the inventory.
    for (const auto& [item, qty] : order) 
    {
        inventory[item].count -= qty;
    }
    return true;
}

/**
 * @brief Processes a restock message to update the inventory count.
 *
 * The expected message format is "RESTOCK item:qty". This function extracts the item name
 * and the quantity to add, then updates the inventory accordingly.
 *
 * @param message The restock message string.
 * @param inventory The inventory map to be updated.
 */
void process_restock(const std::string& message, std::unordered_map<std::string, Item>& inventory) 
{
    // Skip the "RESTOCK " prefix (first 8 characters).
    std::istringstream iss(message.substr(8));
    std::string item_qty;
    iss >> item_qty;
    size_t colon = item_qty.find(':');
    std::string item = item_qty.substr(0, colon);
    int qty = std::stoi(item_qty.substr(colon + 1));
    inventory[item].count += qty;
}

/**
 * @brief Processes a set price message to update an item's price in the inventory.
 *
 * The expected message format is "SETPRICE item:price". This function extracts the item name
 * and the new price, then updates the inventory accordingly.
 *
 * @param message The set price message string.
 * @param inventory The inventory map to be updated.
 */
void process_setprice(const std::string& message, std::unordered_map<std::string, Item>& inventory) 
{
    // Skip the "SETPRICE " prefix (first 9 characters).
    std::istringstream iss(message.substr(9));
    std::string item_price;
    iss >> item_price;
    size_t colon = item_price.find(':');
    std::string item = item_price.substr(0, colon);
    double price = std::stod(item_price.substr(colon + 1));
    inventory[item].price = price;
}








/*============================================================================
 *******************************  Main Function  *******************************
 ============================================================================*/

/**
 * @brief Entry point for the shop process.
 *
 * Sets up POSIX message queues, loads the initial inventory from a file, and enters
 * a loop to process incoming messages (orders, restock, and set price). The inventory
 * is printed to the console every 10 seconds. Depending on the message type, the function
 * calls the appropriate handler to update the inventory and sends back a response.
 *
 * @return int Exit status of the program.
 */
int main() 
{
    //============================================================================
    // Initialize POSIX message queue attributes.
    //============================================================================
    struct mq_attr attr;
    attr.mq_flags = 0;
    attr.mq_maxmsg = MAX_MESSAGES;
    attr.mq_msgsize = MSG_SIZE;
    attr.mq_curmsgs = 0;

    //============================================================================
    // Create and open message queues.
    //============================================================================
    // shop_queue: Used for receiving messages.
    mqd_t shop_queue = mq_open(SHOP_QUEUE.c_str(), O_CREAT | O_RDONLY, 0644, &attr);
    // customer_queue: Used to send responses to customer orders.
    mqd_t customer_queue = mq_open(CUSTOMER_QUEUE.c_str(), O_CREAT | O_WRONLY, 0644, &attr);
    // inventory_queue: Used to send acknowledgments for restock and set price updates.
    mqd_t inventory_queue = mq_open(INVENTORY_QUEUE.c_str(), O_CREAT | O_WRONLY, 0644, &attr);
    if (shop_queue == (mqd_t)-1 || customer_queue == (mqd_t)-1 || inventory_queue == (mqd_t)-1) 
    {
        perror("mq_open");
        exit(1);
    }

    //============================================================================
    // Load initial inventory from file.
    //============================================================================
    std::unordered_map<std::string, Item> inventory;
    load_inventory("inventory.txt", inventory);

    //============================================================================
    // Set up for periodic inventory printing (every 10 seconds).
    //============================================================================
    time_t next_print = time(nullptr) + 10;
    char buffer[MSG_SIZE];

    //============================================================================
    // Main loop: Process incoming messages and print inventory periodically.
    //============================================================================
    struct timespec timeout;
    while (true) 
    {
        // Get current time and check if it's time to print the inventory.
        time_t now = time(nullptr);
        if (now >= next_print) 
        {
            print_inventory(inventory);
            next_print = now + 10;  // Schedule the next print.
        }
        
        // Calculate the timeout period until the next inventory print.
        timeout.tv_sec = next_print - now;
        timeout.tv_nsec = 0;

        // Wait for a message until the timeout expires.
        ssize_t bytes_read = mq_timedreceive(shop_queue, buffer, MSG_SIZE, nullptr, &timeout);
        if (bytes_read < 0) 
        {
            if (errno == ETIMEDOUT) 
            {
                // Timeout is expected when no messages are received before the next print.
                continue;
            }
            perror("mq_timedreceive");
            break;
        }

        // Construct a std::string from the received message.
        std::string message(buffer, bytes_read);

        // Process the message based on its type.
        if (message.substr(0, 5) == "ORDER") 
        {
            auto order = parse_order(message);
            std::string response = process_order(order, inventory) ? 
                                  "SUCCESS" : "FAILURE Not enough stock";
            if (mq_send(customer_queue, response.c_str(), response.size(), 0) < 0) 
            {
                perror("mq_send to customer_queue");
            }
        } else if (message.substr(0, 7) == "RESTOCK") 
        {
            process_restock(message, inventory);
            if (mq_send(inventory_queue, "SUCCESS", 7, 0) < 0) 
            {
                perror("mq_send to inventory_queue");
            }
        } else if (message.substr(0, 8) == "SETPRICE") 
        {
            process_setprice(message, inventory);
            if (mq_send(inventory_queue, "SUCCESS", 7, 0) < 0) 
            {
                perror("mq_send to inventory_queue");
            }
        }
    }
    
    //============================================================================
    // Cleanup: Close all message queues.
    //============================================================================
    mq_close(shop_queue);
    mq_close(customer_queue);
    mq_close(inventory_queue);
    // Note: POSIX message queues persist until explicitly unlinked with mq_unlink.
    return 0;
}
