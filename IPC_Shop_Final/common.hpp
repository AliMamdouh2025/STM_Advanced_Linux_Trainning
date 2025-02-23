/**
 *===================================================================================
 * @file           : common.hpp
 * @author         : Ali Mamdouh
 * @brief          : Header file containing common APIs, data types, and configuration
 *                   constants used throughout the Clothing Shop Simulation project.
 *                   This file defines shared data structures and POSIX message queue
 *                   configuration for inter-process communication (IPC).
 * @Reviewer       : Eng Karim
 * @Version        : 1.0.0
 *===================================================================================
 */

#ifndef COMMON_H
#define COMMON_H





/*============================================================================
 ******************************  Includes  ***********************************
 ============================================================================*/ 
#include <string>
#include <unordered_map>






/*============================================================================
 *************************  Data Type Declarations  *************************
 ============================================================================*/ 

/**
 * @brief Structure representing an inventory item.
 *
 * This structure holds essential information about an item in the shop's inventory,
 * including the available count and the price per unit.
 */
struct Item 
{
    int count;       ///< The number of items available in inventory.
    double price;    ///< The price of one unit of the item.
};







/*============================================================================
 ***********************  Configuration Constants  ***************************
 ============================================================================*/

/**
 * @brief POSIX Message Queue Names.
 *
 * These constants define the names of the POSIX message queues used for
 * inter-process communication in the Clothing Shop Simulation project.
 * Queue names must start with a '/' and be unique within the system.
 */
const std::string SHOP_QUEUE =        "/shop_queue";       ///< Queue for messages related to the Shop process.
const std::string CUSTOMER_QUEUE =    "/customer_queue";   ///< Queue for messages sent by the Customer process.
const std::string INVENTORY_QUEUE =   "/inventory_queue";  ///< Queue for messages sent by the Inventory Manager process.

/**
 * @brief IPC Message Queue Parameters.
 *
 * These constants define the size and capacity of the message queues used in the project.
 * - MSG_SIZE: The maximum size (in bytes) for a single message.
 * - MAX_MESSAGES: The maximum number of messages that can be held in the queue simultaneously.
 */
const size_t MSG_SIZE = 1024;      ///< Maximum size (in bytes) for a single message.
const int MAX_MESSAGES = 90;       ///< Maximum number of messages allowed in the queue.

#endif // COMMON_H
