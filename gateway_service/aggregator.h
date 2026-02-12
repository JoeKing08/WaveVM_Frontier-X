#ifndef AGGREGATOR_H
#define AGGREGATOR_H

#include <stdint.h>
#include <stddef.h>
#include "../common_include/wavevm_config.h"

// The structure for an aggregation buffer.
// Kept the same as V28.
typedef struct {
    uint32_t current_len;
    uint8_t  raw_data[MTU_SIZE];
} slave_buffer_t;

/**
 * @brief Initializes the gateway aggregator.
 * This function sets up the multi-threaded RX workers and the main flush loop.
 * It is designed to be called only once at the start of the program.
 * 
 * @param local_port The UDP port for the gateway to listen on.
 * @param upstream_ip The IP address of the upstream gateway or master node.
 * @param upstream_port The UDP port of the upstream entity.
 * @param config_path Path to the swarm configuration file.
 * @return 0 on success, a negative error code on failure.
 */
int init_aggregator(int local_port, const char *upstream_ip, int upstream_port, const char *config_path);

/**
 * @brief Pushes a packet to the aggregator for a specific slave node.
 * This is the main entry point for the master daemon to send packets.
 * The function is thread-safe.
 * 
 * @param slave_id The destination slave node ID.
 * @param data Pointer to the packet data.
 * @param len The length of the packet data.
 * @return 0 on success, a negative error code on failure (e.g., congestion, OOM).
 */
int push_to_aggregator(uint32_t slave_id, void *data, int len);

/**
 * @brief Flushes all pending aggregation buffers.
 * This function is typically called by a background timer thread to ensure
 * data is not buffered for too long.
 */
void flush_all_buffers(void);

#endif // AGGREGATOR_H
