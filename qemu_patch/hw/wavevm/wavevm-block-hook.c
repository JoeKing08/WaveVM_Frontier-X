/* 
 * [QEMU Hook] virtio-blk IO 拦截与线性化 
 * 此函数应被 virtio_blk_handle_rw 调用
 */

// 引用外部 IPC 发送函数
extern int wvm_send_ipc_block_io(uint64_t lba, void *buf, uint32_t len, int is_write);

static int wavevm_blk_interceptor(uint64_t sector, QEMUIOVector *qiov, int is_write) {
    size_t total_len = qiov->size;
    if (total_len == 0) return 0;

    /* [V31 PHY] 线性化 (Linearization)
     * virtio 请求通常是散列的 (Scatter-Gather)，物理分布在多个 Guest 物理页。
     * 我们必须将其 Flatten 为连续 Buffer 才能通过 socket 发送。
     */
    void *linear_buf = qemu_memalign(4096, total_len); // QEMU 内部对齐分配
    if (!linear_buf) return -1;

    if (is_write) {
        // 将离散的 iov 数据拷贝到连续 buffer
        qemu_iovec_to_buf(qiov, 0, linear_buf, total_len);
    }

    // 发送 IPC 给 Daemon
    // 注意：Daemon 会进一步通过 DHT 路由到正确的 Slave
    int ret = wvm_send_ipc_block_io(sector, linear_buf, total_len, is_write);

    if (!is_write && ret == 0) {
        // 读操作成功后，将数据拷回 iov
        qemu_iovec_from_buf(qiov, 0, linear_buf, total_len);
    }

    qemu_vfree(linear_buf);
    return ret; // 0=Intercepted & Success, -1=Passthrough
}
