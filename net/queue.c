/*
 * Copyright (c) 2003-2008 Fabrice Bellard
 * Copyright (c) 2009 Red Hat, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "net/queue.h"
#include "qemu/queue.h"
#include "net/net.h"
#include "qemu/timer.h"

/* The delivery handler may only return zero if it will call
 * qemu_net_queue_flush() when it determines that it is once again able
 * to deliver packets. It must also call qemu_net_queue_purge() in its
 * cleanup path.
 *
 * If a sent callback is provided to send(), the caller must handle a
 * zero return from the delivery handler by not sending any more packets
 * until we have invoked the callback. Only in that case will we queue
 * the packet.
 *
 * If a sent callback isn't provided, we just drop the packet to avoid
 * unbounded queueing.
 */

struct NetPacket {
    QTAILQ_ENTRY(NetPacket) entry;
    NetClientState *sender;
    unsigned flags;
    int size;
    NetPacketSent *sent_cb;
    uint8_t data[0];
};

struct NetQueue {
    void *opaque;
    uint32_t nq_maxlen;
    uint32_t maxsize;
    uint32_t nq_count;
    uint32_t size_count;

    QTAILQ_HEAD(packets, NetPacket) packets;

    unsigned delivering : 1;
};

NetQueue *qemu_new_net_queue(void *opaque)
{
    NetQueue *queue;

    queue = g_malloc0(sizeof(NetQueue));

    queue->opaque = opaque;
    queue->nq_maxlen = 10000;
    queue->nq_count = 0;
    queue->size_count = 0;

    QTAILQ_INIT(&queue->packets);

    queue->delivering = 0;

    return queue;
}

void qemu_del_net_queue(NetQueue *queue)
{
    NetPacket *packet, *next;

    QTAILQ_FOREACH_SAFE(packet, &queue->packets, entry, next) {
        QTAILQ_REMOVE(&queue->packets, packet, entry);
        g_free(packet);
    }

    g_free(queue);
}

static void qemu_net_queue_append(NetQueue *queue,
                                  NetClientState *sender,
                                  unsigned flags,
                                  const uint8_t *buf,
                                  size_t size,
                                  NetPacketSent *sent_cb)
{
    NetPacket *packet;

    if (queue->nq_count + 1 > queue->nq_maxlen && !sent_cb) {
        return; /* drop if queue full and no callback */
    }
    if (queue->size_count + size > queue->maxsize && !sent_cb) {
        return; /* drop if queue full and no callback */
    }
    packet = g_malloc(sizeof(NetPacket) + size);
    packet->sender = sender;
    packet->flags = flags;
    packet->size = size;
    packet->sent_cb = sent_cb;
    memcpy(packet->data, buf, size);

    queue->nq_count++;
    queue->size_count += size;
    QTAILQ_INSERT_TAIL(&queue->packets, packet, entry);
}

static void qemu_net_queue_append_iov(NetQueue *queue,
                                      NetClientState *sender,
                                      unsigned flags,
                                      const struct iovec *iov,
                                      int iovcnt,
                                      NetPacketSent *sent_cb)
{
    NetPacket *packet;
    size_t max_len = 0;
    int i;

    if (queue->nq_count >= queue->nq_maxlen && !sent_cb) {
        return; /* drop if queue full and no callback */
    }
    for (i = 0; i < iovcnt; i++) {
        max_len += iov[i].iov_len;
    }

    packet = g_malloc(sizeof(NetPacket) + max_len);
    packet->sender = sender;
    packet->sent_cb = sent_cb;
    packet->flags = flags;
    packet->size = 0;

    for (i = 0; i < iovcnt; i++) {
        size_t len = iov[i].iov_len;

        memcpy(packet->data + packet->size, iov[i].iov_base, len);
        packet->size += len;
    }

    queue->nq_count++;
    QTAILQ_INSERT_TAIL(&queue->packets, packet, entry);
}

static ssize_t qemu_net_queue_deliver(NetQueue *queue,
                                      NetClientState *sender,
                                      unsigned flags,
                                      const uint8_t *data,
                                      size_t size)
{
    ssize_t ret = -1;

    queue->delivering = 1;
    ret = qemu_deliver_packet(sender, flags, data, size, queue->opaque);
    queue->delivering = 0;

    return ret;
}

static ssize_t qemu_net_queue_deliver_iov(NetQueue *queue,
                                          NetClientState *sender,
                                          unsigned flags,
                                          const struct iovec *iov,
                                          int iovcnt)
{
    ssize_t ret = -1;

    queue->delivering = 1;
    ret = qemu_deliver_packet_iov(sender, flags, iov, iovcnt, queue->opaque);
    queue->delivering = 0;

    return ret;
}

static void throttle_timer_cb(void *opaque)
{
    NetClientState *nc = opaque;

    printf("%10s:  bps: %8.0f |  bps_rx: %8.0f |  bps_tx: %8.0f "
           "|  pps:    %8.0f |  pps_rx: %8.0f |  pps_tx: %8.0f\n",
           nc->name, nc->bps_count + nc->peer->bps_count,
           nc->peer->bps_count, nc->bps_count,
           nc->pps_count + nc->peer->pps_count,
           nc->peer->pps_count, nc->pps_count);

    timer_mod(nc->throttle_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
              get_ticks_per_sec());

    nc->pps_count = 0;
    nc->peer->pps_count = 0;
    nc->bps_count = 0;
    nc->peer->bps_count = 0;
}

ssize_t qemu_net_queue_send(NetQueue *queue,
                            NetClientState *sender,
                            unsigned flags,
                            const uint8_t *data,
                            size_t size,
                            NetPacketSent *sent_cb)
{
    ssize_t ret;

    /* set the rate limit */
    if (sender->pps_limit) {
        queue->nq_maxlen = sender->pps_limit * 2;
    } else if (sender->bps_limit) {
        queue->maxsize = sender->bps_limit * 2;
    }

    if (!sender->throttle_timer && sender->info->type ==
        NET_CLIENT_OPTIONS_KIND_NIC) {
        sender->throttle_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                              throttle_timer_cb, sender);
        timer_mod(sender->throttle_timer,
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                  get_ticks_per_sec());
    }

    /* throttling network I/O */
    if ((sender->pps_limit && sender->pps_count + 1 > sender->pps_limit) ||
        (sender->bps_limit &&  sender->bps_count + size > sender->bps_limit) ||
        (sender->pps_total_limit && sender->peer->pps_count +
         sender->pps_count + 1 > sender->pps_total_limit) ||
        (sender->bps_total_limit && sender->peer->bps_count +
         sender->bps_count + size > sender->bps_total_limit)) {
        qemu_net_queue_append(queue, sender, flags, data, size, sent_cb);
        return size;
    }

    if (queue->delivering || !qemu_can_send_packet(sender)) {
        qemu_net_queue_append(queue, sender, flags, data, size, sent_cb);
        return 0;
    }

    ret = qemu_net_queue_deliver(queue, sender, flags, data, size);
    if (ret == 0) {
        qemu_net_queue_append(queue, sender, flags, data, size, sent_cb);
        return 0;
    }
    sender->pps_count++;
    sender->bps_count += size;
    qemu_net_queue_flush(queue, sender);

    return ret;
}

ssize_t qemu_net_queue_send_iov(NetQueue *queue,
                                NetClientState *sender,
                                unsigned flags,
                                const struct iovec *iov,
                                int iovcnt,
                                NetPacketSent *sent_cb)
{
    ssize_t ret;

    if (!sender->throttle_timer && sender->info->type ==
        NET_CLIENT_OPTIONS_KIND_NIC) {
        sender->throttle_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                              throttle_timer_cb, sender);
        timer_mod(sender->throttle_timer,
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + get_ticks_per_sec());
    }

    /* throttling network I/O */
    /* TODO: samiliar with qemu_net_queue_send()  */

    if (queue->delivering || !qemu_can_send_packet(sender)) {
        qemu_net_queue_append_iov(queue, sender, flags, iov, iovcnt, sent_cb);
        return 0;
    }

    ret = qemu_net_queue_deliver_iov(queue, sender, flags, iov, iovcnt);
    if (ret == 0) {
        qemu_net_queue_append_iov(queue, sender, flags, iov, iovcnt, sent_cb);
        return 0;
    }

    qemu_net_queue_flush(queue, sender);

    return ret;
}

void qemu_net_queue_purge(NetQueue *queue, NetClientState *from)
{
    NetPacket *packet, *next;

    QTAILQ_FOREACH_SAFE(packet, &queue->packets, entry, next) {
        if (packet->sender == from) {
            QTAILQ_REMOVE(&queue->packets, packet, entry);
            queue->nq_count--;
            queue->size_count -= packet->size;
            g_free(packet);
        }
    }
}

bool qemu_net_queue_flush(NetQueue *queue, NetClientState *sender)
{
    NetPacket *packet;

    while (!QTAILQ_EMPTY(&queue->packets)) {
        int ret;

        packet = QTAILQ_FIRST(&queue->packets);
        QTAILQ_REMOVE(&queue->packets, packet, entry);
        queue->nq_count--;
        queue->size_count -= packet->size;

        if (sender->pps_limit && sender->pps_count + 1 > sender->pps_limit) {
            goto limit;
        }
        if (sender->pps_total_limit && sender->peer->pps_count +
            sender->pps_count + 1 > sender->pps_total_limit) {
            goto limit;
        }
        if (sender->bps_limit && sender->bps_count + packet->size >
            sender->bps_limit) {
            goto limit;
        }
        if (sender->bps_total_limit && sender->peer->bps_count +
            sender->bps_count + packet->size > sender->bps_total_limit) {
            goto limit;
        }

        ret = qemu_net_queue_deliver(queue,
                                     packet->sender,
                                     packet->flags,
                                     packet->data,
                                     packet->size);
        if (ret == 0) {
            queue->nq_count++;
            queue->size_count += packet->size;
            QTAILQ_INSERT_HEAD(&queue->packets, packet, entry);
            return false;
        }

        if (packet->sent_cb) {
            packet->sent_cb(packet->sender, ret);
        }
        sender->pps_count++;
        sender->bps_count += packet->size;

        g_free(packet);
    }
    return true;

limit:
    queue->nq_count++;
    queue->size_count += packet->size;
    QTAILQ_INSERT_HEAD(&queue->packets, packet, entry);
    return true;
}
