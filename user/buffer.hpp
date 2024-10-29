/* SPDX-License-Identifier: GPL-2.0+ */
/* HyQUIC - A hybrid user-kernel QUIC implementation 
 * based on the QUIC kernel implementation by Xin Long.
 * Copyright (C) 2024  Adrian Moeller
 * 
 * Written or modified by:
 * 	   Adrian Moeller
 */

#ifndef __HYQUIC_BUFFER_HPP__
#define __HYQUIC_BUFFER_HPP__

#include <cstdint>
#include <memory>
#include <string>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <optional>
#include <boost/endian/conversion.hpp>
#include "errors.hpp"

namespace hyquic
{
    /**
     * A buffer that manages an allocated memory range via a pointer.
     */
    struct buffer
    {
        uint8_t *data;
        uint32_t len;
        
        buffer()
            : data(nullptr), len(0)
        {
        }

        buffer(uint32_t len)
            : data((uint8_t*) calloc(len, sizeof(uint8_t))), len(len)
        {
        }

        buffer(uint8_t *data, uint32_t len)
            : data(data), len(len)
        {
        }

        buffer(const char* str)
            : buffer(strlen(str))
        {
            strcpy((char*) data, str);
        }

        buffer(const buffer&) = delete;
        buffer& operator=(buffer&) = delete;

        buffer(buffer &&other)
            : data(other.data), len(other.len)
        {
            other.data = nullptr;
            other.len = 0;
        }

        buffer& operator=(buffer &&other)
        {
            std::swap(data, other.data);
            std::swap(len, other.len);
            return *this;
        }

        ~buffer()
        {
            if (data)
                free(data);
        }

        bool empty()
        {
            return !len;
        }
    };

    typedef boost::endian::order endian_order;
    const endian_order NATIVE = endian_order::native;
    const endian_order NETWORK = endian_order::big;

    /**
     * A view onto an allocated memory range managed via a separate buffer object.
     * It contains a set of utility functions to extract and manipulate data inside the memory range.
     */
    class buffer_view
    {
    public:
        uint8_t *data;
        uint32_t len;

        buffer_view()
            : data(nullptr), len(0)
        {
        }

        buffer_view(uint8_t *data, uint32_t len)
            : data(data), len(len)
        {
        }

        buffer_view(const buffer &buff)
            : data(buff.data), len(buff.len)
        {
        }

        buffer_view(const buffer_view &other)
            : data(other.data), len(other.len)
        {
        }

        buffer_view& operator=(const buffer_view &other)
        {
            data = other.data;
            len = other.len;
            return *this;
        }

        buffer_view& operator=(buffer_view &&other)
        {
            std::swap(data, other.data);
            std::swap(len, other.len);
            return *this;
        }

        inline void prune(uint32_t bytes)
        {
            if (len < bytes)
                throw buffer_error("Buffer read/write overflow.");

            data += bytes;
            len -= bytes;
        }

        inline buffer copy(uint32_t len) const
        {
            if (this->len < len)
                throw buffer_error("Buffer read overflow.");
            
            buffer copied(len);
            memcpy(copied.data, data, copied.len);
            return copied;
        }

        inline buffer copy_all() const
        {
            buffer copied(len);
            memcpy(copied.data, data, copied.len);
            return copied;
        }

        inline bool end() const
        {
            return !len;
        }

        inline buffer pull(uint32_t len)
        {
            buffer copied = copy(len);
            this->data += len;
            this->len -= len;
            return copied;
        }

        template<typename T>
        inline T pull()
        {
            uint32_t len = sizeof(T);

            if (this->len < len)
                throw buffer_error("Buffer read overflow.");

            T val;
            memcpy(&val, this->data, len);
            this->data += len;
            this->len -= len;
            return std::move(val);
        }

        inline uint8_t pull_var(uint64_t &val)
        {
            if (end())
                throw buffer_error("Buffer read overflow.");

            uint8_t val_len = (uint8_t) (1u << (*data >> 6));
            if (len < val_len)
                return 0;
            
            dyn_num num;
            switch (val_len)
            {
            case 1:
                val = *data;
                break;
            case 2:
                memcpy(&num.u16, data, 2);
                num.n[0] &= 0x3f;
                val = boost::endian::big_to_native(num.u16);
                break;
            case 4:
                memcpy(&num.u32, data, 4);
                num.n[0] &= 0x3f;
                val = boost::endian::big_to_native(num.u32);
                break;
            case 8:
                memcpy(&num.u64, data, 8);
                num.n[0] &= 0x3f;
                val = boost::endian::big_to_native(num.u64);
                break;
            }
            data += val_len;
            len -= val_len;
            return val_len;
        }

        template<endian_order Order>
        inline uint32_t pull_int(uint8_t len)
        {
            if (this->len < len)
                throw buffer_error("Buffer read overflow.");

            uint32_t val = 0;
            switch (len)
            {
            case 1:
                val = boost::endian::endian_load<uint32_t, 1, Order>(data);
                break;
            case 2:
                val = boost::endian::endian_load<uint32_t, 2, Order>(data);
                break;
            case 3:
                memcpy(((uint8_t*) &val) + 1, data, 3);
                boost::endian::conditional_reverse_inplace<Order, endian_order::native, uint32_t>(val);
                break;
            case 4:
                val = boost::endian::endian_load<uint32_t, 4, Order>(data);
                break;
            }
            data += len;
            len -= len;
            return val;
        }

        inline void push(const uint8_t *data, uint32_t len)
        {
            if (this->len < len)
                throw buffer_error("Buffer write overflow.");

            memcpy(this->data, data, len);
            this->data += len;
            this->len -= len;
        }

        template<typename T>
        inline void push(const T &data)
        {
            push((uint8_t*) &data, sizeof(T));
        }

        inline void push_pulled(buffer_view &to_pull_from, uint32_t len)
        {
            push(to_pull_from.data, len);
            to_pull_from.prune(len);
        }

        inline void push_buff_into(buffer &&buff)
        {
            push(buff.data, buff.len);
        }

        inline void push_buff(const buffer &buff)
        {
            push(buff.data, buff.len);
        }

        inline void push_var(uint64_t val)
        {
            if (val < 64) {
                if (this->len < 1)
                    throw buffer_error("Buffer write overflow.");

                *data = (uint8_t) val;
                data += 1;
                len -= 1;
            } else if (val < 16384) {
                if (this->len < 2)
                    throw buffer_error("Buffer write overflow.");

                uint16_t num = boost::endian::native_to_big((uint16_t) val);
                memcpy(data, &num, 2);
                *data |= 0x40;
                data += 2;
                len -= 2;
            } else if (val < 1073741824) {
                if (this->len < 4)
                    throw buffer_error("Buffer write overflow.");

                uint32_t num = boost::endian::native_to_big((uint32_t) val);
                memcpy(data, &num, 4);
                *data |= 0x80;
                data += 4;
                len -= 4;
            } else {
                if (this->len < 8)
                    throw buffer_error("Buffer write overflow.");

                uint64_t num = boost::endian::native_to_big((uint64_t) val);
                memcpy(data, &num, 8);
                *data |= 0xc0;
                data += 8;
                len -= 8;
            }
        }

        template<endian_order Order>
        inline void push_int(uint32_t val, uint8_t len)
        {
            if (this->len < len)
                throw buffer_error("Buffer write overflow.");

            switch (len)
            {
            case 1:
                *data = (uint8_t) val;
                break;
            case 2: {
                uint16_t num = boost::endian::conditional_reverse<Order, endian_order::native, uint16_t>((uint16_t) val);
                memcpy(data, &num, 2);
                break;
            }
            case 4: {
                uint32_t num = boost::endian::conditional_reverse<Order, endian_order::native, uint32_t>((uint32_t) val);
                memcpy(data, &num, 4);
                break;
            }
            default:
                throw buffer_error("Length not supported.");
            }
            data += len;
            this->len -= len;
        }

    private:
        union dyn_num {
            uint8_t u8;
            uint16_t u16;
            uint32_t u32;
            uint64_t u64;
            uint8_t n[8];
        };
    };

    /**
     * A view onto an outsized allocated memory range.
     * This class can be used if the data length is not known in advance but can be estimated by an upper bound.
     * To shorten the memory range to its final size, use the trim() function.
     */
    class outsized_buffer_view : public buffer_view
    {
    public:
        outsized_buffer_view(uint8_t *data, uint32_t len)
            : buffer_view(data, len), base_data(data), base_len(len)
        {
        }

        buffer trim()
        {
            uint32_t trimmed_len = base_len - len;
            buffer buff(trimmed_len);
            memcpy(buff.data, base_data, trimmed_len);
            return buff;
        }

    private:
        uint8_t *base_data;
        uint32_t base_len;
    };

    /**
     * A thread-safe FIFO-queue.
     * It has the ability to block until data are available in the queue.
     */
    template<class T>
    class wait_queue
    {
    public:
        wait_queue()
        {
        }

        inline void push(T &&value)
        {
            {
                std::lock_guard<std::mutex> lock(mut);
                internal_queue.push(std::move(value));
            }
            cv.notify_all();
        }

        inline std::optional<T> pop()
        {
            std::lock_guard<std::mutex> lock(mut);
            if (!internal_queue.empty()) {
                std::optional<T> value = std::optional<T>(std::move(internal_queue.front()));
                internal_queue.pop();
                return std::move(value);
            }
            return std::optional<T>();
        }

        inline T wait_pop()
        {
            std::unique_lock<std::mutex> lock(mut);
            cv.wait(lock, [this]{
                return !this->internal_queue.empty();
            });
            T value = std::move(internal_queue.front());
            internal_queue.pop();
            return std::move(value);
        }

        template<class Rep, class Period>
        inline std::optional<T> wait_pop_for(const std::chrono::duration<Rep, Period> &timeout)
        {
            std::unique_lock<std::mutex> lock(mut);
            bool not_empty = cv.wait_for(lock, timeout, [this]{
                return !this->internal_queue.empty();
            });
            std::optional<T> value;
            if (not_empty) {
                value = std::optional<T>(std::move(internal_queue.front()));
                internal_queue.pop();
            }
            return std::move(value);
        }

        template<class Clock, class Duration>
        inline std::optional<T> wait_pop_until(const std::chrono::time_point<Clock, Duration> &timeout)
        {
            std::unique_lock<std::mutex> lock(mut);
            bool not_empty = cv.wait_until(lock, timeout, [this]{
                return !this->internal_queue.empty();
            });
            std::optional<T> value;
            if (not_empty) {
                value = std::optional<T>(std::move(internal_queue.front()));
                internal_queue.pop();
            }
            return std::move(value);
        }

        size_t size()
        {
            std::lock_guard<std::mutex> lock(mut);
            return internal_queue.size();
        }

    private:
        std::mutex mut;
        std::condition_variable cv;
        std::queue<T> internal_queue;
    };
} // namespace hyquic

#endif // __HYQUIC_BUFFER_HPP__