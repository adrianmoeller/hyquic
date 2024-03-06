#ifndef __HYQUIC_BUFFER_HPP__
#define __HYQUIC_BUFFER_HPP__

#include <cstdint>
#include <memory>
#include <string>
#include <boost/lockfree/spsc_queue.hpp>
#include <boost/endian/conversion.hpp>

namespace hyquic
{
    struct buffer
    {
        uint8_t *data;
        uint32_t len;
        
        buffer()
            : data(nullptr), len(0)
        {
        }

        buffer(uint32_t len)
            : data((uint8_t*) malloc(len)), len(len)
        {
        }

        buffer(uint8_t *data, uint32_t len)
            : data(data), len(len)
        {
        }

        buffer(const buffer&) = delete;
        buffer& operator=(buffer&) = delete;

        buffer(buffer &&other)
            :data(other.data), len(other.len)
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

    typedef std::tuple<uint64_t, uint8_t> var_int;
    typedef boost::endian::order endian_order;
    const endian_order NATIVE = endian_order::native;
    const endian_order NETWORK = endian_order::big;

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

        inline bool prune(uint32_t bytes)
        {
            if (bytes > len)
                return false;
            data += bytes;
            len -= bytes;
            return true;
        }

        inline bool push(buffer &&buff)
        {
            if (buff.len > len)
                return false;
            memcpy(data, buff.data, buff.len);
            data += buff.len;
            len -= buff.len;
            return true;
        }

        inline buffer copy(uint32_t len)
        {
            if (len > this->len)
                return buffer();
            buffer copied(len);
            memcpy(copied.data, data, copied.len);
            return copied;
        }

        inline bool end()
        {
            return !len;
        }

        inline var_int pull_var()
        {
            if (end())
                return {0, 0};

            uint8_t val_len = (uint8_t) (1u << (*data >> 6));
            if (len < val_len)
                return {0, 0};
            
            dyn_num num;
            uint64_t val;
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
            return {val, val_len};
        }

        template<endian_order Order>
        inline uint32_t pull_int(uint8_t len)
        {
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
                boost::endian::conditional_reverse_inplace<Order, endian_order::big, uint32_t>(val);
                break;
            case 4:
                val = boost::endian::endian_load<uint32_t, 4, Order>(data);
                break;
            }
            return val;
        }

        inline void push_var(uint64_t val)
        {
            dyn_num num;
            if (val < 64) {
                *data = (uint8_t) val;
                data += 1;
                len -= 1;
            } else if (val < 16384) {
                uint16_t num = boost::endian::native_to_big((uint16_t) val);
                memcpy(data, &num, 2);
                *data |= 0x40;
                data += 2;
                len -= 2;
            } else if (val < 1073741824) {
                uint32_t num = boost::endian::native_to_big((uint32_t) val);
                memcpy(data, &num, 4);
                *data |= 0x80;
                data += 4;
                len -= 4;
            } else {
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
            switch (len)
            {
            case 1:
                *data = (uint8_t) val;
                break;
            case 2: {
                uint16_t num = boost::endian::conditional_reverse<Order, endian_order::big, uint16_t>((uint16_t) val);
                memcpy(data, &num, 2);
            }
                break;
            case 4: {
                uint32_t num = boost::endian::conditional_reverse<Order, endian_order::big, uint32_t>((uint32_t) val);
                memcpy(data, &num, 4);
            }
                break;
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

    struct stream_data
    {
        uint64_t id;
        uint32_t flag;
        buffer buff;

        stream_data(uint64_t id, uint32_t flag, buffer &&buff)
            : id(id), flag(flag), buff(std::move(buff))
        {
        }
    };

    typedef boost::lockfree::spsc_queue<std::shared_ptr<stream_data>> stream_data_buff;
} // namespace hyquic


#endif // __HYQUIC_BUFFER_HPP__