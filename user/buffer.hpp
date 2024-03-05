#ifndef __HYQUIC_BUFFER_HPP__
#define __HYQUIC_BUFFER_HPP__

#include <cstdint>
#include <memory>
#include <string>
#include <boost/lockfree/spsc_queue.hpp>

namespace hyquic
{
    using namespace std;

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
            swap(data, other.data);
            swap(len, other.len);
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
            swap(data, other.data);
            swap(len, other.len);
            return *this;
        }

        bool prune(uint32_t bytes)
        {
            if (bytes > len)
                return false;
            data += bytes;
            len -= bytes;
            return true;
        }

        bool write(buffer &&buff)
        {
            if (buff.len > len)
                return false;
            memcpy(data, buff.data, buff.len);
            data += buff.len;
            len -= buff.len;
            return true;
        }

        bool end()
        {
            return !len;
        }
    };

    struct stream_data
    {
        uint64_t id;
        uint32_t flag;
        buffer buff;

        stream_data(uint64_t id, uint32_t flag, buffer &&buff)
            : id(id), flag(flag), buff(move(buff))
        {
        }
    };

    typedef boost::lockfree::spsc_queue<shared_ptr<stream_data>> stream_data_buff;
} // namespace hyquic


#endif // __HYQUIC_BUFFER_HPP__