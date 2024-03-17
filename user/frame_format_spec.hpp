#ifndef __HYQUIC_FRAME_FORMAT_SPEC_HPP__
#define __HYQUIC_FRAME_FORMAT_SPEC_HPP__

#include <iostream>
#include "buffer.hpp"

namespace hyquic
{
    class frame_format_specification
    {
    public:
        uint16_t available() const
        {
            // TODO
        }

        buffer& get_encoded() const
        {
            // TODO
        }

        size_t sizeof_encoded() const
        {
            return get_encoded().len;
        }
    };
} // namespace hyquic

#endif // __HYQUIC_FRAME_FORMAT_SPEC_HPP__