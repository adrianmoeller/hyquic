#ifndef __HYQUIC_FRAME_FORMAT_SPEC_HPP__
#define __HYQUIC_FRAME_FORMAT_SPEC_HPP__

#include <iostream>
#include <vector>
#include "buffer.hpp"
#include "errors.hpp"

#ifndef HYQUIC_REF_ID_MAX
#define HYQUIC_REF_ID_MAX 63
#endif

namespace hyquic
{
    class frame_format_specification_builder
    {
    public:
        buffer get_specification() const
        {
            // TODO
            return buffer();
        }

        uint8_t add_var_int_component(bool declares_length = false)
        {
            uint8_t ref_id = 0;
            if (declares_length) {
                ref_id = ref_id_counter++;
            }
            components.push_back(var_int_component(ref_id));
            return ref_id;
        }

        uint8_t add_fix_len_component(uint32_t length, bool declares_length = false)
        {
            uint8_t ref_id = 0;
            if (declares_length) {
                ref_id = ref_id_counter++;
            }
            components.push_back(fix_len_component(length, ref_id));
            return ref_id;
        }

        void add_mult_const_decl_len_component(uint8_t declared_length)
        {
            // TODO
        }

        void add_mult_scope_decl_len_component(uint8_t declared_length)
        {
            // TODO
        }

    private:
        struct format_component
        {
            uint8_t ref_id;

            format_component(uint8_t ref_id = 0)
                : ref_id(ref_id)
            {
                if (ref_id > HYQUIC_REF_ID_MAX)
                    throw frame_format_spec_error("Maximum number of reference IDs reached.");
            }

            virtual size_t size() = 0;
            // TODO
        };

        struct var_int_component : public format_component
        {
            var_int_component(uint8_t ref_id = 0)
                : format_component(ref_id)
            {
            }
        };

        struct fix_len_component : public format_component
        {
            uint32_t length;

            fix_len_component(uint32_t length, uint8_t ref_id = 0)
                : format_component(ref_id), length(length)
            {
            }
        };

        struct mult_const_decl_len_component : public format_component
        {
            uint8_t constant;

            mult_const_decl_len_component(uint8_t constant, uint8_t ref_id = 0)
                : format_component(ref_id), constant(constant)
            {
            }
        };

        struct mult_scope_decl_len_component : public format_component
        {
            frame_format_specification_builder &scope;

            mult_scope_decl_len_component(frame_format_specification_builder &scope, uint8_t ref_id = 0)
                : format_component(ref_id), scope(scope)
            {
            }
        };

        std::vector<format_component> components;
        uint8_t ref_id_counter = 1;
    };

    inline buffer no_frame_format_specification()
    {
        return buffer();
    }

    inline buffer fixed_length_frame_format_specification(uint32_t length)
    {
        // TODO

        return frame_format_specification_builder().get_specification();
    }
} // namespace hyquic

#endif // __HYQUIC_FRAME_FORMAT_SPEC_HPP__