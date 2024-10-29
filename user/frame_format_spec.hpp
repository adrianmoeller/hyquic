/* SPDX-License-Identifier: GPL-2.0+ */
/* HyQUIC - A hybrid user-kernel QUIC implementation 
 * based on the QUIC kernel implementation by Xin Long.
 * Copyright (C) 2024  Adrian Moeller
 * 
 * Written or modified by:
 * 	   Adrian Moeller
 */

#ifndef __HYQUIC_FRAME_FORMAT_SPEC_HPP__
#define __HYQUIC_FRAME_FORMAT_SPEC_HPP__

#include <iostream>
#include <vector>
#include <memory>
#include "buffer.hpp"
#include "errors.hpp"

#ifndef HYQUIC_REF_ID_MAX
#define HYQUIC_REF_ID_MAX 15
#endif

namespace hyquic
{
    /**
     * Returns the length in bytes of an encoded variable-length integer for the given integer value.
     */
    static inline uint8_t get_var_int_length(uint64_t val)
    {
        if (val < 64)
            return 1;
        if (val < 16384)
            return 2;
        if (val < 1073741824)
            return 4;
        return 8;
    }

    /**
     * Used to build a frame format specification (FFS).
     * It starts with an empty FFS. Components can be added.
     * Finally, the encoded FFS can be exported.
     */
    class frame_format_specification_builder
    {
    public:
        /**
         * Returns the size in bytes of the encoded FFS.
         */
        size_t size() const
        {
            size_t size = 0;
            for (const auto &comp : components)
                size += comp->size();
            return size;
        }

        /**
         * Produces and returns the encoded FFS.
         */
        buffer get_specification() const
        {
            buffer buff(size());
            buffer_view cursor(buff);

            for (const auto &comp : components)
                comp->encode(cursor);

            return buff;
        }

        /**
         * Creates a variable-length integer component and adds it to the FFS.
         * 
         * @param declares_length Denotes if the number contained in the component's field affects the length of a subsequent part of the frame
         * @param is_payload denotes if the bytes parsed by this component are part application data
         * @return the reference ID (>0) to identify the declared length field. If declared_length is false, it always returns 0
         */
        uint8_t add_var_int_component(bool declares_length = false, bool is_payload = false)
        {
            uint8_t ref_id = 0;
            if (declares_length) {
                ref_id = ref_id_counter++;
            }
            components.push_back(std::make_unique<var_int_component>(ref_id, is_payload));
            return ref_id;
        }
        /**
         * Creates a fixed length integer component and adds it to the FFS.
         * 
         * @param length the length of the field
         * @param declares_length Denotes if the number contained in the component's field affects the length of a subsequent part of the frame
         * @param is_payload denotes if the bytes parsed by this component are part application data
         * @return the reference ID (>0) to identify the declared length field. If declared_length is false, it always returns 0
         */
        uint8_t add_fix_len_component(uint32_t length, bool declares_length = false, bool is_payload = false)
        {
            uint8_t ref_id = 0;
            if (declares_length) {
                ref_id = ref_id_counter++;
            }
            components.push_back(std::make_unique<fix_len_component>(length, ref_id, is_payload));
            return ref_id;
        }

        /**
         * Creates a multiply constant by declared length component and adds it to the FFS.
         * 
         * @param declared_length_ref_id the reference ID of the declared length field
         * @param constant the constant that is multiplied with the declared length to determine the field length
         * @param is_payload denotes if the bytes parsed by this component are part application data
         */
        void add_mult_const_decl_len_component(uint8_t declared_length_ref_id, uint8_t constant, bool is_payload = false)
        {
            components.push_back(std::make_unique<mult_const_decl_len_component>(constant, declared_length_ref_id, is_payload));
        }

        /**
         * Creates a multiply scope by declared length component and adds it to the FFS.
         * 
         * @param declared_length_ref_id the reference ID of the declared length field
         * @param scope another FFS builder describing the scope that is executed multiple times in a row according to the declared length
         */
        void add_mult_scope_decl_len_component(uint8_t declared_length_ref_id, frame_format_specification_builder &scope)
        {
            components.push_back(std::make_unique<mult_scope_decl_len_component>(scope, declared_length_ref_id));
        }

        /**
         * Creates a backfill component and adds it to the FFS.
         * Important to node: this component must always be the last component of the FFS.
         * 
         * @param is_payload denotes if the bytes parsed by this component are part application data
         */
        void add_backfill_component(bool is_payload = false)
        {
            components.push_back(std::make_unique<backfill_component>(is_payload));
        }

    private:
        struct format_component
        {
            uint8_t ref_id;
            bool is_payload;

            format_component(uint8_t ref_id = 0, bool is_payload = false)
                : ref_id(ref_id), is_payload(is_payload)
            {
                if (ref_id > HYQUIC_REF_ID_MAX)
                    throw frame_format_spec_error("Maximum number of reference IDs reached.");
            }

            virtual inline size_t size() const = 0;
            virtual inline void encode(buffer_view &target) const = 0;
        };

        struct var_int_component : public format_component
        {
            var_int_component(uint8_t ref_id = 0, bool is_payload = false)
                : format_component(ref_id, is_payload)
            {
            }

            inline size_t size() const
            {
                return 1;
            }

            inline void encode(buffer_view &target) const
            {
                uint8_t header = ref_id | (is_payload << 4) | (HYQUIC_FRAME_FORMAT_SPEC_COMP_VAR_INT << 5);
                target.push_int<NETWORK>(header, 1);
            }
        };

        struct fix_len_component : public format_component
        {
            uint32_t length;

            fix_len_component(uint32_t length, uint8_t ref_id = 0, bool is_payload = false)
                : format_component(ref_id, is_payload), length(length)
            {
            }

            inline size_t size() const
            {
                return 1 + get_var_int_length(length);
            }

            inline void encode(buffer_view &target) const
            {
                uint8_t header = ref_id | (is_payload << 4) | (HYQUIC_FRAME_FORMAT_SPEC_COMP_FIX_LEN << 5);
                target.push_int<NETWORK>(header, 1);
                target.push_var(length);
            }
        };

        struct mult_const_decl_len_component : public format_component
        {
            uint8_t constant;

            mult_const_decl_len_component(uint8_t constant, uint8_t ref_id = 0, bool is_payload = false)
                : format_component(ref_id, is_payload), constant(constant)
            {
            }

            inline size_t size() const
            {
                return 2;
            }

            inline void encode(buffer_view &target) const
            {
                uint8_t header = ref_id | (is_payload << 4) | (HYQUIC_FRAME_FORMAT_SPEC_COMP_MULT_CONST_DECL_LEN << 5);
                target.push_int<NETWORK>(header, 1);
                target.push_int<NETWORK>(constant, 1);
            }
        };

        struct mult_scope_decl_len_component : public format_component
        {
            frame_format_specification_builder &scope;

            mult_scope_decl_len_component(frame_format_specification_builder &scope, uint8_t ref_id = 0)
                : format_component(ref_id), scope(scope)
            {
            }

            inline size_t size() const
            {
                return 2 + scope.size();
            }

            inline void encode(buffer_view &target) const
            {
                uint8_t header = ref_id | (is_payload << 4) | (HYQUIC_FRAME_FORMAT_SPEC_COMP_MULT_CONST_DECL_LEN << 5);
                target.push_int<NETWORK>(header, 1);

                size_t scope_length = scope.size();
                if (!scope_length)
                    throw frame_format_spec_error("Scope must not be empty.");
                if (scope_length >= (1 << 8))
                    throw frame_format_spec_error("Scope is too large.");

                target.push_int<NETWORK>(scope_length, 1);
                target.push_buff_into(scope.get_specification());
            }
        };

        struct backfill_component : public format_component
        {
            backfill_component(bool is_payload = false)
                : format_component(0, is_payload)
            {
            }

            inline size_t size() const
            {
                return 1;
            }

            inline void encode(buffer_view &target) const
            {
                uint8_t header = ref_id | (is_payload << 4) | (HYQUIC_FRAME_FORMAT_SPEC_COMP_BACKFILL << 5);
                target.push_int<NETWORK>(header, 1);
            }
        };

        std::vector<std::unique_ptr<format_component>> components;
        uint8_t ref_id_counter = 1;
    };

    /**
     * Creates an encoded FFS that describes an empty frame.
     * 
     * @return a buffer containing an empty FFS
     */
    inline buffer no_frame_format_specification()
    {
        return buffer();
    }

    /**
     * Creates an encoded FFS that describes a fixed length frame.
     * 
     * @param length the length of the frame
     * @return a buffer containing the FFS
     */
    inline buffer fixed_length_frame_format_specification(uint32_t length)
    {
        frame_format_specification_builder builder;
        builder.add_fix_len_component(length);
        return builder.get_specification();
    }
} // namespace hyquic

#endif // __HYQUIC_FRAME_FORMAT_SPEC_HPP__