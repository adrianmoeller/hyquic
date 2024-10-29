/* SPDX-License-Identifier: GPL-2.0+ */
/* HyQUIC - A hybrid user-kernel QUIC implementation 
 * based on the QUIC kernel implementation by Xin Long.
 * Copyright (C) 2024  Adrian Moeller
 * 
 * Written or modified by:
 * 	   Adrian Moeller
 */

#ifndef __HYQUIC_ERRORS_HPP__
#define __HYQUIC_ERRORS_HPP__

#include <iostream>
#include <variant>
#include <boost/stacktrace.hpp>

namespace hyquic
{
    template <typename R>
    using err_res = std::variant<R, int>;

    template <typename R>
    inline bool is_err(err_res<R> &res)
    {
        return std::holds_alternative<int>(res);
    }

    template <typename R>
    inline bool is_val(err_res<R> &res)
    {
        return std::holds_alternative<R>(res);
    }

    template <typename R>
    inline int get_err(err_res<R> &res)
    {
        return std::get<int>(res);
    }

    template <typename R>
    inline R get_val(err_res<R> &res)
    {
        return std::get<R>(res);
    }

    class error : public std::exception
    {
    public:
        explicit error(std::string msg)
            : msg(msg)
        {
            std::cerr << boost::stacktrace::stacktrace() << std::endl;
        }

        explicit error(std::string msg, int err_no)
            : msg(std::string(strerror(err_no)) + ": " + msg)
        {
            std::cerr << boost::stacktrace::stacktrace() << std::endl;
        }

        inline const char* what() const noexcept
        {
            return msg.c_str();
        }

    private:
        const std::string msg;
    };

    class extension_config_error : public error
    {
        using error::error;
    };

    class invalid_data_error : public error
    {
        using error::error;
    };

    class network_error : public error
    {
        using error::error;
    };

    class frame_format_spec_error : public error
    {
        using error::error;
    };

    class buffer_error : public error
    {
        using error::error;
    };

    class internal_error : public error
    {
        using error::error;
    };
} // namespace hyquic


#endif // __HYQUIC_ERRORS_HPP__