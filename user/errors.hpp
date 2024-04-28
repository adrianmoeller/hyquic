#ifndef __HYQUIC_ERRORS_HPP__
#define __HYQUIC_ERRORS_HPP__

#include <iostream>

namespace hyquic
{
    class error : public std::exception
    {
    public:
        explicit error(std::string msg)
            : msg(msg)
        {
        }

        explicit error(std::string msg, int err_no)
            : msg(std::string(strerror(err_no)) + ": " + msg)
        {
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