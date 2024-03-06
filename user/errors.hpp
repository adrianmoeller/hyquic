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
} // namespace hyquic


#endif // __HYQUIC_ERRORS_HPP__