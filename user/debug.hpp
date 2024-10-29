/* SPDX-License-Identifier: GPL-2.0+ */
/* HyQUIC - A hybrid user-kernel QUIC implementation 
 * based on the QUIC kernel implementation by Xin Long.
 * Copyright (C) 2024  Adrian Moeller
 * 
 * Written or modified by:
 * 	   Adrian Moeller
 */

#ifndef __HYQUIC_DEBUG_HPP__
#define __HYQUIC_DEBUG_HPP__

#include <iostream>
#include <chrono>
#include <source_location>
#include <string>
#include <mutex>
#include <boost/algorithm/string.hpp>

using namespace std;

namespace hq_debug
{
    static mutex mut;   
} // namespace debug

inline void pr_pos(string msg = string(), const source_location loc = source_location::current())
{
    const auto now = chrono::system_clock::now().time_since_epoch();
    string func_name(loc.function_name());
    boost::algorithm::replace_all(func_name, "hyquic::", "");

    std::lock_guard<std::mutex> lock(hq_debug::mut);
    cout << chrono::duration_cast<chrono::milliseconds>(now).count();
    cout << " " << loc.file_name() << ":" << loc.line() << "@" << func_name << " | " << msg << endl;
}

#endif // __HYQUIC_DEBUG_HPP__