#ifndef __HYQUIC_DEBUG_HPP__
#define __HYQUIC_DEBUG_HPP__

#include <iostream>
#include <chrono>
#include <source_location>

using namespace std;

inline void pr_pos(const source_location loc = source_location::current())
{
    const auto now = chrono::system_clock::now().time_since_epoch();
    cout << chrono::duration_cast<chrono::milliseconds>(now).count();
    cout << " " << loc.file_name() << ":" << loc.line() << "@" << loc.function_name() << endl;
}

#endif // __HYQUIC_DEBUG_HPP__