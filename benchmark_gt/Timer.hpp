#ifndef SYMRLWE_TIMER_HPP
#define SYMRLWE_TIMER_HPP
#include <chrono>

using std::chrono::duration_cast;
typedef std::chrono::nanoseconds Time_t;
typedef std::chrono::high_resolution_clock Clock;
double time_as_second(const Time_t &t) { return t.count() / 1.0e9; }
double time_as_millsecond(const Time_t &t) { return t.count() / 1.0e6; }

#endif //SYMRLWE_TIMER_HPP
