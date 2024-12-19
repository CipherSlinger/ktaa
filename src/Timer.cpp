#include "Timer.h"

namespace PBC
{
    void Timer::Start()
    {
        this->duration = 0;
        this->current_clock = clock();
    }

    void Timer::Stop()
    {
        this->duration += (clock() - current_clock);
    }

    void Timer::Clear()
    {
        this->duration = 0;
    }

    double Timer::GetSecond()
    {
        return this->duration / (double)CLOCKS_PER_SEC;
    }

    double Timer::GetMillisecond()
    {
        return this->duration / (double)CLOCKS_PER_SEC * 1000;
    }
}