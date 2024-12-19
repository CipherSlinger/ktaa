#pragma once

#include <ctime>

namespace PBC
{
    
class Timer
{
    private:
    std::clock_t current_clock;
    std::clock_t duration;

    public:
    /**
     * @brief Start
     * 
     */
    void Start();
    /**
     * @brief Stop/Pause
     * 
     */
    void Stop();
    /**
     * @brief Set the time to 0
     * 
     */
    void Clear();
    /**
     * @brief Get the Second result
     * 
     * @return double 
     */
    double GetSecond();
    /**
     * @brief Get the Millisecond result
     * 
     * @return double 
     */
    double GetMillisecond();
};

}