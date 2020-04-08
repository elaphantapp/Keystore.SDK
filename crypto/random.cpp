
#include "random.h"
#include <random>

uint8_t getRandomByte()
{
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    auto dice = std::bind(dis, gen);
    return dice();
}


