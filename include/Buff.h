#pragma once

#include <pbc>
#include <vector>

namespace PBC
{
class Buff
{
private:
    unsigned char *data;

    vector<unsigned char> buf;
    char* begin;
    char* end;

public:
    Buff(/* args */);
    ~Buff();

    /**
     * @return The size of all padding data
     */
    int GetSize();
    /**
     * @brief Pad the data to the buffer.
     * 
     * @param data binary sting to be padded.
     * @param length Length of array data.
     */
    void Append(unsigned char *data, int length);
    /**
     * @brief Pad a pbc element to the buffer.
     * 
     * @param g A group element (G1, G2, GT or Zr).
     */
    void Append(Element g);
    /**
     * @brief Clear the buff.
     * 
     */
    void Clear();
};

Buff::Buff(/* args */)
{
}

Buff::~Buff()
{
    delete this->buf;
    this->buf = nullptr;
}
} // namespace PBC
