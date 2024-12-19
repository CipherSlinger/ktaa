#pragma once

#include <pbc.h>
#include <ostream>

namespace PBC
{
    
class Zr
{
    private:
    field_ptr type;

    public:
    element_t Value;
    bool isEmpty;
    static int Num_system;

    //-------Constructor & Deconstructor-----------
    Zr();
    Zr(const Zr& h);
    Zr(signed long num);
    ~Zr();

    static Zr Get_Identity();
    static Zr Get_Zero();
    void Set0();
    void Set1();
    void Set(unsigned long num);
    void Set(const Zr& h);
    void Set_From_Hash(unsigned char *data, long long int len);

    //---------Output------------------
    int ToBytes(unsigned char*);
    std::string ToString();
    void Print();
    
    bool IsQR();
    //---------Override operators -----------
    bool operator==(const Zr& h);
    bool operator==(const signed long num);
    bool operator!=(const Zr& h);
    bool operator!=(const signed long num);
    //
    Zr operator+(const Zr& h);
    Zr operator+(const signed long num);
    friend Zr operator+(const signed long num, const Zr&h);
    Zr operator-(const Zr& h);
    Zr operator-(const signed long num);
    friend Zr operator-(const signed long num, const Zr&h);
    Zr operator-();
    Zr operator*(const Zr& h);
    Zr operator*(const signed long num);
    friend Zr operator*(const signed long num, const Zr& h);
    Zr operator/(const Zr& h);
    Zr operator/(const unsigned long num);
    friend Zr operator/(const signed long num, const Zr& h);
    Zr operator^(const Zr& pow);
    Zr operator^(const signed long int& pow);
    friend Zr operator^(const signed long num, const Zr& h);
    //
    Zr& operator=(const Zr& h);
    Zr& operator=(const signed long num);
    Zr& operator+=(const Zr&h);
    Zr& operator+=(const signed long num);
    Zr& operator-=(const Zr&h);
    Zr& operator-=(const signed long num);
    Zr& operator*=(const Zr&h);
    Zr& operator*=(const signed long num);
    Zr& operator/=(const Zr&h);
    Zr& operator/=(const signed long num);

    // Override << operation
    friend std::ostream & operator << (std::ostream &os, Zr& h);
};

}