#pragma once

#include "Zr.h"
#include <ostream>

namespace PBC{
class Element
{
    friend class BP;
    private:
    bool IsAlive;
    field_ptr type;

    protected:

    public:
    element_t Value; /// Element_t type from pbc lib
    bool IsEmpty; /// Check for initiazation

    //-------Constructor & Deconstructor-----------
    Element();
    Element(field_ptr type);
    Element(const Element& h);
    virtual ~Element();

    static Element Get_Identity();
    static Element Get_Zero();
    //void Set0();
    //void Set1();
    //void Set(const Element& h);
    void Set_From_Hash(const unsigned char *data, int len);

    //---------Output------------------
    int ToBytes(unsigned char* buf, bool compressed = false);
    std::string ToString();
    void Print();
    
    //---------Override operators -----------
    bool operator==(const Element& h);
    Element operator+(const Element& h);
    Element operator-(const Element& h);
    Element operator-();
    Element operator*(const Element& h);
    Element operator*(const signed long c);
    friend Element operator*(const signed long c, const Element& h);
    Element operator*(const Zr& num);
    friend Element operator*(const Zr& num, const Element& h);
    Element operator/(const Element& h);
    Element operator/(const unsigned long num);
    Element operator/(const Zr& num);
    Element operator^(const signed long int& pow);
    Element operator^(const Zr& pow);
    Element& operator=(const Element& h);
    Element& operator+=(const Element&h);
    Element& operator-=(const Element&h);
    Element& operator*=(const Element&h);
    Element& operator/=(const Element&h);

    // Override << operation
    friend std::ostream & operator << (std::ostream &os, Element& h);
    friend std::istream & operator >> (std::istream &is, const Element& h);
};

    class G1 : public Element
    {
        public:
        friend class BP;
        G1();
        G1(const Element& h);
        G1& operator=(const Element& h);
        static G1 Get_Identity();
    };

    class G2 : public Element
    {
        public:
        friend class BP;
        G2();
        G2(const Element& h);
        G2& operator=(const Element& h);
        static G2 Get_Identity();
    };

    class GT : public Element
    {
        public:
        friend class BP;
        GT();
        GT(const Element& h);
        GT& operator=(const Element& h);
        static GT Get_Identity();
    };
}