#include <pbc.h>

#include "Group.h"
#include "Pairing.h"

#include <string.h>
#include <iostream>

namespace PBC
{

    extern BP PG;

    Element::Element()
    {
        this->IsAlive = false;
        this->IsEmpty = true;
        this->type = nullptr;
    }
    Element::Element(field_ptr type)
    {
        this->IsAlive = true;
        this->IsEmpty = false;
        this->type = type;
        element_init(this->Value, type);
    }
    Element::Element(const Element& h)
    {
        this->IsAlive = true;
        this->IsEmpty = h.IsEmpty;
        this->type = h.type;
        if (this->type != nullptr) {
            element_init(this->Value, h.type);
            if (!h.IsEmpty) {
                element_set(this->Value, const_cast<Element&>(h).Value);
            }
        }
    }
    Element::~Element()
    {
        if (this->IsAlive) {
            element_clear(this->Value);
            this->IsAlive = false;
        }
    }

    Element& Element::operator=(const Element& h)
    {
        if (this != &h) {  // Self-assignment check
            if (this->IsAlive) {
                element_clear(this->Value);
            }
            this->type = h.type;
            this->IsEmpty = h.IsEmpty;
            this->IsAlive = true;
            element_init(this->Value, h.type);
            if (!h.IsEmpty) {
                element_set(this->Value, const_cast<Element&>(h).Value);
            }
        }
        return *this;
    }

    
    Element Element::Get_Identity()
    {
        Element identity;
        element_set1(identity.Value);
        return identity;
    }

    
    // static Element Get_Zero()
    // {
    //     Element zero;
    //     element_set0(zero.Value);
    //     return zero;
    // }

    // void Element::Set1()
    // {
    //     element_set1(this->Value);
    // }
    // void Element::Set0()
    // {
    //     element_set0(this->Value);
    // }

    // void Element::Set(const Element& h)
    // {
    //     element_set(this->Value, const_cast<Element&>(h).Value);
    //     this->isAlive = true;
    //     this->isEmpty = false;
    // }

    void Element::Set_From_Hash(const unsigned char *data, int len)
    {
        unsigned char buf[32];
        SHA::sha256(buf, data, len);
        element_from_hash(this->Value, buf, 32);
    }

    int Element::ToBytes(unsigned char *buf, bool compressed)
    {
        if(!compressed)
            return element_to_bytes(buf, this->Value);
        else
            return element_to_bytes_compressed(buf, this->Value);
    }
    std::string Element::ToString()
    {
        if (!this->IsAlive || this->IsEmpty || this->type == nullptr) {
            return "Empty Element";
        }
        
        char temp[4 * this->type->fixed_length_in_bytes];
        element_snprint(temp, sizeof(temp), this->Value);
        std::string result = temp;
        if (result.empty()) {
            return "Invalid Element";
        }
        return result;
    }
    void Element::Print()
    {
        element_printf("%B\n", this->Value);
    }

    bool Element::operator==(const Element &h)
    {
        return !element_cmp(this->Value, const_cast<Element &>(h).Value);
    }
    Element Element::operator+(const Element &h)
    {
        Element result(this->type);
        element_add(result.Value, this->Value, const_cast<Element &>(h).Value);
        return result;
    }
    Element Element::operator-(const Element &h)
    {
        Element result(this->type);
        element_sub(result.Value, this->Value, const_cast<Element &>(h).Value);
        return result;
    }
    Element Element::operator-()
    {
        Element result(this->type);
        element_neg(result.Value, this->Value);
        return result;
    }
    Element Element::operator*(const Element &h)
    {
        Element result(this->type);
        element_mul(result.Value, this->Value, const_cast<Element &>(h).Value);
        return result;
    }
    Element Element::operator*(const signed long c)
    {
        Element result(this->type);
        element_mul_si(result.Value, this->Value, c);
        return result;
    }
    Element operator*(const signed long c, const Element &h)
    {
        Element result(h.type);
        element_mul_si(result.Value, const_cast<Element &>(h).Value, c);
        return result;
    }
    Element Element::operator*(const Zr &num)
    {
        Element result(this->type);
        element_mul_zn(result.Value, this->Value, const_cast<Zr &>(num).Value);
        return result;
    }
    Element operator*(const Zr &num, const Element &h)
    {
        Element result(h.type);
        element_mul_zn(result.Value, const_cast<Element &>(h).Value, const_cast<Zr &>(num).Value);
        return result;
    }

    Element Element::operator/(const Element &h)
    {
        Element result(this->type);
        element_div(result.Value, this->Value, const_cast<Element &>(h).Value);
        return result;
    }
    Element Element::operator/(const unsigned long num)
    {
        Element result(this->type);
        element_t r;
        element_init(r, PG.pairing->Zr);
        element_set_si(r, num);
        element_div(result.Value, this->Value, r);
        element_clear(r);
        return result;
    }
    Element Element::operator/(const Zr &num)
    {
        Element result(this->type);
        element_div(result.Value, this->Value, const_cast<Zr &>(num).Value);
        return result;
    }
    Element Element::operator^(const signed long int &pow)
    {
        Element result(this->type);
        if (pow < 0)
        {
            switch (pow)
            {
                case -1:
                    element_invert(result.Value, this->Value);
                    break;
                case -2:
                    element_invert(result.Value, this->Value);
                    element_square(result.Value, result.Value);
                    break;
                default:
                    element_t r;
                    element_init(r, PG.pairing->Zr);
                    element_set_si(r, -pow);
                    element_pow_zn(result.Value, this->Value, r);
                    element_clear(r);
                        break;
            }
        }
        else
        {
            switch (pow)
            {
                case 2:
                    element_square(result.Value, this->Value);
                    break;
                default:
                    element_t r;
                    element_init(r, PG.pairing->Zr);
                    element_set_si(r, pow);
                    element_pow_zn(result.Value, this->Value, r);
                    element_clear(r);
                        break;
            }
        }
        return result;
    }
    Element Element::operator^(const Zr &pow)
    {
        Element result(this->type);
        element_pow_zn(result.Value, this->Value, const_cast<Zr &>(pow).Value);
        return result;
    }
    Element &Element::operator+=(const Element &h)
    {
        element_add(this->Value, this->Value, const_cast<Element &>(h).Value);
        return *this;
    }
    Element &Element::operator-=(const Element &h)
    {
        element_sub(this->Value, this->Value, const_cast<Element &>(h).Value);
        return *this;
    }
    Element &Element::operator*=(const Element &h)
    {
        element_mul(this->Value, this->Value, const_cast<Element &>(h).Value);
        return *this;
    }
    Element &Element::operator/=(const Element &h)
    {
        element_div(this->Value, this->Value, const_cast<Element &>(h).Value);
        return *this;
    }
    // Override << operation
    std::ostream &operator<<(std::ostream &os, Element &h)
    {
        os << h.ToString();
        return os;
    }
    std::istream &operator>>(std::istream &is, Element &h)
    {
        is >> h;
        return is;
    }

    //----------------Definition of Group Elements------------

    G1::G1() : Element(PG.pairing->G1) 
    {
        this->IsEmpty = false;
    }

    G1::G1(const Element& h) : Element(PG.pairing->G1)
    {
        element_set(this->Value, const_cast<Element&>(h).Value);
        this->IsEmpty = h.IsEmpty;
    }

    G1 &G1::operator=(const Element& h)
    {
        element_set(this->Value, const_cast<Element &>(h).Value);
        return *this;
    }
    G1 G1::Get_Identity()
    {
        G1 identity;
        element_set1(identity.Value);
        return identity;
    }

    G2::G2() : Element(PG.pairing->G2) 
    {
        this->IsEmpty = false;
    }
    G2 &G2::operator=(const Element& h)
    {
        element_set(this->Value, const_cast<Element &>(h).Value);
        return *this;
    }
    G2 G2::Get_Identity()
    {
        G2 identity;
        element_set1(identity.Value);
        return identity;
    }
    GT::GT() : Element(PG.pairing->GT) 
    {
        this->IsEmpty = false;
    }
    GT::GT(const Element& h) : Element(PG.pairing->GT)
    {
        element_set(this->Value, const_cast<Element&>(h).Value);
        this->IsEmpty = h.IsEmpty;
    }
    GT &GT::operator=(const Element& h)
    {
        element_set(this->Value, const_cast<Element &>(h).Value);
        return *this;
    }
    GT GT::Get_Identity()
    {
        GT identity;
        element_set1(identity.Value);
        return identity;
    }

    G2::G2(const Element& h) : Element(PG.pairing->G2)
    {
        element_set(this->Value, const_cast<Element&>(h).Value);
        this->IsEmpty = h.IsEmpty;
    }
}
