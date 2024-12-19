#include <pbc.h>
#include "Zr.h"
#include "Pairing.h"

#include <string.h>
#include <iostream>

namespace PBC
{

    extern BP PG;

    Zr::Zr()
    {
        this->isEmpty = true;
        this->type = PG.pairing->Zr;
        element_init(this->Value, this->type);
    }
    Zr::Zr(const Zr &h)
    {
        this->isEmpty = false;
        this->type = PG.pairing->Zr;
        element_init(this->Value, this->type);
        element_set(this->Value, const_cast<Zr &>(h).Value);
    }
    Zr::Zr(signed long num)
    {
        this->isEmpty = false;
        this->type = PG.pairing->Zr;
        element_init(this->Value, this->type);
        element_set_si(this->Value, num);
    }
    Zr::~Zr()
    {
        //std::cout<< "clearing Zr " << ++Zr::Num_system << " : "<< this->ToString() << std::endl;
        this->type = NULL;
        element_clear(this->Value);
    }
    Zr Zr::Get_Identity()
    {
        Zr identity;
        element_set1(identity.Value);
        return identity;
    }

    static Zr Get_Zero()
    {
        Zr zero;
        element_set0(zero.Value);
        return zero;
    }

    void Zr::Set1()
    {
        element_set1(this->Value);
        this->isEmpty = false;
    }
    void Zr::Set0()
    {
        element_set0(this->Value);
        this->isEmpty = false;
    }
    void Zr::Set(unsigned long num)
    {
        element_set_si(this->Value, num);
        this->isEmpty = false;
    }
    void Zr::Set(const Zr &h)
    {
        element_set(this->Value, const_cast<Zr &>(h).Value);
        this->isEmpty = false;
    }

    void Zr::Set_From_Hash(unsigned char *data, long long int len)
    {
        unsigned char buf[64];

        SHA::sha256(buf, data, len);
        element_from_hash(this->Value, buf, 64);
        this->isEmpty = false;
    }

    int Zr::ToBytes(unsigned char *buf)
    {
        return element_to_bytes(buf, this->Value);
    }
    std::string Zr::ToString()
    {
        char temp[4 * this->type->fixed_length_in_bytes];
        element_snprint(temp, sizeof(temp), this->Value);
        return std::string(temp);
    }
    void Zr::Print()
    {
        element_printf("%B\n", this->Value);
    }

    bool Zr::IsQR()
    {
        return (element_is_sqr(this->Value) != 0);
    }
    bool Zr::operator==(const Zr &h)
    {
        return !element_cmp(this->Value, const_cast<Zr &>(h).Value);
    }
    bool Zr::operator==(const signed long num)
    {
        switch (num)
        {
        case 0:
            return element_is0(this->Value);

        case 1:
            return element_is1(this->Value);

        default:
            PG.temp_Zr->Set(num);
            int result = !element_cmp(this->Value, PG.temp_Zr->Value);
            return result;
        }
    }
    bool Zr::operator!=(const Zr &h)
    {
        return element_cmp(this->Value, const_cast<Zr &>(h).Value);
    }
    bool Zr::operator!=(const signed long num)
    {   
        switch (num)
        {
        case 0:
            return !element_is0(this->Value);

        case 1:
            return !element_is1(this->Value);

        default:
            PG.temp_Zr->Set(num);
            int result = element_cmp(this->Value, PG.temp_Zr->Value);
            return result;
        }
    }
    Zr Zr::operator+(const Zr &h)
    {
        Zr result;
        element_add(result.Value, this->Value, const_cast<Zr &>(h).Value);
        return result;
    }
    Zr Zr::operator+(const signed long num)
    {
        Zr result;
        element_set_si(PG.temp_Zr->Value, num);
        element_add(result.Value, this->Value, PG.temp_Zr->Value);
        return result;
    }
    Zr operator+(signed long num, const Zr &h)
    {
        Zr result;
        element_add(result.Value, const_cast<Zr &>(h).Value, PG.temp_Zr->Value);
        return result;
    }
    Zr Zr::operator-(const Zr &h)
    {
        Zr result;
        element_sub(result.Value, this->Value, const_cast<Zr &>(h).Value);
        return result;
    }
    Zr Zr::operator-(const signed long num)
    {
        Zr result;
        PG.temp_Zr->Set(num);
        element_sub(result.Value, this->Value, PG.temp_Zr->Value);
        return result;
    }
    Zr operator-(signed long num, const Zr &h)
    {
        Zr result;
        PG.temp_Zr->Set(num);
        element_sub(result.Value, const_cast<Zr &>(h).Value, PG.temp_Zr->Value);
        return result;
    }
    Zr Zr::operator-()
    {
        Zr result;
        element_neg(result.Value, this->Value);
        return result;
    }
    Zr Zr::operator*(const Zr &h)
    {
        Zr result;
        element_mul_zn(result.Value, this->Value, const_cast<Zr &>(h).Value);
        return result;
    }
    Zr Zr::operator*(const signed long num)
    {  
        Zr result;
        element_mul_si(result.Value, this->Value, num);
        return result;
    }
    Zr operator*(const signed long num, const Zr &h)
    {
        Zr result;
        element_mul_si(result.Value, const_cast<Zr &>(h).Value, num);
        return result;
    }
    Zr Zr::operator/(const Zr &h)
    {
        Zr result;
        element_div(result.Value, this->Value, const_cast<Zr &>(h).Value);
        return result;
    }
    Zr Zr::operator/(const unsigned long c)
    {
        Zr result;
        element_set_si(PG.temp_Zr->Value, c);
        element_div(result.Value, this->Value, PG.temp_Zr->Value);
        return result;
    }
    Zr operator/(const signed long num, const Zr &h)
    {
        switch (num)
        {
        case 1:
        {
            Zr result;
            element_invert(result.Value, const_cast<Zr &>(h).Value);
            return result;
        }

        default:
        {
            Zr result(num);
            element_div(result.Value, result.Value, const_cast<Zr &>(h).Value);
            return result;
        }
        }
    }
    Zr Zr::operator^(const Zr &pow)
    {
        Zr result;
        element_pow_zn(result.Value, this->Value, const_cast<Zr &>(pow).Value);
        return result;
    }
    Zr Zr::operator^(const signed long int &pow)
    {
        Zr result;
        if (pow < 0)
        {
            switch (pow)
            {
            case -1:
                element_invert(result.Value, this->Value);
                return result;
            case -2:
                element_invert(result.Value, this->Value);
                element_square(result.Value, result.Value);
                return result;
            default:
                element_invert(result.Value, this->Value);
                Zr r(-pow);
                element_pow_zn(result.Value, result.Value, r.Value);
                return result;
            }
        }
        else
        {
            switch (pow)
            {
                case 2:
                {
                    element_square(result.Value, this->Value);
                    return result;
                }
                default:
                {
                    Zr r(pow);
                    element_pow_zn(result.Value, this->Value, r.Value);
                    return result;
                }
        }
        }
    }
    Zr operator^(const signed long num, const Zr &h)
    {
        Zr result;
        element_set_si(PG.temp_Zr->Value, num);
        element_pow_zn(result.Value, PG.temp_Zr->Value, const_cast<Zr &>(h).Value);
        return result;
    }
    Zr &Zr::operator=(const Zr &h)
    {
        element_set(this->Value, const_cast<Zr &>(h).Value);
        return *this;
    }
    Zr &Zr::operator=(const signed long num)
    {
        element_set_si(this->Value, num);
        return *this;
    }
    Zr &Zr::operator+=(const Zr &h)
    {
        element_add(this->Value, this->Value, const_cast<Zr &>(h).Value);
        return *this;
    }
    Zr &Zr::operator+=(const signed long num)
    {
        Zr result(num);
        element_add(this->Value, this->Value, result.Value);
        return *this;
    }
    Zr &Zr::operator-=(const Zr &h)
    {
        element_sub(this->Value, this->Value, const_cast<Zr &>(h).Value);
        return *this;
    }
    Zr &Zr::operator-=(const signed long num)
    {
        Zr result(num);
        element_sub(this->Value, this->Value, result.Value);
        return *this;
    }
    Zr &Zr::operator*=(const Zr &h)
    {
        element_mul_zn(this->Value, this->Value, const_cast<Zr &>(h).Value);
        return *this;
    }
    Zr &Zr::operator*=(const signed long num)
    {
        element_mul_si(this->Value, this->Value, num);
        return *this;
    }
    Zr &Zr::operator/=(const Zr &h)
    {
        element_div(this->Value, this->Value, const_cast<Zr &>(h).Value);
        return *this;
    }
    Zr &Zr::operator/=(const signed long num)
    {
        Zr result(num);
        element_div(this->Value, this->Value, result.Value);
        return *this;
    }
    // Override << operation
    std::ostream &operator<<(std::ostream &os, Zr &h)
    {
        os << h.ToString();
        return os;
    }
}
