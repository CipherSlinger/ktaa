#include <pbc.h>

#include "Zr.h"
#include "Group.h"
#include "Pairing.h"

#include <iostream>
#include <string.h>

namespace PBC
{

BP PG;

BP::BP(){
    // Do nothing: wait for setup phase
};
BP::~BP()
{
    delete this->g_G1;
    delete this->g_G2;
    delete this->g_GT;
    delete this->temp_G1;
    delete this->temp_G2;
    delete this->temp_GT;
    delete this->temp_Zr;
    pairing_clear(this->pairing);
}

void BP::Setup(int bits, PBC_LIB_CURVE type = PBC_LIB_CURVE::TYPE_F)
{
    Set_Type_F(bits);
}

/**
 * @brief Setup the bilinear pairing F type (Discovered by Barreto and Naehrig, "Pairing-friendly elliptic curves of prime order".)
 *
 * q: The curve is defined over Fq
 * r: The order of the curve.
 * b: E: y^2= x^3 + b
 * 
 * @param bits Both the group order r and the order of the base field q will be roughly bits-bit numbers.
 */
void BP::Set_Type_F(int bits)
{

    pbc_param_t param;
    pbc_param_init_f_gen(param, bits);
    pairing_init_pbc_param(this->pairing, param);
    pbc_param_clear(param);

    this->Is_Symmetric = (this->pairing->G1 == this->pairing->G2);
    this->Length_G1 = this->pairing->G1->fixed_length_in_bytes;
    this->Length_G2 = this->pairing->G2->fixed_length_in_bytes;
    this->Length_G1_x = this->pairing->G1->fixed_length_in_bytes / 2;
    this->Length_G2_x = this->pairing->G2->fixed_length_in_bytes / 2;
    this->Length_G1_Compressed = this->pairing->G1->fixed_length_in_bytes / 2 + 1;
    this->Length_G2_Compressed = this->pairing->G2->fixed_length_in_bytes / 2 + 1;
    this->Length_GT = this->pairing->GT->fixed_length_in_bytes;
    this->Length_Zr = this->pairing->Zr->fixed_length_in_bytes;

    this->g_G1 = new G1();
    element_init(g_G1->Value, this->pairing->G1);
    element_random(g_G1->Value);

    this->g_G2 = new G2();
    element_init(g_G2->Value, this->pairing->G2);
    element_random(g_G2->Value);

    this->g_GT = new GT();
    element_init(g_GT->Value, this->pairing->G2);
    element_random(g_GT->Value);

    this->temp_G1 = new G1();
    this->temp_G2 = new G2();
    this->temp_GT = new GT();
    this->temp_Zr = new Zr();
}

void BP::Set_Type_A(int rbit, int qbit)
{

    pbc_param_t param;
    pbc_param_init_a_gen(param, rbit, qbit);
    pairing_init_pbc_param(this->pairing, param);
    pbc_param_clear(param);

    this->Is_Symmetric = (this->pairing->G1 == this->pairing->G2);
    this->Length_G1 = this->pairing->G1->fixed_length_in_bytes;
    this->Length_G2 = this->pairing->G2->fixed_length_in_bytes;
    this->Length_G1_x = this->pairing->G1->fixed_length_in_bytes / 2;
    this->Length_G2_x = this->pairing->G2->fixed_length_in_bytes / 2;
    this->Length_G1_Compressed = this->pairing->G1->fixed_length_in_bytes / 2 + 1;
    this->Length_G2_Compressed = this->pairing->G2->fixed_length_in_bytes / 2 + 1;
    this->Length_GT = this->pairing->GT->fixed_length_in_bytes;
    this->Length_Zr = this->pairing->Zr->fixed_length_in_bytes;

    this->g_G1 = new G1();
    element_init(g_G1->Value, this->pairing->G1);
    element_random(g_G1->Value);

    this->g_G2 = new G2();
    element_init(g_G2->Value, this->pairing->G2);
    element_random(g_G2->Value);

    this->g_GT = new GT();
    element_init(g_GT->Value, this->pairing->G2);
    element_random(g_GT->Value);

    this->temp_G1 = new G1();
    this->temp_G2 = new G2();
    this->temp_GT = new GT();
    this->temp_Zr = new Zr();
}

void BP::Set_Type_D()
{
    const char* d159 = 
    "type d\n"
    "q 625852803282871856053922297323874661378036491717\n"
    "n 625852803282871856053923088432465995634661283063\n"
    "h 3\n"
    "r 208617601094290618684641029477488665211553761021\n"
    "a 581595782028432961150765424293919699975513269268\n"
    "b 517921465817243828776542439081147840953753552322\n"
    "k 6\n"
    "nk 60094290356408407130984161127310078516360031868417968262992864809623507269833854678414046779817844853757026858774966331434198257512457993293271849043664655146443229029069463392046837830267994222789160047337432075266619082657640364986415435746294498140589844832666082434658532589211525696\n"
    "hk 1380801711862212484403205699005242141541629761433899149236405232528956996854655261075303661691995273080620762287276051361446528504633283152278831183711301329765591450680250000592437612973269056\n"
    "coeff0 472731500571015189154958232321864199355792223347\n"
    "coeff1 352243926696145937581894994871017455453604730246\n"
    "coeff2 289113341693870057212775990719504267185772707305\n"
    "nqr 431211441436589568382088865288592347194866189652";

    pbc_param_t param;

    // Generate pairing parameters
    pbc_param_init_set_str(param, d159);
    pairing_init_pbc_param(this->pairing, param);
    pbc_param_clear(param);

    this->Is_Symmetric = (this->pairing->G1 == this->pairing->G2);
    this->Length_G1 = this->pairing->G1->fixed_length_in_bytes;
    this->Length_G2 = this->pairing->G2->fixed_length_in_bytes;
    this->Length_G1_x = this->pairing->G1->fixed_length_in_bytes / 2;
    this->Length_G2_x = this->pairing->G2->fixed_length_in_bytes / 2;
    this->Length_G1_Compressed = this->pairing->G1->fixed_length_in_bytes / 2 + 1;
    this->Length_G2_Compressed = this->pairing->G2->fixed_length_in_bytes / 2 + 1;
    this->Length_GT = this->pairing->GT->fixed_length_in_bytes;
    this->Length_Zr = this->pairing->Zr->fixed_length_in_bytes;

    this->g_G1 = new G1();
    element_init(g_G1->Value, this->pairing->G1);
    element_random(g_G1->Value);

    this->g_G2 = new G2();
    element_init(g_G2->Value, this->pairing->G2);
    element_random(g_G2->Value);

    this->g_GT = new GT();
    element_init(g_GT->Value, this->pairing->G2);
    element_random(g_GT->Value);

    this->temp_G1 = new G1();
    this->temp_G2 = new G2();
    this->temp_GT = new GT();
    this->temp_Zr = new Zr();
}
void BP::Set_Type_G()
{
    const char* g149 = 
    "type g\n"
    "q 503189899097385532598615948567975432740967203\n"
    "n 503189899097385532598571084778608176410973351\n"
    "h 1\n"
    "r 503189899097385532598571084778608176410973351\n"
    "a 465197998498440909244782433627180757481058321\n"
    "b 463074517126110479409374670871346701448503064\n"
    "k 10\n"
    "nk 1040684643531490707494989587381629956832530311976146077888095795458709511789670022388326295177424065807612879371896982185473788988016190582073591316127396374860265835641044035656044524481121528846249501655527462202999638159773731830375673076317719519977183373353791119388388468745670818193868532404392452816602538968163226713846951514831917487400267590451867746120591750902040267826351982737642689423713163967384383105678367875981348397359466338807\n"
    "hk 4110127713690841149713310614420858884651261781185442551927080083178682965171097172366598236129731931693425629387502221804555636704708008882811353539555915064049685663790355716130262332064327767695339422323460458479884756000782939428852120522712008037615051139080628734566850259704397643028017435446110322024094259858170303605703280329322675124728639532674407\n"
    "coeff0 67343110967802947677845897216565803152319250\n"
    "coeff1 115936772834120270862756636148166314916823221\n"
    "coeff2 87387877425076080433559927080662339215696505\n"
    "coeff3 433223145899090928132052677121692683015058909\n"
    "coeff4 405367866213598664862417230702935310328613596\n"
    "nqr 22204504160560785687198080413579021865783099";

    pbc_param_t param;

    // Generate pairing parameters
    pbc_param_init_set_str(param, g149);
    pairing_init_pbc_param(this->pairing, param);
    pbc_param_clear(param);

    this->Is_Symmetric = (this->pairing->G1 == this->pairing->G2);
    this->Length_G1 = this->pairing->G1->fixed_length_in_bytes;
    this->Length_G2 = this->pairing->G2->fixed_length_in_bytes;
    this->Length_G1_x = this->pairing->G1->fixed_length_in_bytes / 2;
    this->Length_G2_x = this->pairing->G2->fixed_length_in_bytes / 2;
    this->Length_G1_Compressed = this->pairing->G1->fixed_length_in_bytes / 2 + 1;
    this->Length_G2_Compressed = this->pairing->G2->fixed_length_in_bytes / 2 + 1;
    this->Length_GT = this->pairing->GT->fixed_length_in_bytes;
    this->Length_Zr = this->pairing->Zr->fixed_length_in_bytes;

    this->g_G1 = new G1();
    element_init(g_G1->Value, this->pairing->G1);
    element_random(g_G1->Value);

    this->g_G2 = new G2();
    element_init(g_G2->Value, this->pairing->G2);
    element_random(g_G2->Value);

    this->g_GT = new GT();
    element_init(g_GT->Value, this->pairing->G2);
    element_random(g_GT->Value);

    this->temp_G1 = new G1();
    this->temp_G2 = new G2();
    this->temp_GT = new GT();
    this->temp_Zr = new Zr();
}
/**
 * @brief Display the details of bilinear type.
 * 
 */
void BP::ShowParameter()
{
    std::cout << "Bilinear Type: " << (Is_Symmetric ? "Symmetric" : "Asymmetric") << std::endl;
    std::cout << "Length of G1:" << Length_G1 << " Bytes (" << Length_G1_Compressed << " Compressed Bytes)" << std::endl;
    std::cout << "Length of G2:" << Length_G2 << " Bytes (" << Length_G2_Compressed << " Compressed Bytes)" << std::endl;
    std::cout << "Length of G1 x:" << Length_G1_x << " Bytes" << std::endl;
    std::cout << "Length of G2 x:" << Length_G2_x << " Bytes" << std::endl;
    std::cout << "Length of GT:" << Length_GT << " Bytes" << std::endl;
    std::cout << "Length of Zr:" << Length_Zr << " Bytes" << std::endl;

    std::cout << "Generators:" << std::endl
              << "G1:" << PG.g_G1->ToString() << std::endl
              << "G2:" << PG.g_G2->ToString() << std::endl
              << "GT:" << PG.g_GT->ToString() << std::endl;
}

/**
 * @brief Generate a new random G1 element.
 * 
 * @return G1 
 */
G1 BP::random_G1()
{
    G1 g;
    element_init(g.Value, this->pairing->G1);
    element_random(g.Value);
    return g;
}
/**
 * @brief Generate a new random G2 element.
 * 
 * @return G2 
 */
G2 BP::random_G2()
{
    G2 g;
    element_init(g.Value, this->pairing->G2);
    element_random(g.Value);
    return g;
}
/**
 * @brief Generate a new random GT element.
 * 
 * @return GT 
 */
GT BP::random_GT()
{
    GT g;
    element_init(g.Value, this->pairing->GT);
    element_random(g.Value);
    return g;
}
/**
 * @brief Generate a new random integer.
 * 
 * @return Zr
 */
Zr BP::random_Zr()
{
    Zr z;
    element_init(z.Value, this->pairing->Zr);
    element_random(z.Value);
    return z;
}

void BP::random_G1(G1 *g, int num)
{
    for (int i = 0; i != num; i++)
    {
        element_random((g + i)->Value);
    }
}
void BP::random_G2(G2 *g, int num)
{
    for (int i = 0; i != num; i++)
    {
        element_random((g + i)->Value);
    }
}
void BP::random_GT(GT *g, int num)
{
    for (int i = 0; i != num; i++)
    {
        element_random((g + i)->Value);
    }
}

G1 BP::BytesToG1(unsigned char *buf, int num)
{
    G1 g;
    element_from_hash(g.Value, buf, num);
    return g;
}
G2 BP::BytesToG2(unsigned char *buf, int num)
{
    G2 g;
    element_from_hash(g.Value, buf, num);
    return g;
}
GT BP::BytesToGT(unsigned char *buf, int num)
{
    GT g;
    element_from_hash(g.Value, buf, num);
    return g;
}
Zr BP::BytesToZr(unsigned char *buf, int num)
{
    Zr g;
    element_from_hash(g.Value, buf, num);
    return g;
}

GT BP::e(const G1 &g, const G1 &h)
{
    GT result;
    element_pairing(result.Value, const_cast<G1 &>(g).Value, const_cast<G1 &>(h).Value);
    return result;
}


GT BP::e(const G1 &g, const G2 &h)
{
    GT result;
    element_pairing(result.Value, const_cast<G1 &>(g).Value, const_cast<G2 &>(h).Value);
    return result;
}

/*
GT BP::e_prod(G1 *g, G2 *h, int num)
{
    element_t gt[num], ht[num];
    for (int i = 0; i != num; i++)
    {
        element_init_same_as(gt[i], g[0].Value);
        element_init_same_as(ht[i], h[0].Value);
        element_set(gt[i], g[i].Value);
        element_set(ht[i], h[i].Value);
    }
    GT result;
    element_prod_pairing(result.Value, gt, ht, num);
    return result;
}
*/
} // namespace PBC