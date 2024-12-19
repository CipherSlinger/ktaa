#pragma once

#include "Zr.h"
#include "Group.h"
#include "SHA256.h"

namespace PBC
{

/**
 * @brief Bilinear group tpye from pbc lib (A to G)
 * 
 */
enum PBC_LIB_CURVE
{
     TYPE_A,
     TYPE_B,
     TYPE_C,
     TYPE_D,
     TYPE_E,
     TYPE_F,
     TYPE_G
};

/*
    Bilinear pairing description
*/
class BP
{
public:
     pairing_t pairing;

     G1 *g_G1; /// Generator of G1
     G2 *g_G2; /// Generator of G2
     GT *g_GT; /// Generator of GT

     G1 *temp_G1;
     G2 *temp_G2;
     GT *temp_GT;
     Zr *temp_Zr;

     BP();
     ~BP();

     /**
 * @brief System parameter setup.
 * 
 * @param bits Security bits
 * @param type Curve Types from PBC library (PBC_LIB_CURVE.TYPE_A~TYPE_G)
 */
     void Setup(int bits, PBC_LIB_CURVE type);

     /**
     * @brief Set the curve as F type curve in pbc library.
     * 
     * @param bits Security bits (e.g. bits = 160).
     */
     void Set_Type_F(int bits);

     void Set_Type_A(int rbit, int qbit);

    void Set_Type_D();
    void Set_Type_G();
     
     bool Is_Symmetric;///Symmetric or Asymmetric pairing.
     int Length_G1;///Size of G1.
     int Length_G2;///Size of G2.
     int Length_G1_Compressed;///Size of compressed G1.
     int Length_G2_Compressed;///Size of Compressed G2.
     int Length_G1_x;///Size of x ordinary of G1.
     int Length_G2_x;///Size of x ordinary of G2.
     int Length_GT;///Size of x ordinary of GT.
     int Length_Zr;///Size of x ordinary of Zr.

     /**
         * @brief Print the parameters of pairing.
         * */
     void ShowParameter();

     /**
         * @brief Generate a random element from G1.
         * */
     G1 random_G1();
     /**
         * @brief Generate a random element from G2.
         * */
     G2 random_G2();
     /**
         * @brief Generate a random element from GT.
         * */
     GT random_GT();
     /**
         * @brief Generate a random element from Zr.
         * */
     Zr random_Zr();
     //Generate random group element array
     void random_G1(G1 *g, int num);
     void random_G2(G2 *g, int num);
     void random_GT(GT *g, int num);

     /**
      * @brief Mapping bytes to G1 element.
      * 
      * @param buf data array
      * @param len length of data array (bytes)
      * @return G1
      */
     G1 BytesToG1(unsigned char *buf, int len);
          /**
      * @brief Mapping bytes to G2 element.
      * 
      * @param buf data array
      * @param len length of data array (bytes)
      * @return G2 
      */
     G2 BytesToG2(unsigned char *buf, int len);
          /**
      * @brief Mapping bytes to GT element.
      * 
      * @param buf data array
      * @param len length of data array (bytes)
      * @return GT
      */
     GT BytesToGT(unsigned char *buf, int len);
          /**
      * @brief Mapping bytes to G1 element.
      * 
      * @param buf data array
      * @param len length of data array (bytes)
      * @return Zr
      */
     Zr BytesToZr(unsigned char *buf, int len);

     //Generate random group element vector
     //Vector<G1> random_G1(int num);
     //Vector<G1> random_G2(int num);
     //Vector<G1> random_GT(int num);

     /**
     * @brief Perform the bilinear pairing
     * 
     * @param g G1 element.
     * @param h G2 element.
     * @return e(g, h)
     */
     GT e(const G1 &g, const G2 &h);


     GT e(const G1 &g, const G1 &h);
};

extern BP PG;
} // namespace PBC