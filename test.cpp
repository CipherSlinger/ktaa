#include "pbc++.h"
#include "Timer.h"

#include <iostream>
#include <string>


using namespace std;
using namespace SHA;
using namespace PBC;

int main()
{

    Timer timing;
    // PG.Set_Type_F(160);
    PG.Set_Type_A(160, 512);
    // PG.Set_Type_D();
    PG.ShowParameter();

    G1 g = PG.random_G1();
    G2 h = PG.random_G2();
    Zr ex = PG.random_Zr();
    GT gt;

    int t = 100;
    timing.Clear();
    timing.Start();
    for (int i = 0; i < t; i++)
    {
        gt = PG.e(g, h);
    }
    timing.Stop();
    cout << "\nTime for e(g, h): " << timing.GetMillisecond() / t << endl;

    Zr a = PG.random_Zr();
    Zr b = PG.random_Zr();
    G1 ga, ga1, ga2;
    G2 ha;

    G1 G1_indentity = G1::Get_Identity();

    ga = g^(-a);
    ga1 = g^a;
    ga2 = ga * ga1;
    cout << (ga2 == G1_indentity ? "Valid" : "Invalid") << endl;

    b = a ^ (-2);
    Zr ab, identity;
    ab = (a ^ 2) * b;
    identity = Zr::Get_Identity();
    cout << (ab == identity ? "Valid" : "Invalid") << endl;

    GT gt1, gt2;
    gt1 = PG.e(ga, h);
    gt2 = (PG.e(g, h)^(-a));
    cout << (gt1 == gt2 ? "Valid" : "Invalid") << endl;

    ha = h^((-a)^-1);
    gt1 = PG.e(ga, ha);
    gt2 = PG.e(g, h);
    cout << (gt1 == gt2 ? "Valid" : "Invalid") << endl;

    return 0;
}

