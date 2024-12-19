#include "pbc++.h"
#include "Timer.h"

#include <sys/resource.h>
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>

using namespace std;
using namespace SHA;
using namespace PBC;

long printMemoryUsage() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
	return usage.ru_maxrss;
}

#define pathchsize 711

struct grantproof
{	// total: 260 + 140 = 400 bytes	
public:
	// G1: 65 * 4 bytes	= 260 bytes	
	G1 alpha[2], gamma[2];
	// Zr: 20 * 7 = 140 bytes
	Zr gamma0;
	Zr h;
	Zr sa, sc, sx, sy, stao;
	grantproof() = default;
};

struct authproof
{	
	// Zr: 20 * 5 = 100 bytes	
	Zr sigma0; 
	Zr sx, sy, sz, h;
	// G1: 65 * 1 = 65 bytes
	G1 sigma1;	
	authproof() = default;
};

struct LOG{
	// Total: 849 bytes
	int index;			// 4 bytes
	int kvalue;				// 4 bytes
	int w;				// 4 bytes
	G1 alpha[2];		// 65 * 2 bytes
	G1 gamma;			// 65 bytes
	G1 gammaw;			// 65 bytes
	grantproof pi;		// 400 bytes
	authproof token;	// 165 bytes
	LOG(){
		index = 0;
		kvalue = 0;
		w = 0;
	}
};

class GroupManager
{
public:
	G1 g, h, S, LIST;
	Zr s;
	GT gt;

	GroupManager()
	{
		h = PG.random_G1();
		s = PG.random_Zr();
		g = PG.random_G1();
		gt = PG.e(g, h);
		S = g ^ s;
		cout << "GM Created" << endl;
	}
};

class AppProvider
{
public:
	G1 LOG;
	int w; // recode user's access time

	AppProvider()
	{
		w = 0;
		cout << "AP Created" << endl;
	}
};

class User
{
public:
	int k, w;
	G1 u;
	Zr y;

	//Certificate of group member
	G1 F;
	G1 A;
	Zr x;

	// Precompute for public keys of GM
	GT gg, gs;
	Zr c;
	G1 hc;
	GT hgamma1, ggamma2, ghc;

	User(GroupManager &gm)
	{
		w = 0;
		unsigned char buf[3] = {'C','P','0'};
		u = PG.BytesToG1(buf, 3);
		y = PG.random_Zr();

		F = gm.g ^ y;
		gg = PG.e(gm.g, gm.g);
		gs = PG.e(gm.g, gm.S);
		c = PG.random_Zr();
		hc = gm.h ^ c;

		cout << "User Created" << endl;
	}
};

void join(GroupManager &gm, User &u)
{
	u.x = PG.random_Zr();
	u.A = (gm.h * u.F) ^ ((gm.s + u.x) ^ (-1)); // A = (hF)^(1/(s+x))
	gm.LIST = gm.g ^ u.x;
}

/*
	e(A,g2)^x e(A,S) = e(g1,g2)e(g,g2)^y
*/
bool Check_Certificate(GroupManager &gm, User &u)
{
    GT left, right;
    G1 temp = (gm.g ^ u.x) * gm.S;
    left = PG.e(u.A, temp);
    right = gm.gt * (PG.e(gm.g, gm.g) ^ u.y);

    return (left == right);
}

grantproof Grant_User(GroupManager &gm, User &u)
{
	unsigned char patch[711];
	grantproof pi;

	G1 R_alpha0, R_gamma1;
	GT R_alpha1, R_gamma2;
	Zr a = PG.random_Zr();
	Zr ra = PG.random_Zr();
	Zr rc = PG.random_Zr();
	Zr rx = PG.random_Zr();
	Zr ry = PG.random_Zr();
	Zr rtao = PG.random_Zr();
	Zr tao = a * u.x;

	pi.alpha[0] = u.u ^ a;
	pi.alpha[1] = u.A * (gm.g ^ a);

	pi.gamma0 = PG.random_Zr();
	pi.gamma[0] = gm.g ^ u.c;
	pi.gamma[1] = u.hc ^ ( (u.y - pi.gamma0) * (u.x^-1));

	/*
	\	Calculate R terms
	*/
	//------------ R_alpha 0 = alpha0^rx * (u^-rtao)
	R_alpha0 = (pi.alpha[0] ^ rx) * (u.u ^ (-rtao));
	//------------ R_alpha 1
	G1 temp = (gm.g^(rtao + ry)) * (gm.S^ra);
	R_alpha1 = PG.e(gm.g, temp) * (PG.e(pi.alpha[1], gm.g) ^ (-rx));

	//--------R_gamma terms
	R_gamma1 = gm.g ^ rc;
	R_gamma2 = (PG.e(gm.h, pi.gamma[0]) ^ ry) * (PG.e(pi.gamma[1], gm.g) ^ (-rx));
	//------------patch hash terms
	int patch_length = 0;
	patch_length += gm.S.ToBytes(patch, true);									// 65 bytes
	patch_length += pi.alpha[0].ToBytes(patch + patch_length, true);  			// 65 bytes
	patch_length += pi.alpha[1].ToBytes(patch + patch_length, true);			// 65 bytes
	patch_length += R_alpha0.ToBytes(patch + patch_length, true);				// 65 bytes
	patch_length += R_alpha1.ToBytes(patch + patch_length, false);				// 128 bytes
	patch_length += pi.gamma[0].ToBytes(patch + patch_length, true); 
	patch_length += pi.gamma[1].ToBytes(patch + patch_length, true);  		
	patch_length += R_gamma1.ToBytes(patch + patch_length, true);
	patch_length += R_gamma2.ToBytes(patch + patch_length, false);
	pi.h.Set_From_Hash(patch, patch_length);

	//
	pi.sa = a * pi.h + ra;
	pi.sc = u.c * pi.h + rc;
	pi.sx = u.x * pi.h + rx;
	pi.sy = u.y * pi.h + ry;
	pi.stao = tao * pi.h + rtao;

	u.hgamma1 = PG.e(gm.h, pi.gamma[0]);
	u.ggamma2 = PG.e(gm.g, pi.gamma[1]);
	u.ghc = PG.e(gm.g, gm.h)^u.c;

	return pi;
}

bool Grant_AP(grantproof &pi, GroupManager &gm, User &u)
{
	unsigned char *patch = new unsigned char[711];

	Zr h;
	Zr h_neg = -pi.h;

	G1 R_alpha0, R_gamma1;
	GT R_alpha1, R_gamma2;

	R_alpha0 = (pi.alpha[0] ^ pi.sx) * (u.u ^ (-pi.stao));
	R_alpha1 = (u.gg ^ (pi.stao + pi.sy)) * (u.gs ^ pi.sa) * (PG.e(pi.alpha[1], gm.g) ^ (-pi.sx)) * ((PG.e(gm.g, gm.h) * (PG.e(pi.alpha[1], gm.S)^-1)) ^ pi.h);

	R_gamma1 = (gm.g ^ pi.sc) * (pi.gamma[0] ^ h_neg);
	R_gamma2 = (PG.e(gm.h, pi.gamma[0]) ^ (pi.sy-pi.h * pi.gamma0)) * (PG.e(pi.gamma[1], gm.g)^ (-pi.sx)) ;

	//------------patch hash terms
	int patch_length = 0;
	patch_length += gm.S.ToBytes(patch, true);
	patch_length += pi.alpha[0].ToBytes(patch + patch_length, true); 
	patch_length += pi.alpha[1].ToBytes(patch + patch_length, true);
	patch_length += R_alpha0.ToBytes(patch + patch_length, true); 
	patch_length += R_alpha1.ToBytes(patch + patch_length, false);
	for (int i = 0; i != 2; i++)
	{
		patch_length += pi.gamma[i].ToBytes(patch + patch_length, true); 
	}
	patch_length += R_gamma1.ToBytes(patch + patch_length, true);
	patch_length += R_gamma2.ToBytes(patch + patch_length, false);

	h.Set_From_Hash(patch, patch_length);
	delete[] patch;
	return (pi.h == h);
}

authproof Auth_User(GroupManager &gm, User &u, grantproof &pi)
{
	unsigned char patch[215];
	int patch_length = 0;
	int t = u.w + 1;
	int remaining = u.k + 1 - t;
	authproof token;
	Zr z = PG.random_Zr();
	token.sigma0 = PG.random_Zr();
	Zr token_trap = (u.x + z * remaining)^-1;
	token.sigma1 = u.hc ^ ((u.y - token.sigma0) * token_trap);

	Zr rx = PG.random_Zr();
	Zr ry = PG.random_Zr();
	Zr rz = PG.random_Zr();

	GT hgamma1rx= u.hgamma1^rx;
	G1 Rgamma = hgamma1rx * (u.ggamma2^(-ry));
	G1 Rgammat = hgamma1rx * (u.ghc ^ (token_trap * (-ry - rz * remaining )));

	//------------patch hash terms
	patch_length = 0;
	patch_length += token.sigma0.ToBytes(patch + patch_length);
	patch_length += token.sigma1.ToBytes(patch + patch_length, true);
	patch_length += Rgamma.ToBytes(patch + patch_length, true);
	patch_length += Rgammat.ToBytes(patch + patch_length, true);
	token.h.Set_From_Hash(patch, patch_length);
	token.sx = u.x * token.h + rx;
	token.sy = u.y * token.h + ry;
	token.sz = z * token.h + rz;

	return token;
}

int Auth_AP(GroupManager &gm, AppProvider &ap, User &u, grantproof &pi, authproof &token)
{
	Zr hp;
	int t = u.w + 1;
	G1 Rgamma, Rgammat;

	Rgamma = (u.hgamma1 ^ (token.sx - pi.gamma0 * token.h)) * (u.ggamma2 ^ (-token.sy));
	Rgammat = (u.hgamma1 ^ (token.sx - token.sigma0 * token.h)) * 
				(PG.e(token.sigma1, gm.g) ^ (-token.sy - token.sz * (u.k + 1 - t)));

	unsigned char patch[215];
	int patch_length = 0;
	patch_length += token.sigma0.ToBytes(patch + patch_length);
	patch_length += token.sigma1.ToBytes(patch + patch_length, true);
	patch_length += Rgamma.ToBytes(patch + patch_length, true);
	patch_length += Rgammat.ToBytes(patch + patch_length, true);
	hp.Set_From_Hash(patch, patch_length);

	return (hp == token.h);
}

void ktaa(GroupManager &gm, AppProvider &ap, User &u)
{
	Timer timing;
	cout << "Joining Protocol < GM, User >" << endl;
	join(gm, u);
	cout << "The Certificate is " << (Check_Certificate(gm, u) ? "VALID" : "INVALID") << endl;

	/**
	*	Granting
	*/
	cout << "Granting Protocol< User, CP >" << endl;
	cout << "User: Granting information generated" << endl;

	timing.Start();
	grantproof pi = Grant_User(gm, u);
	timing.Stop();
	cout << "Timing: " << timing.GetSecond() << " s" << endl << endl;

	timing.Clear();
	timing.Start();
	int isValid = Grant_AP(pi, gm, u);
	timing.Stop();

	cout << "CP: The Granting Information from User is " << (isValid ? "VALID" : "INVALID") << endl;
	cout << "Timing: " << timing.GetSecond() << " s" << endl << endl;

	/**
	*	Authentication
	*/
	cout << "Authentication Protocol< User, CP >" << endl;
	//--------Authentication-User Begin
	cout << "User: Authentication token generated" << endl;

	timing.Clear();
	timing.Start();
	authproof token = Auth_User(gm, u, pi);
	timing.Stop();
	cout << "Timing: " << timing.GetMillisecond() << " ms" << endl << endl;
	//--------Authentication-AP Begin


	timing.Clear();
	timing.Start();
	isValid = Auth_AP(gm, ap, u, pi, token);
	timing.Stop();

	cout << "CP: The Authentication token is " << (isValid ? "VALID" : "INVALID") << endl;
	cout << "Timing: " << timing.GetMillisecond() << " ms" << endl << endl;
}

void ktaa_timing(GroupManager &gm, AppProvider &ap, User &u, 
	vector<double> &grant_user_timing, 
	vector<double> &grant_cp_timing, 
	vector<double> &auth_user_timing, 
	vector<double> &auth_cp_timing)	
{
	Timer timing;
	grantproof pi;
	authproof token;
	join(gm, u);

	int loop = 100;	

	timing.Start();
	for (int i = 0; i < loop; i++){
		pi = Grant_User(gm, u);
	}
	timing.Stop();
	grant_user_timing.push_back(timing.GetSecond() / loop);
	timing.Start();
	for (int i = 0; i < loop; i++){
		Grant_AP(pi, gm, u);
	}
	timing.Stop();
	grant_cp_timing.push_back(timing.GetSecond() / loop);
	/**
	*	Authentication
	*/
	timing.Start();
	for (int i = 0; i < loop; i++){
		token = Auth_User(gm, u, pi);
	}
	timing.Stop();
	auth_user_timing.push_back(timing.GetMillisecond() / loop);
	//--------Authentication-AP Begin
	timing.Start();
	for (int i = 0; i < loop; i++){
		Auth_AP(gm, ap, u, pi, token);
	}
	timing.Stop();
	auth_cp_timing.push_back(timing.GetMillisecond() / loop);
}

void ktaa_timing(GroupManager &gm, AppProvider &ap, User &u){
	vector<double> grant_user_timing;
	vector<double> grant_cp_timing;
	vector<double> auth_user_timing;
	vector<double> auth_cp_timing;	
	int kvalues[] = {5000, 10000, 15000, 20000, 25000, 30000};
	for (int i = 0; i < sizeof(kvalues) / sizeof(kvalues[0]); i++)
	{
		u.k = kvalues[i];
		ktaa_timing(gm, ap, u, grant_user_timing, grant_cp_timing, auth_user_timing, auth_cp_timing);
	}

	cout << "Grant User Timing: " << endl;	
	for (int i = 0; i < sizeof(kvalues) / sizeof(kvalues[0]); i++){
		cout << "(" << kvalues[i] << ", " << grant_user_timing[i] << ")" << endl;
	}
	cout << "Grant CP Timing: " << endl;
	for (int i = 0; i < sizeof(kvalues) / sizeof(kvalues[0]); i++){
		cout << "(" << kvalues[i] << ", " << grant_cp_timing[i] << ")" << endl;
	}
	cout << "Auth User Timing: " << endl;
	for (int i = 0; i < sizeof(kvalues) / sizeof(kvalues[0]); i++){
		cout << "(" << kvalues[i] << ", " << auth_user_timing[i] << ")" << endl;
	}
	cout << "Auth CP Timing: " << endl;
	for (int i = 0; i < sizeof(kvalues) / sizeof(kvalues[0]); i++){
		cout << "(" << kvalues[i] << ", " << auth_cp_timing[i] << ")" << endl;
	}
	cout << endl << "KTAA Ending..." << endl;
}

int main()
{
	long beforeMem = printMemoryUsage();
	PG.Set_Type_A(160,512);
	PG.ShowParameter();

	cout << "KTAA Begins..." << endl;

	GroupManager gm;
	AppProvider ap;
	User u(gm);

	u.k = 25000;
	ktaa(gm,ap,u);

	long afterMem = printMemoryUsage();

	cout << "memory: " << afterMem - beforeMem << " KB" << endl;
	// ktaa_timing(gm,ap, u);
	return 0;
}