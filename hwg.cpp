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

struct grantproof
{
// Total: 21k + 126 + 160 = 21k + 286 bytes
public:
	G1 alpha[2], gamma[2];
	vector<G1> beta; // 21* (k + 6) bytes
	// 20 * 8 bytes
	Zr h;
	Zr sa, sb, sc;
	Zr sx, sy, sz;
	Zr stao;

	grantproof() = default;
	grantproof(int k){
		beta.resize(k + 2);
	}
};

struct authproof
{
	G1 gammat;	// 21 bytes
	Zr sz, h;	// 20 * 2 bytes
	authproof() = default;
};


struct LOG
{// total: 42k + 458
	int Index;		// 4 bytes
	int kvalue;			// 4 bytes
	int w;			// 4 bytes
	G1 alpha[2]; 	// 	21 bytes
	vector<G1> beta; 	// 	21 * (k+2) = 21k + 42 bytes
	G1 gamma0;		// 	21 bytes
	G1 gammaw;		// 	21 bytes
	G1 gammat;		//	21 bytes
	grantproof pi;	//	21k + 286 bytes
	authproof token;// 61 bytes
	LOG() = default;
	LOG(int k){
		beta.clear();
		beta.resize(k + 2);
	}
};

class GroupManager
{
public:
	G1 g1, g, LIST;
	G2 g2, S;
	Zr s;

	GroupManager()
	{
		s = PG.random_Zr();
		g1 = PG.random_G1();
		g = PG.random_G1();
		g2 = PG.random_G2();
		S = g2 ^ s;
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
	// Precompute for recepit for AP
	unsigned char Rpt[100];
	G1 u;
	Zr y;

	//Certificate of group member
	G1 F;
	G1 A;
	Zr x;
	int k, w;

	User(GroupManager &gm)
	{
		w = 0;
		k = 5000;
		memset(Rpt, 0, sizeof(Rpt));
		snprintf((char *)Rpt, sizeof(Rpt), "AP, k:=%x, SDN", k);
		u = PG.BytesToG1(Rpt, strlen((const char *)Rpt));
		y = PG.random_Zr();
		F = gm.g ^ y;

		cout << "User Created" << endl;
	}
};

void join(GroupManager &gm, User &u)
{
	u.x = PG.random_Zr();
	u.A = (gm.g1 * u.F) ^ ((gm.s + u.x) ^ (-1)); // A = (g1F)^(1/(s+x))
	gm.LIST = gm.g ^ u.x;
}

/*
	e(A,g2)^x e(A,S) = e(g1,g2)e(g,g2)^y
*/
bool Check_Certificate(GroupManager &gm, User &u)
{
	GT left, right;

	left = (PG.e(u.A, gm.g2) ^ u.x) * PG.e(u.A, gm.S);
	right = PG.e(gm.g1, gm.g2) * (PG.e(gm.g, gm.g2) ^ u.y);

	return (left == right);
}

grantproof Grant_User(GroupManager &gm, User &u)
{
	unsigned char *patch = new unsigned char[(42 * u.k + 546)];
	grantproof pi(u.k);

	G1 R_alpha0;
	GT R_alpha1;
	std::vector<G1> R_beta(u.k + 2);
	G1 R_beta_p;
	std::vector<G1> R_gamma(2);

	Zr a = PG.random_Zr();
	Zr b = PG.random_Zr();
	Zr c = PG.random_Zr();
	Zr ra = PG.random_Zr();
	Zr rb = PG.random_Zr();
	Zr rc = PG.random_Zr();
	Zr rx = PG.random_Zr();
	Zr ry = PG.random_Zr();
	Zr rz = PG.random_Zr();
	Zr rtao = PG.random_Zr();

	Zr tao = a * u.x;
	Zr z = u.y^(u.k+1);

	pi.alpha[0] = u.u ^ a;
	pi.alpha[1] = u.A * (gm.g ^ a);
	pi.beta[0] = gm.g1 ^ b;

	for (int i = 1; i != u.k + 2; i++)
	{
		pi.beta[i] = (pi.beta[i - 1] ^ u.y);
	}

	pi.gamma[0] = gm.g1 ^ c;
	pi.gamma[1] = (gm.g1 ^ (u.x + c * (u.y^(u.k+1))));

	/*
	\	Calculate R terms
	*/
	//------------ R_alpha 0 = alpha0^rx * (u^-rtao)
	R_alpha0 = (pi.alpha[0] ^ rx) * (u.u ^ (-rtao));
	//------------ R_alpha 1
	R_alpha1 = (PG.e(gm.g, gm.g2) ^ (rtao + ry)) * 
				(PG.e(gm.g, gm.S) ^ ra) * 
				(PG.e(pi.alpha[1], gm.g2) ^ (-rx));

	//--------- R_beta terms
	R_beta[0] = gm.g1 ^ rb;
	// for i in [1, k+1]
	for (int i = 1; i != u.k + 2; i++)
	{
		R_beta[i] = pi.beta[i - 1] ^ ry; // The original paper use Rbeta[i - 1], it is a typo.
	}
	R_beta_p = pi.beta[0] ^ rz;

	//--------R_gamma terms
	R_gamma[0] = gm.g1 ^ rc;
	R_gamma[1] = (gm.g1 ^ rx) * (pi.gamma[0] ^ rz);
	//------------patch hash terms: 21 * (2(k+2) + 8) + 41 * 1 + 240 * 1  + 41 + 13 = 42k + 546
	int patch_length = 0;
	patch_length += gm.S.ToBytes(patch, true);							// 41 bytes	
	int rptlen = strlen(reinterpret_cast<const char *>(u.Rpt));			
	memcpy(patch + patch_length, u.Rpt, rptlen);						// 13 bytes
	patch_length += rptlen;
	patch_length += pi.alpha[0].ToBytes(patch + patch_length, true);		// 21 bytes	-> 75 bytes
	patch_length += R_alpha0.ToBytes(patch + patch_length, true);			// 21 bytes -> 96 bytes
	patch_length += pi.alpha[1].ToBytes(patch + patch_length, true);		// 21 bytes -> 117 bytes
	patch_length += R_alpha1.ToBytes(patch + patch_length, false);			// 240 bytes -> 357 bytes
	
	for (int i = 0; i != u.k + 2; i++)
	{
		patch_length += pi.beta[i].ToBytes(patch + patch_length, true);	// 21 * (k+2) bytes -> 
		patch_length += R_beta[i].ToBytes(patch + patch_length, true); // 21 * (k+2) bytes -> 861
	}
	patch_length += R_beta_p.ToBytes(patch + patch_length, true);    // 21 bytes -> 882
	for (int i = 0; i != 2; i++)
	{
		patch_length += pi.gamma[i].ToBytes(patch + patch_length, true);//21 * 2 bytes
		patch_length += R_gamma[i].ToBytes(patch + patch_length, true);	// 21 * 2 bytes
	}
	pi.h.Set_From_Hash(patch, patch_length);

	//
	pi.sa = a * pi.h + ra;
	pi.sb = b * pi.h + rb;
	pi.sc = c * pi.h + rc;
	pi.sx = u.x * pi.h + rx;
	pi.sy = u.y * pi.h + ry;
	pi.sz = z * pi.h + rz;
	pi.stao = tao * pi.h + rtao;
	// cout << "before: R_beta_p: " << R_beta_p.ToString()  << endl;
	// R_beta_p = (R_beta[0] ^ pi.sz) * (pi.beta[0] ^ (-pi.h * u.y^(k+1)));
	// cout << "after: R_beta_p: " << R_beta_p.ToString()  << endl;
	delete[] patch;

	return pi;
}

int Grant_AP(grantproof &pi, GroupManager &gm, User &u)
{
	int pathchsize =(42 * u.k + 546);
	unsigned char *patch = new unsigned char[pathchsize];
	memset(patch, 0, pathchsize);

	Zr h;
	Zr h_neg = -pi.h;

	// Initialize all elements
	G1 R_alpha0;
	GT R_alpha1;
	G1 R_beta[u.k + 2];
	G1 R_beta_p;
	G1 R_gamma[2];

	// Simple calculations first
	R_alpha0 = (pi.alpha[0] ^ pi.sx) * (u.u ^ (-pi.stao));
	
	// Simplified GT calculations
	GT e_gg = PG.e(gm.g, gm.g2);
	GT e_gs = PG.e(gm.g, gm.S);
	GT e_ah = PG.e(pi.alpha[1], gm.g2);
	GT e_as = PG.e(pi.alpha[1], gm.S);
	GT e_base = PG.e(gm.g1, gm.g2);

	R_alpha1 = (e_gg ^ (pi.stao + pi.sy)) * 
			   (e_gs ^ pi.sa) * 
			   (e_ah ^ (-pi.sx)) * 
			   ((e_base * (e_as^(-1))) ^ pi.h);

	// Calculate R_beta terms
	R_beta[0] = (gm.g1 ^ pi.sb) * (pi.beta[0] ^ h_neg);
	for (int i = 1; i < u.k + 2; i++) {
		R_beta[i] = (pi.beta[i-1] ^ pi.sy) * (pi.beta[i] ^ h_neg);
	}
	R_beta_p = (pi.beta[0] ^ pi.sz) * (pi.beta[u.k + 1] ^ h_neg);

	// Calculate R_gamma terms
	R_gamma[0] = (gm.g1 ^ pi.sc) * (pi.gamma[0] ^ h_neg);
	R_gamma[1] = (gm.g1 ^ pi.sx) * (pi.gamma[0] ^ pi.sz) * (pi.gamma[1] ^ h_neg);

	// Hash calculation
	int patch_length = 0;
	patch_length += gm.S.ToBytes(patch, true);
	int rptlen = strlen(reinterpret_cast<const char *>(u.Rpt));
	memcpy(patch + patch_length, u.Rpt, rptlen);
	patch_length += rptlen;

	// Write alpha terms
	patch_length += pi.alpha[0].ToBytes(patch + patch_length, true);
	patch_length += R_alpha0.ToBytes(patch + patch_length, true);
	patch_length += pi.alpha[1].ToBytes(patch + patch_length, true);
	patch_length += R_alpha1.ToBytes(patch + patch_length, false);

	// Write beta terms
	for (int i = 0; i < u.k + 2; i++) {
		patch_length += pi.beta[i].ToBytes(patch + patch_length, true);
		patch_length += R_beta[i].ToBytes(patch + patch_length, true);
	}
	patch_length += R_beta_p.ToBytes(patch + patch_length, true);

	// Write gamma terms
	for (int i = 0; i < 2; i++) {
		patch_length += pi.gamma[i].ToBytes(patch + patch_length, true);
		patch_length += R_gamma[i].ToBytes(patch + patch_length, true);
	}

	h.Set_From_Hash(patch, patch_length);
	delete[] patch;

	bool result = (pi.h == h);
	return result;
}

authproof Auth_User(GroupManager &gm, User &u, grantproof &pi)
{
	unsigned char patch[140];
	int patch_length = 0;
	//----
	int t = u.w + 1;

	authproof token;

	//--------------------------------------
	// t-th token: gamma^{y^{t}}
	token.gammat = pi.gamma[0] ^ (u.y ^ t);

	G1 R1, R2;
	Zr rz = PG.random_Zr();
	R1 = pi.beta[0] ^ rz;
	R2 = pi.gamma[0] ^ rz;

	//------------patch hash terms
	patch_length = 0;
	patch_length += gm.S.ToBytes(patch, true);
	int rptlen = strlen(reinterpret_cast<const char *>(u.Rpt));
	memcpy(patch + patch_length, u.Rpt, rptlen);
	patch_length += rptlen;
	sprintf((char *)patch + patch_length, "%d%d", u.w, t);
	patch_length += token.gammat.ToBytes(patch + patch_length, true);
	patch_length += R1.ToBytes(patch + patch_length, true);
	patch_length += R2.ToBytes(patch + patch_length, true);
	token.h.Set_From_Hash(patch, patch_length);

	token.sz = (u.y ^ t) * token.h + rz;
	return token;
}

int Auth_AP(GroupManager &gm, AppProvider &ap, User &u, grantproof &pi, authproof &token)
{
	Zr hp;
	int t = ap.w + 1;

	G1 R1, R2;
	R1 = (pi.beta[0] ^ token.sz) * (pi.beta[t] ^ (-token.h));
	R2 = (pi.gamma[0] ^ token.sz) * (token.gammat ^ (-token.h));

	unsigned char patch[140];
	int patch_length = 0;
	patch_length += gm.S.ToBytes(patch, true);
	int rptlen = strlen(reinterpret_cast<const char *>(u.Rpt));
	memcpy(patch + patch_length, u.Rpt, rptlen);
	patch_length += rptlen;
	sprintf((char *)patch + patch_length, "%d%d", ap.w, t);
	patch_length += token.gammat.ToBytes(patch + patch_length, true);
	patch_length += R1.ToBytes(patch + patch_length, true);
	patch_length += R2.ToBytes(patch + patch_length, true);
	hp.Set_From_Hash(patch, patch_length);

	ap.w++;
	return (hp == token.h);
}

void ktaa(GroupManager &gm, AppProvider &ap, User &u){
	Timer timing;
	cout << "Joining Protocol < GM, User >" << endl;
	join(gm, u);
	cout << "The Certificate is " << (Check_Certificate(gm, u)? "VALID" : "INVALID") << endl;

	/**
	*	Granting
	*/
	cout << "Granting Protocol< User, CP >" << endl;
	timing.Start();
	grantproof pi = Grant_User(gm, u);
	timing.Stop();
	cout << "User: Granting information generated" << endl;
	cout << "Timing: " << timing.GetSecond() << " s" << endl << endl;

	timing.Start();
	bool isValid = Grant_AP(pi, gm, u);
	timing.Stop();

	cout << "CP: The Granting Information from User is " << (isValid ? "VALID" : "INVALID") << endl;
	cout << "Timing: " << timing.GetSecond() << " s" << endl << endl;

	/**
	*	Authentication
	*/
	cout << "Authentication Protocol< User, CP >" << endl;
	//--------Authentication-User Begin
	cout << "User: Authentication token generated" << endl;

	timing.Start();
	authproof token = Auth_User(gm, u, pi);
	timing.Stop();
	cout << "Timing: " << timing.GetMillisecond() << " ms" << endl << endl;
	//--------Authentication-AP Begin


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
    join(gm, u);
	grantproof pi(u.k);
	authproof token;

	int loop = 10;
    // Granting Protocol
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

    // Authentication Protocol
    timing.Start();
	for (int i = 0; i < loop; i++){
		token = Auth_User(gm, u, pi);
	}
    timing.Stop();
    auth_user_timing.push_back(timing.GetMillisecond() / loop);

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
    
	// Clear vectors before use
	grant_user_timing.clear();
	grant_cp_timing.clear();
	auth_user_timing.clear();
	auth_cp_timing.clear();

	for (int i = 0; i < sizeof(kvalues) / sizeof(kvalues[0]); i++)
	{
		u.k = kvalues[i];
		ktaa_timing(gm, ap, u, grant_user_timing, grant_cp_timing, auth_user_timing, auth_cp_timing);
	}

	// Print results only if vectors have data
	if (!grant_user_timing.empty()) {
		cout << "Grant User Timing: " << endl;    
		for (int i = 0; i < grant_user_timing.size(); i++){
			cout << "(" << kvalues[i] << ", " << grant_user_timing[i] << ")" << endl;
		}
		cout << "Grant CP Timing: " << endl;
		for (int i = 0; i < grant_cp_timing.size(); i++){
			cout << "(" << kvalues[i] << ", " << grant_cp_timing[i] << ")" << endl;
		}
		cout << "Auth User Timing: " << endl;
		for (int i = 0; i < auth_user_timing.size(); i++){
			cout << "(" << kvalues[i] << ", " << auth_user_timing[i] << ")" << endl;
		}
		cout << "Auth CP Timing: " << endl;
		for (int i = 0; i < auth_cp_timing.size(); i++){
			cout << "(" << kvalues[i] << ", " << auth_cp_timing[i] << ")" << endl;
		}
	}

	cout << endl << "KTAA Ending..." << endl;
}

int main()
{
	long beforeMem = printMemoryUsage();
	PG.Set_Type_D();
	PG.ShowParameter();

	cout << "KTAA Begins..." << endl;

	GroupManager gm;
	AppProvider ap;
	User u(gm);

	u.k = 30000;
	ktaa(gm, ap, u);
	long afterMem = printMemoryUsage();

	cout << "memory: " << afterMem - beforeMem << " KB" << endl;

	// ktaa_timing(gm, ap, u);
	return 0;
}
