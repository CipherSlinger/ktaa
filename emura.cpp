#include "pbc++.h"
#include "Timer.h"
#include <sys/resource.h>
#include <iostream>
#include <vector>
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

using namespace std;
using namespace SHA;
using namespace PBC;
// Function to print memory usage
long printMemoryUsage() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
	return usage.ru_maxrss;
}
struct proof
{
public:
    proof() = default;
};

struct grantproof : public proof
{
// Total: 42k + 189 + 20k + 180 + 4 = 62k + 373 bytes
public:
	int k;											// 4 bytes
	// 21 * (2k +9) bytes
    G1 C1, C2, C31, C32;							// 21 * 4
    vector<G1> C4;									// 21 * (k+2)	
	vector<G1> h;									// 21 * (k+3)

	// 20 * (k+9) bytes	
    Zr c, salpha, sbeta, sgamma, sx, sy, stao;		// 20 * 7
    vector<Zr> sz;									// 20 * (k+2)	
    
	grantproof(){
		this->k = 0;
	}
    grantproof(int k) {
        this->k = k;
        C4.resize(k+3);
        h.resize(k+3);
        sz.resize(k+3);
    }
};

struct authproof: public proof
{// total: 107 bytes
public:
	int l;					// 4 bytes
	Zr c, sy;				// 20 * 2 = 40 bytes
	G1 C3l0, C3l1, C3l2; 	// 21 * 3 = 63 bytes
	authproof() {
		l = 0;
	}
};

struct LOG
{// total: 232k+570
public:
	int index;					// 4 bytes
	int k;						// 4 bytes
	G1 C1, C2;					// 21 * 2 bytes
	vector<G1> C3;//(k+2)			// 21 * (k+2)  bytes
	vector<G1> C4;//(k+2)			// 21 * (k+2)  bytes
	vector<G1> h;//(k+3)			// 21 * (k+3) bytes
	grantproof pi;				// 62k + 373 bytes
	vector<authproof> tokens;	// k * 107 bytes
	LOG()
	{
		index = 0;
		pi = grantproof(0);
	}
};

class GroupManager
{
public:
	G1 g, g1;
	G2 g2;
	Zr gamma;
	G2 omega;

	G1 LIST;

	GroupManager()
	{
		g = PG.random_G1();
		g1 = PG.random_G1();
		g2 = PG.random_G2();
		gamma = PG.random_Zr();
		omega = g2 ^ gamma;
		cout << "GM Created" << endl;
	}
};

class AppProvider
{
public:
	LOG log = LOG();
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

	int w;
	int k;
	Zr x, y;
	G1 A, F;
	G1 mpk;
	User(GroupManager &gm)
	{
		w = 0;
		y = PG.random_Zr();
		F = gm.g ^ y;
		cout << "User Created" << endl;
	}
};

void join(GroupManager &gm, User &u)
{
	u.x = PG.random_Zr();
	u.A = (gm.g1 * u.F) ^ ((gm.gamma + u.x) ^ (-1)); // A = (g1F)^(1/(gamma+x))
	u.mpk = gm.g1 ^ u.x;
	gm.LIST = u.mpk;
}

bool Check_Certificate(GroupManager &gm, User &u)
{
	GT left, right;

	left = (PG.e(u.A, gm.g2) ^ u.x) * PG.e(u.A, gm.omega) * (PG.e(gm.g, gm.g2)^(-u.y));
	right = PG.e(gm.g1, gm.g2);

	return (left == right);
}

grantproof Grant_User(GroupManager &gm, User &u)
{
	unsigned char *patch = new unsigned char[84 * u.k + 541];
	grantproof pi(u.k);

	// Step 1
	Zr alpha = PG.random_Zr();
	Zr beta = PG.random_Zr();
	Zr gamma = PG.random_Zr();
	// Calculate coefficients of polynomial f(y) = \prod_{i=1}^{k+2} (y+i)
	vector<Zr> a(u.k+3, 0); 
	vector<Zr> temp(u.k+3, 0); 
	a[0] = 1;  // constant term
	a[1] = 1;  // coefficient of y
	for(int i = 2; i <= u.k+2; i++) {
		fill(temp.begin(), temp.end(), 0);
		for(int j = 0; j < u.k+2; j++) {
			temp[j+1] += a[j];
		}
		for(int j = 0; j <= u.k+2; j++) {
			temp[j] += i * a[j];
		}
		a = temp;
	}

	for(int i = 0; i < u.k+3; i++){
		pi.h[i] = gm.g1^(a[i] * beta);
	}

	pi.C1 = u.A * (gm.g^alpha);
	pi.C31 = gm.g1^beta;
	pi.C32 = pi.C31^u.y;
	pi.C4[0] = gm.g;
	pi.C4[1] = gm.g1^gamma;
	for(int i = 2; i < u.k+3; i++){
		pi.C4[i] = pi.C4[i-1]^u.y;
	}
	// Step 2
	Zr tao = alpha * u.x;
	vector<Zr> z(u.k+3);
	z[0] = 1;
	pi.C2 = u.mpk * pi.h[0];
	for(int i = 1; i < u.k+3; i++){
		z[i] = z[i-1] * u.y;
		pi.C2 *= (pi.h[i]^z[i]);
	}

	// (a)
	Zr ralpha = PG.random_Zr();
	Zr rbeta = PG.random_Zr();
	Zr rgamma = PG.random_Zr();
	Zr rx = PG.random_Zr();
	Zr ry = PG.random_Zr();
	Zr rtao = PG.random_Zr();
	vector<Zr> rz(u.k+3);
	for(int i = 0; i < u.k+3; i++){
		rz[i] = PG.random_Zr();
	}

	// (b)
	GT R1;
	R1 = (PG.e(gm.g, gm.g2)^rtao) * 
		 (PG.e(gm.g, gm.g2)^ry) * 
		 (PG.e(gm.g, gm.omega)^ralpha) * 
		 (PG.e(pi.C1, gm.g2)^(-rx));
	G1 R2;
	R2 = (gm.g1^ rx) * (pi.h[0] ^ rz[0]) * (pi.h[1]^ry); // *!! The original paper ignores rz[0] here, it is a typo
	for(int i = 2; i < u.k+3; i++){
		R2 *= (pi.h[i]^rz[i]);
	}
	G1 R31, R32;
	R31 = gm.g1 ^ rbeta;
	R32 = pi.C31 ^ ry;
	G1 R4[u.k+3];
	R4[0] = gm.g1;
	R4[1] = gm.g1 ^ rgamma;
	for(int i = 2; i < u.k+3; i++){
		R4[i] = pi.C4[i-1]^ry;
	}
	G1 R4p[u.k+3];
	R4p[0] = gm.g;
	R4p[1] = gm.g;
	R4p[2] = gm.g;
	for(int i = 3; i < u.k+3; i++){
		R4p[i] = pi.C4[1] ^ rz[i-1];
	}
	// G1 R5[u.k+3];
	// for(int i = 0; i < u.k+3; i++){
	// 	R5[i] = pi.h[i]^rbeta;
	// }

	// (c)
	//------------patch hash terms (assume k = 10, bytes: 21 * (k+2) -> 1288)
	int patch_length = 0;
	const char* idv = "IDv";										// bytes: 3
	memcpy(patch + patch_length, idv, strlen(idv));
	patch_length += strlen(idv);
	int k_value = u.k;  // Create a variable with k's value
	memcpy(patch + patch_length, &k_value, sizeof(k_value));		// bytes: 4 
	patch_length += sizeof(k_value);
	patch_length += pi.C1.ToBytes(patch + patch_length, true);  	// bytes: 21 
	patch_length += pi.C2.ToBytes(patch + patch_length, true);		// bytes: 21 
	patch_length += pi.C31.ToBytes(patch + patch_length, true);		// bytes: 21 
	patch_length += pi.C32.ToBytes(patch + patch_length, true);		// bytes: 21 
	for(int i = 1; i < u.k+3; i++){
		patch_length += pi.C4[i].ToBytes(patch + patch_length,true); // bytes: 21 * (k+2) 
	}
	patch_length += R1.ToBytes(patch + patch_length, false); 		// bytes: 240 
	patch_length += R2.ToBytes(patch + patch_length, true); 		// bytes: 21 
	patch_length += R31.ToBytes(patch + patch_length, true); 		// bytes: 21 
	patch_length += R32.ToBytes(patch + patch_length, true); 		// bytes: 21 
	for(int i = 1; i < u.k+3; i++){
		patch_length += R4[i].ToBytes(patch + patch_length, true); //bytes: 21 * (k+2) 
	}
	for(int i = 3; i < u.k+3; i++){
		patch_length += R4p[i].ToBytes(patch + patch_length, true);//bytes: 21 * k 
	}
	// It is not necessary to prove the relation of h[i]'s.
	// This is because the h[i]'s are generated by g^{beta * ai} where ai are coefficient of the polynomial f(y) = \prod_{i=1}^{k+2} (y+i)
	// which is public information.
	// for(int i = 1; i < k+3; i++){
	// 	patch_length += R5[i].ToBytes(patch + patch_length, true); 
	// }
	for(int i = 0; i < u.k+3; i++){
		patch_length += pi.h[i].ToBytes(patch + patch_length, true); //bytes: 21 * (k+3)
	}
	// 21 * (4k+7 + 7) + 240 + 3 +4  = 84k + 541
	pi.c.Set_From_Hash(patch, patch_length);

	//
	pi.salpha = ralpha + pi.c * alpha;
	pi.sbeta = rbeta + pi.c * beta;
	pi.sgamma = rgamma + pi.c * gamma;
	pi.sx = rx + pi.c * u.x;
	pi.sy = ry + pi.c * u.y;
	pi.stao = rtao + pi.c * tao;
	for(int i = 0; i < u.k+3; i++){
		pi.sz[i] = rz[i] + pi.c * z[i];
	}
	delete patch;

	return pi;
}

int Grant_AP(grantproof &pi, GroupManager &gm, User &u)
{
	unsigned char *patch = new unsigned char[84 * u.k + 541];
	pi.k = u.k;
	Zr c = pi.c;
	Zr c_neg = -pi.c;
	GT R1;
	G1 R2, R31, R32;
	G1 R4[pi.k+3], R4p[pi.k+3];
	G1 R5[pi.k+3];

	R1 = (PG.e(gm.g, gm.g2) ^ pi.stao) * 
		 (PG.e(gm.g, gm.g2) ^ pi.sy) * 
		 (PG.e(gm.g, gm.omega)^pi.salpha) * 
		 (PG.e(pi.C1, gm.g2)^(-pi.sx)) * 
		 ((PG.e(gm.g1, gm.g2) * (PG.e(pi.C1, gm.omega)^-1))^c);
	R2 = (gm.g1^ pi.sx) * (pi.h[0]^pi.sz[0]) * (pi.h[1]^pi.sy);
	for(int i = 2; i < u.k+3; i++){
		R2 *= (pi.h[i]^pi.sz[i]);
	}
	R2 *= ( pi.C2^c_neg);
	R31 = (gm.g1^pi.sbeta) * (pi.C31^c_neg);
	R32 = (pi.C31^pi.sy) * (pi.C32^c_neg);
	R4[1] = (gm.g1^pi.sgamma) * (pi.C4[1]^c_neg);
	for(int i = 2; i < u.k+3; i++){
		R4[i] = (pi.C4[i-1]^pi.sy) * (pi.C4[i]^c_neg); // *!! The original paper uses pi.C4[i-1] here, it is a typo
	}
	for(int i = 3; i < u.k+3; i++){
		R4p[i] = (pi.C4[1]^pi.sz[i-1]) * (pi.C4[i]^c_neg);// *!! The original paper uses pi.C4[1] here, it is a typo	
	}
	// for(int i = 0; i < k+3; i++){
	// 	R5[i] = (pi.h[i]^pi.sbeta) * (pi.h[i]^c_neg);
	// }

	//------------patch hash terms
	int patch_length = 0;
	const char* idv = "IDv";
	memcpy(patch + patch_length, idv, strlen(idv));
	patch_length += strlen(idv);
	int k_value = u.k;  // Create a variable with k's value
	memcpy(patch + patch_length, &k_value, sizeof(k_value));
	patch_length += sizeof(k_value);
	patch_length += pi.C1.ToBytes(patch + patch_length, true);
	patch_length += pi.C2.ToBytes(patch + patch_length, true); 
	patch_length += pi.C31.ToBytes(patch + patch_length, true); 
	patch_length += pi.C32.ToBytes(patch + patch_length, true); 
	for(int i = 1; i < u.k+3; i++){
		patch_length += pi.C4[i].ToBytes(patch + patch_length, true);
	}
	patch_length += R1.ToBytes(patch + patch_length, false); 
	patch_length += R2.ToBytes(patch + patch_length, true);
	patch_length += R31.ToBytes(patch + patch_length, true);
	patch_length += R32.ToBytes(patch + patch_length, true);
	for(int i = 1; i < u.k+3; i++){
		patch_length += R4[i].ToBytes(patch + patch_length, true);
	}
	for(int i = 3; i < u.k+3; i++){
		patch_length += R4p[i].ToBytes(patch + patch_length, true);
	}
	// for(int i = 1; i < k+3; i++){
	// 	patch_length += R5[i].ToBytes(patch + patch_length, true); 
	// }
	for(int i = 0; i < u.k+3; i++){
		patch_length += pi.h[i].ToBytes(patch + patch_length, true);
	}

	c.Set_From_Hash(patch, patch_length);
	delete patch;

	return (pi.c == c);
}

authproof Auth_User(GroupManager &gm, User &u, LOG &log)
{
	unsigned char *patch = new unsigned char[49];
	authproof token;
	int w = u.w + 1;
	token.C3l0 = log.C3[w-1];
	token.C3l1 = log.C3[w];
	token.C3l2 = token.C3l1 ^ u.y;
	Zr ry = PG.random_Zr();
	G1 R1 = token.C3l0 ^ ry;
	G1 R2 = token.C3l1 ^ ry;
	int patch_length = 0;
	memcpy(patch + patch_length, &w, sizeof(w));					// bytes: 4 
	patch_length += sizeof(w);
	const char* idv = "IDv";										// bytes: 3
	memcpy(patch + patch_length, idv, strlen(idv));
	patch_length += strlen(idv);
	patch_length += R1.ToBytes(patch + patch_length, true);  		// bytes: 21 
	patch_length += R2.ToBytes(patch + patch_length, true);  		// bytes: 21 
	token.c.Set_From_Hash(patch, patch_length);

	token.sy = ry + token.c * u.y;
	token.l = w;

	delete patch;
	return token;
}

bool Auth_AP(GroupManager &gm, AppProvider &ap, User &u, authproof &token)
{
	if(token.l > ap.log.k){
		return false;
	} 
	unsigned char *patch = new unsigned char[49];
	G1 R1 = (token.C3l0 ^ token.sy) * (token.C3l1^(-token.c));
	G1 R2 = (token.C3l1 ^ token.sy) * (token.C3l2^(-token.c));

	int w = token.l;

	int patch_length = 0;
	memcpy(patch + patch_length, &w, sizeof(w));					// bytes: 4 
	patch_length += sizeof(w);
	const char* idv = "IDv";										// bytes: 3
	memcpy(patch + patch_length, idv, strlen(idv));
	patch_length += strlen(idv);
	patch_length += R1.ToBytes(patch + patch_length, true);  		// bytes: 21 
	patch_length += R2.ToBytes(patch + patch_length, true);  	// bytes: 21 
	Zr cp;
	cp.Set_From_Hash(patch, patch_length);

	delete patch;
	return (cp == token.c);
}

void ktaa(GroupManager &gm, AppProvider &ap, User &u)
{
	Timer timing;
	cout << "\nJoining Protocol < GM, User >" << endl;
	join(gm, u);
	cout << "The Certificate is " << (Check_Certificate(gm, u)? "VALID" : "INVALID") << endl;

	/**
	*	Granting
	*/
	cout << "\nGranting Protocol< User, CP >" << endl << "User: Granting information generated" << endl;

	timing.Start();
	grantproof pi = Grant_User(gm, u);
	timing.Stop();
	cout << "Timing: " << timing.GetSecond() << " s" << endl;

	timing.Start();
	bool isValid = Grant_AP(pi, gm, u);
	timing.Stop();

	cout << "CP: The Granting Information from User is " << (isValid ? "VALID" : "INVALID") << endl;
	cout << "Timing: " << timing.GetSecond() << " s" << endl ;

	cout << "Add info to log" << endl<< endl;
	ap.log.pi = pi;
	ap.log.k = u.k;
	ap.log.C1 = pi.C1;
	ap.log.C2 = pi.C2;
	ap.log.C3.push_back(pi.C31);
	ap.log.C3.push_back(pi.C32);
	for(int i = 0; i < u.k+3; i++){
		ap.log.C4.push_back(pi.C4[i]);
		ap.log.h.push_back(pi.h[i]);
	}

	/**
	*	Authentication
	*/
	cout << "Authentication Protocol< User, CP >" << endl;
	//--------Authentication-User Begin
	cout << "User: Authentication token generated" << endl;

	timing.Start();
	authproof token = Auth_User(gm, u, ap.log);
	timing.Stop();
	cout << "Timing: " << timing.GetMillisecond() << " ms" << endl << endl;
	// //--------Authentication-AP Begin

	timing.Start();
	isValid = Auth_AP(gm, ap, u, token);
	timing.Stop();

	cout << "CP: The Authentication token is " << (isValid ? "VALID" : "INVALID") << endl;
	cout << "Timing: " << timing.GetMillisecond() << " ms" << endl << endl;
}

void ktaa_timing(
	GroupManager &gm, AppProvider &ap, User &u, 
                 vector<double> &grant_user_timing, 
                 vector<double> &grant_cp_timing, 
                 vector<double> &auth_user_timing, 
                 vector<double> &auth_cp_timing
){
	Timer timing;
	grantproof pi;
	authproof token;
	int loop = 1;
	join(gm, u);
	
	timing.Start();
	for (int i = 0; i < loop; i++){
		pi = Grant_User(gm, u);
	}
	timing.Stop();
	grant_user_timing.push_back(timing.GetSecond() / loop);

	timing.Start();
	for (int i = 0; i < loop; i++) {
		Grant_AP(pi, gm, u);
	}
	timing.Stop();
	grant_cp_timing.push_back(timing.GetSecond() / loop);

	ap.log.pi = pi;
	ap.log.k = u.k;
	ap.log.C1 = pi.C1;
	ap.log.C2 = pi.C2;
	ap.log.C3.push_back(pi.C31);
	ap.log.C3.push_back(pi.C32);
	for(int i = 0; i < u.k+3; i++){
		ap.log.C4.push_back(pi.C4[i]);
		ap.log.h.push_back(pi.h[i]);
	}

	timing.Start();
	for (int i = 0; i < loop; i++) {
		token = Auth_User(gm, u, ap.log);
	}
	timing.Stop();
	auth_user_timing.push_back(timing.GetMillisecond() / loop);
	// //--------Authentication-AP Begin

	timing.Start();
	for (int i = 0; i < loop; i++) {
		Auth_AP(gm, ap, u, token);
	}
	timing.Stop();
	auth_cp_timing.push_back(timing.GetMillisecond() / loop);
}

int main()
{
	long beforeMem = printMemoryUsage();
	// PG.Set_Type_F(160);
	PG.Set_Type_D();
	PG.ShowParameter();

	cout << "\nKTAA Begins...\n" << endl;

	GroupManager gm;
	AppProvider ap;
	User u(gm);

	vector<double> grant_user_timing;
	vector<double> grant_cp_timing;
	vector<double> auth_user_timing;
	vector<double> auth_cp_timing;    

	int kvalues[] = {10000}; // , 10000, 15000, 20000, 25000, 30000 
    
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

	long afterMem = printMemoryUsage();

	cout << "Memory: " << afterMem - beforeMem << endl;
	cout << endl << "KTAA Ending..." << endl;

	return 0;
}