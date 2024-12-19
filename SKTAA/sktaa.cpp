#include "/usr/local/include/pbc/pbc.h"
#include<iostream>
#include<string.h>
#include<stdio.h>
#include<stdlib.h>

using namespace std;

#define Same 0
#define Diff 1
#define k 10

struct grantproof
{
	element_t alpha[2];
	element_t beta[k+2];
	element_t gamma[2];

	element_t h;
	element_t sa;
	element_t sb;
	element_t sc;
	element_t sx;
	element_t sy;
	element_t sz;
	element_t stao;

	grantproof(pairing_t &pairing)
	{
		element_init_G1(alpha[0],pairing);
		element_init_G1(alpha[1],pairing);
		for(int i=0; i!=k+2; i++)
		{
			element_init_G1(beta[i],pairing);
		}
		element_init_G1(gamma[0],pairing);
		element_init_G1(gamma[1],pairing);

		element_init_Zr(h,pairing);
		element_init_Zr(sa,pairing);
		element_init_Zr(sb,pairing);
		element_init_Zr(sc,pairing);
		element_init_Zr(sx,pairing);
		element_init_Zr(sy,pairing);
		element_init_Zr(sz,pairing);
		element_init_Zr(stao,pairing);
	}
	~grantproof()
	{
		/*
		cout<< "Granting Proof Clear Begin" <<endl;
		element_free(alpha[0]);
		element_free(alpha[1]);
		for(int i=0; i!=k+2; i++)
		{
			element_free(beta[i]);
		}
		element_free(gamma[0]);
		element_free(gamma[1]);

		element_free(h);
		element_free(sa);
		element_free(sb);
		element_free(sc);
		element_free(sx);
		element_free(sy);
		element_free(sz);
		element_free(stao);
		cout<< "Granting Proof Clear End" <<endl;
		*/
	}
};

class GroupManager
{
	public:
	pairing_t pairing;

	element_t g1,g2,g;
	element_t s;
	element_t S;

	element_t LIST;

	element_pp_t g1pp;

	GroupManager()
	{
		pbc_param_t param;

		pbc_param_init_f_gen(param, 160);
		pairing_init_pbc_param(pairing, param);
		pbc_param_clear(param);
		element_init_G1(g1, pairing);
		element_init_G2(g2, pairing);
		element_init_G1(g, pairing);
		element_init_Zr(s, pairing);
		element_init_G1(LIST, pairing);
		element_init_G2(S, pairing);
		element_random(g1);
		element_random(g2);
		element_random(g);
		element_random(s);
		element_pow_zn(S, g2, s);

		element_pp_init(g1pp,g1);
		cout<<"GM Created"<<endl;
	}
	void ShowParamters()
	{
		printf("Pairing Parameters:\n");
		printf("Pairing Type: %s\n",(pairing_is_symmetric(pairing)?"Symmetirc":"Asymmetirc"));
		printf("G1: %d Bytes\n",pairing_length_in_bytes_G1(pairing));
		printf("G2: %d Bytes\n",pairing_length_in_bytes_G2(pairing));
		printf("GT: %d Bytes\n",pairing_length_in_bytes_GT(pairing));
		printf("Zr: %d Bytes\n",pairing_length_in_bytes_Zr(pairing));
		element_printf("g1: %B\n", g1);
		element_printf("g2: %B\n", g2);
		element_printf("g: %B\n", g);
		element_printf("s: %B\n", s);
		element_printf("S: %B\n", S);
	}
	~GroupManager()
	{
		element_clear(g1);
		element_clear(g2);
		element_clear(g);
		element_clear(s);
		element_clear(LIST);
		element_clear(S);

		element_pp_clear(g1pp);
		pairing_clear(pairing);
		cout<<"GM Cleared!"<<endl;
	}
};



class AppProvider
{
	public:
	element_t LOG;

	AppProvider(GroupManager &gm)
	{
		element_init_G1(LOG, gm.pairing);
		cout<<"AP Created"<<endl;
	}
	~AppProvider()
	{
		element_clear(LOG);
		cout<<"AP Cleared!"<<endl;
	}
};


class User
{
	public:
	// Precompute for recepit for AP
	char Rpt[100];
	element_t u;
	element_t y[k+1];// y[i] = y[0]^{i-1}
	element_t kt;// equals to y^{k+1}

	//Certificate of group member
	element_t F;
	element_t A;
	element_t x;


	// Precompute for public keys of GM
	element_t gg2, gs, g1g2;

	User(GroupManager &gm)
	{
		element_init_G1(u,gm.pairing);
		memset(Rpt, 0, sizeof(Rpt));
		snprintf(Rpt, sizeof(Rpt),"AP,k:=%x, SDN",k);
		element_from_hash(u,Rpt,strlen(Rpt));

		element_init_Zr(y[0], gm.pairing);
		element_random(y[0]);
		element_init_Zr(kt,gm.pairing);
		element_set1(kt);

		for(int i=1 ; i!= k+1; i++)
		{
			element_mul(kt,kt,y[0]);

			//element_init_G1(y[i], gm.pairing);
			element_init_Zr(y[i], gm.pairing);
			//element_pow_zn(y[i], gm.g1, kt);
			element_mul_zn(y[i], y[i-1], y[0]);
		}

		element_init_G1(F, gm.pairing);
		element_pow_zn(F,gm.g,y[0]);

		element_init_G1(A, gm.pairing);
		element_init_G1(x, gm.pairing);


		element_init_GT(gg2, gm.pairing);
		element_init_GT(gs,gm.pairing);
		element_init_GT(g1g2,gm.pairing);
		element_pairing(gg2,gm.g, gm.g2);
		element_pairing(gs,gm.g,gm.S);
		element_pairing(gs,gm.g1,gm.g2);

		cout<<"User Created"<<endl;
		
	}
	~User()
	{
		for(int i=0 ; i!= k+1; i++)
		{
			element_clear(y[i]);

		}		
		element_clear(F);
		element_clear(A);
		element_clear(x);

		element_clear(u);

		element_clear(gg2);
		element_clear(gs);
		cout<<"User Cleared!"<<endl;
	}

};

void join(GroupManager &gm, User &u)
{
	element_t temp1, temp2;
	element_init_G1(temp1,gm.pairing);
	element_init_Zr(temp2,gm.pairing);

	element_random(u.x);
	element_mul(temp1,gm.g1,u.F);	//temp1 = g1F
	element_add(temp2,gm.s,u.x);	// temp2 = s+x
	element_invert(temp2, temp2);	//temp2 = 1/(s+x)
	element_pow_zn(u.A,temp1,temp2);// temp1 = (g1F)^{1/(s+x)}
	element_pow_zn(gm.LIST,gm.g,u.x);

	element_clear(temp1);
	element_clear(temp2);
}

/*
e(A,g2)^x e(A,S)  = e(g1,g2)e(g,g2)^y
*/
int Check_Certificate(GroupManager &gm, User &u)
{
	element_t result1, result2, temp;
	element_init_GT(result1, gm.pairing);
	element_init_GT(result2, gm.pairing);
	element_init_GT(temp, gm.pairing);

	element_pairing(result1, u.A,gm.g2);
	element_pow_zn(result1,result1,u.x);
	element_pairing(temp,u.A,gm.S);
	element_mul(result1,result1,temp);
	element_pairing(temp,gm.g,gm.g2);
	element_pow_zn(temp,temp,u.y[0]);

	element_pairing(result2,gm.g1,gm.g2);
	element_mul(result2,result2,temp);

	int cp = element_cmp(result1,result2);

	element_clear(temp);
	element_clear(result1);
	element_clear(result2);

	return cp;
}

grantproof Grant_User(GroupManager &gm, User &u)
{
	unsigned char patch[1000];
	element_t temp_G, temp_Z, temp_GT;
	element_init_G1(temp_G,gm.pairing);
	element_init_Zr(temp_Z,gm.pairing);
	element_init_GT(temp_GT,gm.pairing);

	grantproof pi(gm.pairing);
	
	element_t a, b, c, tao, z;
	element_t ra,rb,rc,rx,ry,rz,rtao;
	element_t R_alpha[2],R_beta[k+2],R_beta_p,R_gamma[2];

	element_init_Zr(a,gm.pairing);
	element_init_Zr(b,gm.pairing);
	element_init_Zr(c,gm.pairing);
	element_init_Zr(tao,gm.pairing);

	element_init_Zr(ra,gm.pairing);
	element_init_Zr(rb,gm.pairing);
	element_init_Zr(rc,gm.pairing);
	element_init_Zr(rx,gm.pairing);
	element_init_Zr(ry,gm.pairing);
	element_init_Zr(rz,gm.pairing);
	element_init_Zr(rtao,gm.pairing);

	element_init_G1(R_alpha[0], gm.pairing);
	element_init_GT(R_alpha[1], gm.pairing);
	for(int i=0; i!= k+2; i++)
	{
		element_init_G1(R_beta[i],gm.pairing);
	}
	element_init_G1(R_beta_p, gm.pairing);
	element_init_G1(R_gamma[0], gm.pairing);
	element_init_G1(R_gamma[1], gm.pairing);

	element_random(a);
	element_random(b);
	element_random(c);
	element_random(ra);
	element_random(rb);
	element_random(rc);
	element_random(rx);
	element_random(ry);
	element_random(rz);
	element_random(rtao);

	element_mul_zn(tao, a, u.x);
	element_init_same_as(z,u.y[k+1]);

	element_pow_zn(pi.alpha[0],u.u,a);
	element_pow_zn(pi.alpha[1],gm.g,a);
	element_mul(pi.alpha[1],u.A,pi.alpha[1]);

	element_pow_zn(pi.beta[0],gm.g1,b);
	for(int i=1; i != k+2; i++)
	{
		element_pow_zn(pi.beta[i],pi.beta[i-1],u.y[0]);
	}

	element_pow_zn(pi.gamma[0],gm.g1,c);
	element_mul(temp_Z, u.y[k], c);
	element_pow_zn(pi.gamma[1], gm.g1, temp_Z);
	element_mul(pi.gamma[1], pi.gamma[1], gm.LIST);
	
	/*
	\	Calculate R terms
	*/
	//------------ R_alpha 0
	element_pow_zn(R_alpha[0],pi.alpha[0],rx);//alpha0^rx
	element_neg(temp_Z, rtao);//-tao
	element_pow_zn(temp_G,u.u,temp_Z);//u^{-tao}
	element_mul(R_alpha[0],R_alpha[0],temp_G);
	//------------ R_alpha 1
	element_add(temp_Z, rtao, ry);
	element_pow_zn(R_alpha[1], u.gg2, temp_Z);
	element_pow_zn(temp_GT,u.gs, ra);
	element_mul(R_alpha[1], R_alpha[1], temp_GT);
	element_pairing(temp_GT, pi.alpha[1], gm.g2);
	element_neg(temp_Z,rx);
	element_pow_zn(temp_GT, temp_GT, temp_Z);
	element_mul(R_alpha[1],R_alpha[1], temp_GT);

	//--------- R_beta terms
	element_pow_zn(R_beta[0], gm.g1, rb);
	for(int i=1; i!= k+1; i++)
	{
		element_pow_zn(R_beta[i], R_beta[i-1], ry);
	}
	element_pow_zn(R_beta_p, pi.beta[0], rz);
	//--------R_gamma terms
	element_pow_zn(R_gamma[0], gm.g1, rc);
	element_pow_zn(R_gamma[1], gm.g1, rx);
	element_pow_zn(temp_G, pi.gamma[0], rz);
	element_mul(R_gamma[1],R_gamma[1], temp_G);
	//------------patch hash terms
	int patch_length = 0;
	patch_length += element_to_bytes_compressed(patch, gm.S);
	memcpy(patch+patch_length, u.Rpt, strlen(u.Rpt));
	patch_length += strlen(u.Rpt);
	patch_length += element_to_bytes_compressed(patch+patch_length,pi.alpha[0]);
	patch_length += element_to_bytes_compressed(patch+patch_length,R_alpha[0]);
	patch_length += element_to_bytes(patch+patch_length,pi.alpha[1]);
	patch_length += element_to_bytes(patch+patch_length,R_alpha[1]);
	for(int i=0; i!=k+1; i++)
	{
		patch_length += element_to_bytes_compressed(patch+patch_length, pi.beta[i]);
		patch_length += element_to_bytes_compressed(patch+patch_length, R_beta[i]);
	}
	patch_length += element_to_bytes_compressed(patch+patch_length, R_beta_p);
	for(int i = 0; i!=2; i++)
	{
		
		patch_length += element_to_bytes_compressed(patch+patch_length,pi.gamma[i]);
		patch_length += element_to_bytes_compressed(patch+patch_length,R_gamma[i]);
	}
	element_from_hash(pi.h,patch,patch_length);

	//
	element_mul_zn(pi.sa, pi.h,a);
	element_add(pi.sa,pi.sa,ra);
	//
	element_mul_zn(pi.sb, pi.h,b);
	element_add(pi.sb,pi.sb,rb);
	//
	element_mul_zn(pi.sc, pi.h,c);
	element_add(pi.sc,pi.sc,rc);
	//
	element_mul_zn(pi.sx, pi.h,u.x);
	element_add(pi.sx,pi.sx,rx);
	//
	element_mul_zn(pi.sy, pi.h,u.y[0]);
	element_add(pi.sy,pi.sy,ry);
	//
	element_mul_zn(pi.sz, pi.h,z);
	element_add(pi.sz,pi.sz,rz);
	//
	element_mul_zn(pi.stao, pi.h,tao);
	element_add(pi.stao,pi.stao,rtao);
	
	/*
	element_free(R_alpha[0]);
	element_free(R_alpha[1]);
	for(int i=0; i!= k+2; i++)
	{
		element_free(R_beta[i]);
	}
	element_free(R_beta_p);
	element_free(R_gamma[0]);
	element_free(R_gamma[1]);

	element_free(a);
	element_free(b);
	element_free(c);
	element_free(tao);
	element_free(z);
	element_free(ra);
	element_free(rb);
	element_free(rc);
	element_free(rx);
	element_free(ry);
	element_free(rz);
	element_free(rtao);

	element_free(temp_G);
	element_free(temp_Z);
	element_free(temp_GT);
	*/
	return pi;
}

int Grant_AP(grantproof &pi, GroupManager &gm, User &u)
{
	unsigned char patch[1000];
	element_t temp_G, temp_Z, temp_GT;
	element_init_G1(temp_G,gm.pairing);
	element_init_Zr(temp_Z,gm.pairing);
	element_init_GT(temp_GT,gm.pairing);


	element_t h_neg,h;
	element_init_Zr(h_neg,gm.pairing);
	element_neg(h_neg, pi.h);
	element_init_Zr(h, gm.pairing);

	element_t R_alpha[2],R_beta[k+2],R_beta_p,R_gamma[2];
	element_init_G1(R_alpha[0], gm.pairing);
	element_init_GT(R_alpha[1], gm.pairing);
	for(int i=0; i!= k+2; i++)
	{
		element_init_G1(R_beta[i],gm.pairing);
	}
	element_init_G1(R_beta_p, gm.pairing);
	element_init_G1(R_gamma[0], gm.pairing);
	element_init_G1(R_gamma[1], gm.pairing);

	element_pow_zn(R_alpha[0], pi.alpha[0], pi.sx);
	element_neg(temp_Z, pi.stao);
	element_pow_zn(temp_G, u.u, temp_Z);
	element_mul(R_alpha[0], R_alpha[0], temp_G);

	element_add(temp_Z, pi.stao, pi.sy);
	element_pow_zn(R_alpha[1], u.gg2, temp_Z);
	element_pow_zn(temp_GT, u.gs, pi.sa);
	element_mul(R_alpha[1], R_alpha[1], temp_GT);
	element_pairing(temp_GT, pi.alpha[1], gm.g2);
	element_neg(temp_Z, pi.sx);
	element_pow_zn(temp_GT, temp_GT, temp_Z);
	element_mul(R_alpha[1], R_alpha[1], temp_GT);
	element_pairing(temp_GT, pi.alpha[1], gm.S);
	element_div(temp_GT, u.g1g2, temp_GT);
	element_pow_zn(temp_GT, temp_GT, pi.h);
	element_mul(R_alpha[1], R_alpha[1], temp_GT);

	element_pow_zn(R_beta[0], gm.g1, pi.sb);
	element_pow_zn(temp_G, pi.beta[0], h_neg);
	element_mul(R_beta[0], R_beta[0], temp_G);

		for(int i=1; i!= k+2; i++)
		{
			element_pow_zn(R_beta[i], R_beta[i-1], pi.sy);
			element_pow_zn(temp_G, pi.beta[i-1], h_neg);
			element_mul(R_beta[i], R_beta[i], temp_G);
		}
		element_pow_zn(R_beta_p, R_beta[0], pi.sz);
		element_pow_zn(temp_G, pi.beta[k+1], h_neg);
		element_mul(R_beta_p, R_beta_p, temp_G);

	element_pow_zn(R_gamma[0], gm.g1, pi.sc);
	element_pow_zn(temp_G, pi.gamma[0], h_neg);
	element_mul(R_gamma[0], R_gamma[0], temp_G);

	element_pow_zn(R_gamma[1], gm.g1, pi.sx);
	element_pow_zn(temp_G, pi.gamma[0], pi.sz);
	element_mul(R_gamma[1], R_gamma[1], temp_G);
	element_pow_zn(temp_G, pi.gamma[1], h_neg);
	element_mul(R_gamma[1], R_gamma[1], temp_G);

	
	//------------patch hash terms
	int patch_length = 0;
	patch_length += element_to_bytes_compressed(patch, gm.S);
	memcpy(patch+patch_length, u.Rpt, strlen(u.Rpt));
	patch_length += strlen(u.Rpt);
	patch_length += element_to_bytes_compressed(patch+patch_length,pi.alpha[0]);
	patch_length += element_to_bytes_compressed(patch+patch_length,R_alpha[0]);
	patch_length += element_to_bytes(patch+patch_length,pi.alpha[1]);
	patch_length += element_to_bytes(patch+patch_length,R_alpha[1]);
	for(int i=0; i!=k+1; i++)
	{
		patch_length += element_to_bytes_compressed(patch+patch_length, pi.beta[i]);
		patch_length += element_to_bytes_compressed(patch+patch_length, R_beta[i]);
	}
	patch_length += element_to_bytes_compressed(patch+patch_length, R_beta_p);
	for(int i = 0; i!=2; i++)
	{
		
		patch_length += element_to_bytes_compressed(patch+patch_length,pi.gamma[i]);
		patch_length += element_to_bytes_compressed(patch+patch_length,R_gamma[i]);
	}
	element_from_hash(h,patch,patch_length);

	return element_cmp(pi.h, h);
}

int main()
{
	cout<< "Program Begin..." << endl;

	GroupManager gm;
	AppProvider ap(gm);
	User u(gm);

	//gm.ShowParamters();

	cout<<"Joining Processing..."<<endl;
	join(gm,u);	
	cout<<"The Certificate is "<<(Check_Certificate(gm,u)==Same?"valid":"invalid")<<endl;
	
	cout<<"Generateing the Grant Proof..."<<endl;
	grantproof pi = Grant_User(gm,u);
	int isValue = Grant_AP(pi, gm, u);
	cout<< "The Grant Information of User is " << ( isValue == Same ? "Valid":"Invalid")<<endl;


//--------Authentication-User Begin
	int w = 0;
	int l = 1; //require times
	int t = 0;
	unsigned char patch[500];
	int patch_length;
	memset(patch, 0, 500);
	element_t temp_G;
	element_init(temp_G, gm.pairing->G1);

	//----
	t = w + l;
	if(t > k) return -1;

	element_t sz, h, gammat;//These three terms consists of the proof
	element_t h_neg;
	element_init(sz, gm.pairing->Zr);
	element_init(h, gm.pairing->Zr);
	element_init(gammat, gm.pairing->G1);
	element_init(h_neg, gm.pairing->Zr);
	element_neg(h_neg, pi.h);
	
	element_t hp;
	element_init(hp, gm.pairing->Zr);
	//--------------------------------------

	element_pow_zn(gammat, pi.gamma[0], u.y[t-1]);
	element_init(gammat, gm.pairing->G1);

	element_t R1,R2, rz;
	element_init(R1, gm.pairing->G1);
	element_init(R2, gm.pairing->G1);
	element_init(rz, gm.pairing->Zr);

	element_random(rz);
	element_pow_zn(R1, pi.beta[0], rz);
	element_pow_zn(R2, pi.gamma[0], rz);
	
	//------------patch hash terms
	patch_length = 0;
	patch_length += element_to_bytes_compressed(patch, gm.S);
	memcpy(patch+patch_length, u.Rpt, strlen(u.Rpt));
	patch_length += strlen(u.Rpt);
	sprintf((char*) patch+patch_length, "%d%d", w, t);
	patch_length += element_to_bytes_compressed(patch+patch_length,gammat);
	patch_length += element_to_bytes_compressed(patch+patch_length,R1);
	patch_length += element_to_bytes_compressed(patch+patch_length,R2);
	element_from_hash(h,patch,patch_length);
	//--------Authentication-AP Begin
	
	t = w + l;
	if(t > k) return -1;
	element_pow_zn(R1, pi.gamma[0], pi.sz);
	element_pow_zn(temp_G, pi.gamma[t], h_neg);
	element_mul(R1, R1, temp_G);

	element_pow_zn(R2, pi.beta[0], pi.sz);
	element_pow_zn(temp_G, pi.beta[t], h_neg);
	element_mul(R2, R2, temp_G);

	patch_length = 0;
	patch_length += element_to_bytes_compressed(patch, gm.S);
	memcpy(patch+patch_length, u.Rpt, strlen(u.Rpt));
	patch_length += strlen(u.Rpt);
	sprintf((char*) patch+patch_length, "%d%d", w, t);
	patch_length += element_to_bytes_compressed(patch+patch_length,gammat);
	patch_length += element_to_bytes_compressed(patch+patch_length,R1);
	patch_length += element_to_bytes_compressed(patch+patch_length,R2);
	element_from_hash(hp,patch,patch_length);

	int isValid = element_cmp(h, hp);
	cout<< "The Authentication is " << ( isValue == Same ? "Valid":"Invalid")<<endl;

	
	cout<< endl<<"Program Ending..." <<endl <<"Clearing Datas..."<<endl;

	return 0;
}