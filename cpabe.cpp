#include <iostream>
#include <string.h>
#include <string>
#include <stdio.h>
#include <vector>
#include <cstddef>
#include <bitset>
#include <inttypes.h>

#include <pbc/pbc.h>
#include <pbc/pbc_field.h>
#include <pbc/pbc_test.h>

typedef uint8_t byte;
using namespace std;

int LOG =1;

class pubkey
{
public:
    string pairingDesc;
    pairing_t p;
    element_t g, h, f, gp, g_hat_alpha;
};

class mstkey
{
public:
    element_t beta, g_alpha;
};
char curveParams[500] = "type a\nq 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\nh 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\nr 730750818665451621361119245571504901405976559617\nexp2 159\nexp1 107\nsign1 1\nsign0 1\n";
string cp = "type a\nq 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\nh 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\nr 730750818665451621361119245571504901405976559617\nexp2 159\nexp1 107\nsign1 1\nsign0 1\n";

class cpabe
{

public:
    void setup(int args, char **argv, pubkey &pub_key, mstkey &msk_key)
    {
        element_t alpha, beta_inv;
        pairing_t pairing;
        char param[1024];

        // pairingDesc
        pub_key.pairingDesc = cp;
        // p
        // pub_key.p=pairing;
        if (pairing_init_set_buf(pub_key.p, (const char *)curveParams, cp.size()))
            pbc_die("pairing init failed");
        // g
        element_init_G1(pub_key.g, pub_key.p);
        // element_from_hash(pub_key.g, "hashofmessage", 13);
        // h
        element_init_G1(pub_key.h, pub_key.p);
        // element_from_hash(pub_key.h, "hashofmessage", 13);
        // f
        element_init_G1(pub_key.f, pub_key.p);
        // element_from_hash(pub_key.f, "hashofmessage", 13);
        // gp
        element_init_G2(pub_key.gp, pub_key.p);
        // element_random(pub_key.gp);
        // g_hat_alpha
        element_init_GT(pub_key.g_hat_alpha, pub_key.p);
        // alpha
        element_init_Zr(alpha, pub_key.p);
        // beta
        element_init_Zr(msk_key.beta, pub_key.p);
        // g_alpha
        element_init_Zr(msk_key.g_alpha, pub_key.p);

        element_random(alpha);
        element_random(msk_key.beta);
        element_random(pub_key.g);
        element_random(pub_key.gp);

        // msk_key.g_alpha=pub_key.gp.duplicate();
        element_init_same_as(msk_key.g_alpha, pub_key.gp);
        // memcpy(msk_key.g_alpha->data, pub_key.gp->data, 1 * sizeof(pub_key.gp->data));
        // // msk_key.g_alpha->data=pub_key.gp->data;
        // memcpy(msk_key.g_alpha->field, pub_key.gp->field, 1 * sizeof(pub_key.gp->field));
        // msk_key.g_alpha->field=pub_key.gp->field;

        // // element_pow_zn();
        element_pow_zn(msk_key.g_alpha, msk_key.g_alpha, alpha);

        // beta_inv = msk.beta.duplicate();
        // beta_inv.invert();
        // pub.f = pub.g.duplicate();
        // pub.f.powZn(beta_inv);
        element_init_same_as(beta_inv, msk_key.beta);
        element_invert(beta_inv, beta_inv);
        element_init_same_as(pub_key.f, pub_key.g);
        element_pow_zn(pub_key.f, pub_key.f, beta_inv);


        // pub.h = pub.g.duplicate();
		// pub.h.powZn(msk.beta);

        element_init_same_as(pub_key.h, pub_key.g);
        element_pow_zn(pub_key.h, pub_key.h, msk_key.beta);

		// pub.g_hat_alpha = pairing.pairing(pub.g, msk.g_alpha);

        element_pairing(pub_key.g_hat_alpha, pub_key.g, msk_key.g_alpha);
        printPubKey(pub_key);
        // uint8_t bt;
        // cout << (unsigned)bt;

        // vector<uint32_t> o =serializePubKey(pub_key);

        // for(int i=0; i<o.size(); i++)cout << (unsigned)o[i];
        

    }

    void keygen(){

    }

    void enc(){

    }

    void dec(){

    }

    void printPubKey(pubkey pk){
        cout << pk.pairingDesc << "\n";
        element_printf("g %B\n", pk.g);
        element_printf("f %B\n", pk.f);
        element_printf("g_hat_alpha %B\n", pk.g_hat_alpha);
        element_printf("gp %B\n", pk.gp);
        element_printf("h %B\n", pk.h);
        // element_printf("p %B\n", pk.p);
    }

    vector<uint32_t> serializePubKey(pubkey pk){
        vector<uint32_t> arrlist;
        serializeString(arrlist, pk.pairingDesc);
        return arrlist;

    };

    void serializeString(vector<uint32_t> arrlist, string s) {
		vector<uint32_t> b;
        for(int i=0; i<s.size(); i++)b.push_back(uint32_t(s[i]));
		serializeUint32(arrlist, b.size());
		byteArrListAppend(arrlist, b);
	}

    void serializeUint32(vector<uint32_t> arrlist, int k) {
		int i;
		uint32_t b;
	
		for (i = 3; i >= 0; i--) {
			b = (uint32_t) ((k & (0x000000ff << (i * 8))) >> (i * 8));
			// arrlist.add(Byte.valueOf(b));
            arrlist.push_back(uint32_t(b));
		}
	}

    void byteArrListAppend(vector<uint32_t> arrlist, vector<uint32_t> b) {
		int len = b.size();
		for (int i = 0; i < len; i++)
			arrlist.push_back(uint32_t(b[i]));
	}


    void log(string s){
        if(LOG){
            cout << s << "\n";
        }
    }
};

int main(int args, char **argv)
{
    pubkey pub_key = pubkey();
    mstkey msk_key = mstkey();
    cpabe test =  cpabe();
    test.log("start setup");
    test.setup(args, argv, pub_key, msk_key);
    test.log("end setup");
    test.log("start enc");
    test.enc();
    test.log("end enc");
    test.log("start keygen");
    test.keygen();
    test.log("end keygen");
    test.log("start dec");
    test.dec();
    test.log("end dec");
    return 0;
}


/*
http://gas.dia.unisa.it/projects/jpbc/docs/pairing.html#initializing
https://crypto.stanford.edu/pbc/manual.pdf
*/

//./main <~/Downloads/pbc/param/a.param
//https://www. youtube.com/watch?v=f7S5vCr_cQY