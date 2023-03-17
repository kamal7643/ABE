#include <iostream>
#include <string.h>
#include <stdio.h>

#include <pbc/pbc.h>
#include <pbc/pbc_field.h>
#include <pbc/pbc_test.h>

using namespace std;

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
char curveParams[500] = "type a\nq\n8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\nh\n12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\nr 730750818665451621361119245571504901405976559617\nexp2 159\nexp1 107\nsign1 1\nsign0 1\n";
string cp = "type a\nq\n8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\nh\n12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\nr 730750818665451621361119245571504901405976559617\nexp2 159\nexp1 107\nsign1 1\nsign0 1\n";

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
        if (pairing_init_set_buf(pub_key.p, (const char *)curveParams, 359))
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
        memcpy(msk_key.g_alpha->data, pub_key.gp->data, 1 * sizeof(pub_key.gp->data));
        // msk_key.g_alpha->data=pub_key.gp->data;
        memcpy(msk_key.g_alpha->field, pub_key.gp->field, 1 * sizeof(pub_key.gp->field));
        // msk_key.g_alpha->field=pub_key.gp->field;

        // element_pow_zn();
        element_pow_zn(msk_key.g_alpha, msk_key.g_alpha, alpha);

        // beta_inv = msk.beta.duplicate();
        // beta_inv.invert();
        // pub.f = pub.g.duplicate();
        // pub.f.powZn(beta_inv);

        memcpy(beta_inv->data, msk_key.beta->data, sizeof(msk_key.beta->data));
        memcpy(beta_inv->field, msk_key.beta->field, sizeof(msk_key.beta->field));
    }
};

int main(int args, char **argv)
{
    pubkey pub_key = pubkey();
    mstkey msk_key = mstkey();
    cpabe test =  cpabe();
    test.setup(args, argv, pub_key, msk_key);
    cout << "program terminated !!!";
    return 0;
}



//./main <~/Downloads/pbc/param/a.param