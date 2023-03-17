#include <pbc/pbc.h>
#include <pbc/pbc_field.h>
#include <pbc/pbc_pairing.h>
#include <pbc/pbc_utils.h>
#include <pbc/pbc_param.h>
#include <pbc/pbc_a_param.h>
#include <pbc/pbc_a1_param.h>
#include <pbc/pbc_curve.h>
#include <pbc/pbc_d_param.h>
#include <pbc/pbc_e_param.h>
#include <pbc/pbc_fieldquadratic.h>
#include <pbc/pbc_fp.h>
#include <pbc/pbc_f_param.h>
#include <pbc/pbc_g_param.h>
#include <pbc/pbc_hilbert.h>
#include <pbc/pbc_i_param.h>
#include <pbc/pbc_memory.h>
#include <pbc/pbc_mnt.h>
#include <pbc/pbc_multiz.h>
#include <pbc/pbc_poly.h>
#include <pbc/pbc_random.h>
#include <pbc/pbc_singular.h>
#include <pbc/pbc_ternary_extension_field.h>
#include <pbc/pbc_z.h>
#include <pbc/pbc_test.h>

// #include <string.h>
// #include<stdio.h>
// #include<gmp.h>
// #include<stdlib.h>


struct pubkey
{
    char * pairingDesc;
    pairing_s p;
    // pairing_s p;
    // element_s g, h, f, gp, g_hat_alpha;
};

// struct mstkey
// {
// public:
//     element_s beta, g_alpha;
// };
// string curveParams = "type a\n" + "q 87807107996633125224377819847540498158068831994142082" + "1102865339926647563088022295707862517942266222142315585" + "8769582317459277713367317481324925129998224791\n" +"h 12016012264891146079388821366740534204802954401251311" + "822919615131047207289359704531102844802183906537786776\n" + "r 730750818665451621361119245571504901405976559617\n" + "exp2 159\n"+ "exp1 107\n" + "sign1 1\n" + "sign0 1\n";


// void setup(pubkey & pub_key, mstkey &msk_key);
int main(int args, char * argv)
{
    // pubkey pub_key = pubkey();
    // mstkey msk_key = mstkey();
    // setup(pub_key, msk_key);
    // cout << "program terminated !!!";
    return 0;
}

// void setup(pubkey &pub_key, mstkey &msk_key)
// {
//     element_s alpha, beta_inv;
//     element_t et;
//     pairing_t pt;
//     pairing_t pairing;
//     char param[1024];
//     size_t count = fread(param, 1, 1024, stdin);
//     if (!count) cout << "input error";
//     // pairing_init_set_buf(pairing, param, count);
//     // element_s * element_t = new element_s();
//     // pairing_s * pairing_t = new pairing_s();
//     // element_init_G1(et, pt);
//     // element_init_G1(et, pt);
//     // cout << et[0] << pt[0];
//     // element_init_G1(et, pt);
//     pbc_die((const char *)"error");
//     // pt->G1->init(et);

// }