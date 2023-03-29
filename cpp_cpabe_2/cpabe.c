// #include <iostream>
#include <glib.h>
#include <pbc/pbc.h>
#include <pbc/pbc_field.h>
#include <pbc/pbc_test.h>
#include <aes.h>
#include "cpabe.h"
#include "bswabe.h"
#include "common.h"

// using namespace std;

char *pub_file = (char *)"pub_key";
char *msk_file = (char *)"master_key";
bswabe_pub_t *pub;
bswabe_msk_t *msk;

void setup(){
    bswabe_setup(&pub, &msk);
}

// class app
// {
// public:
//     char *pub_file = (char *)"pub_key";
//     char *msk_file = (char *)"master_key";
//     bswabe_pub_t *pub;
//     bswabe_msk_t *msk;
//     void setup()
//     {
//         bswabe_setup(&pub, &msk);
//         spit_file(pub_file, bswabe_pub_serialize(pub), 1);
//         // spit_file(msk_file, bswabe_msk_serialize(msk), 1);
//     };
//     void keygen();
//     void enc();
//     void dec();
// };

int main()
{
    // app abe = app();
    // abe.setup();
    printf("done");

    return 0;
}

//  gcc -o main -Wall -I/opt/homebrew/include/glib-2.0 -I/opt/homebrew//Cellar/glib/2.76.1/lib/glib-2.0/include/ -I/usr/local/include/node/openssl -I/usr/local/include/node/ -I/opt/homebrew/Cellar/openssl@3/3.1.0/lib cpabe.c bswabe_core.c -L. -lgmp -lpbc -lcrypto