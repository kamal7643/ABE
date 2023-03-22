#include <iostream>
#include <string.h>
#include <string>
#include <stdio.h>
#include <vector>
#include <cstddef>
#include <bitset>
#include <inttypes.h>
#include <hashlib++/hashlibpp.h>
#include <fstream>

#include <pbc/pbc.h>
#include <pbc/pbc_field.h>
#include <pbc/pbc_test.h>


// #include <openssl/aes.h>
// #include <openssl/rand.h>
// #include <openssl/err.h>
// #include <node/openssl/aes.h>
// #include <node/openssl/rand.h>
// #include <node/openssl/err.h>
// #include <openssl/aes.h>

using namespace std;

int LOG = 1;
std::ostream& operator<< (std::ostream& os, std::byte b) {
    return os << std::bitset<8>(std::to_integer<int>(b));
}

class bswabePubKey
{
public:
    char *pairingDesc;
    pairing_t p;
    element_t g, h, f, gp, g_hat_alpha;
};

class bswabeMskKey
{
public:
    element_t beta, g_alpha;
};

class bswabePrvComp
{
public:
    string attr;
    element_t d;
    element_t dp;

    int used;
    element_t z;
    element_t zp;
};

class bswabePrvKey
{
public:
    element_t d;
    vector<bswabePrvComp> comps;
};

class bswabePolinomial{
    int deg;
    vector<element_t> coef;
};

class bswabePolicy{
    int k;
    string attr;
    element_t c;
    element_t cp;

    vector<bswabePolicy> children;

    bswabePolinomial q;
    bool satisfiable;
    int min_leaves;
    int attri;

    vector<int> satl;

    int simplify(string file_attr){
        cout << "remove file elements\n";
        return 0;
    }
};

class bswabeCph{
    public:
    element_t c;
    element_t cs;
    bswabePolicy p;
};

class bswabeCphKey{
    public:
    element_t key;
    bswabeCph cph;
};

class common
{
public:
    byte *suckFile(string inputfile)
    {
        ifstream is(inputfile);
        string data ="";
        char buf[4096];
        do {
            is.read(buf, sizeof(buf));
            // is >> buf;
            data+=buf;
        } while(is);
        // cout << data;

        // ifstream infile; 
        // infile.open(inputfile); 
        // ofstream outfile ;
        // outfile.open(inputfile);
        // outfile << "working!";
        // outfile.close();
        // vector<byte> res ;
        // if (infile.is_open())
        // {
        //     char mychar;
        //     while (infile)
        //     {
        //         infile >> mychar;
        //         res.push_back((byte)mychar);
        //     }
            
        // }
        // infile.close();
        // cout << res.size();
        byte * r = (byte *)malloc(sizeof(byte)*data.size());
        for(int i=0; i<data.size(); i++)r[i]=(byte)data[i];
        return r;
    }

    void spitFile(string outputfile, byte * data){
    }
};

/*class AESCoder {
private:
    static const int KEY_SIZE = 16; // 128 bits
    static const int BLOCK_SIZE = 16; // 128 bits

    static void handleErrors(void)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

public:
    static void getRawKey(unsigned char* seed, unsigned char* rawKey) {
        AES_KEY aesKey;
        if (AES_set_encrypt_key(seed, KEY_SIZE * 8, &aesKey) < 0) {
            std::cerr << "Failed to set AES key." << std::endl;
            handleErrors();
        }
        std::memcpy(rawKey, aesKey.rd_key, KEY_SIZE);
    }

    static void encrypt(unsigned char* seed, unsigned char* plaintext, int plaintext_len, unsigned char* ciphertext) {
        unsigned char rawKey[KEY_SIZE];
        getRawKey(seed, rawKey);
        AES_KEY aesKey;
        if (AES_set_encrypt_key(rawKey, KEY_SIZE * 8, &aesKey) < 0) {
            std::cerr << "Failed to set AES key." << std::endl;
            handleErrors();
        }
        AES_encrypt(plaintext, ciphertext, &aesKey);
    }

    static void decrypt(unsigned char* seed, unsigned char* ciphertext, int ciphertext_len, unsigned char* plaintext) {
        unsigned char rawKey[KEY_SIZE];
        getRawKey(seed, rawKey);
        AES_KEY aesKey;
        if (AES_set_decrypt_key(rawKey, KEY_SIZE * 8, &aesKey) < 0) {
            std::cerr << "Failed to set AES key." << std::endl;
            handleErrors();
        }
        AES_decrypt(ciphertext, plaintext, &aesKey);
    }
};
*/
class serializeUtils
{
public:
vector<byte> serializeBswabeCph(){
    vector<byte> res;
    return res;
}
void serializeUint32(std::vector<byte>& arrlist, int k) {
    byte b;
    
    for (int i = 3; i >= 0; i--) {
        b = static_cast<byte>((k & (0x000000ff << (i * 8))) >> (i * 8));
        arrlist.push_back(b);
    }
}

int unserializeUint32(vector<byte> arr, int offset){
    int i, r=0;

    for(i=3; i>=0; i--){
        r |= (this->byte2int((char)arr[offset++])<<(i*8));
    }
    return r;
}
int byte2int(char b) {
    if (b >= 0) {
        return b;
    } else {
        return (256 + b);
    }
}
};
class langPolicy
{
public:
    vector<string> parseAttribute(string attr)
    {
        attr += " ";
        vector<string> res;
        string tok1 = "", tok2 = "";
        bool stop1 = false;
        for (char c : attr)
        {
            if (c == ' ')
            {
                if (tok1 != "" && tok2 != "")
                {
                    res.push_back(tok1 + ":" + tok2);
                    tok1 = "";
                    tok2 = "";
                    stop1 = false;
                }
            }
            else if (c == ':')
            {
                stop1 = true;
            }
            else
            {
                if (stop1)
                {
                    tok2 += c;
                }
                else
                {
                    tok1 += c;
                }
            }
        }

        return res;
    }
};

class bswabe
{
public:
    void setup(bswabePubKey &pub_key, bswabeMskKey &msk_key)
    {
        element_t alpha, beta_inv;
        pairing_t pairing;
        char param[1024] = "type a\nq 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\nh 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\nr 730750818665451621361119245571504901405976559617\nexp2 159\nexp1 107\nsign1 1\nsign0 1\n";

        // pairingDesc
        pub_key.pairingDesc = param;
        // p
        // pub_key.p=pairing;
        if (pairing_init_set_buf(pub_key.p, (const char *)param, strlen((char *)param)))
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
    }

    bswabePrvKey keygen(bswabePubKey pk, bswabeMskKey msk, vector<string> attrs)
    {
        bswabePrvKey prv_key = bswabePrvKey();
        element_t g_r, r, beta_inv;
        pairing_t p;
        // memcpy(p, pk.p, sizeof(pk.p));
        element_init_G2(prv_key.d, pk.p);
        element_init_G2(g_r, pk.p);
        element_init_Zr(r, pk.p);
        element_init_Zr(beta_inv, pk.p);

        element_random(r);
        element_init_same_as(g_r, pk.gp);
        element_pow_zn(g_r, g_r, r);

        element_init_same_as(prv_key.d, msk.g_alpha);
        element_mul(prv_key.d, prv_key.d, g_r);
        element_init_same_as(beta_inv, msk.beta);
        element_invert(beta_inv, beta_inv);

        int i, len = attrs.size();

        prv_key.comps = vector<bswabePrvComp>();

        for (i = 0; i < len; i++)
        {
            bswabePrvComp comp = bswabePrvComp();
            element_t h_rp, rp;

            comp.attr = attrs[i];

            element_init_G2(comp.d, pk.p);
            element_init_G1(comp.dp, pk.p);
            element_init_G2(h_rp, pk.p);
            element_init_Zr(rp, pk.p);

            // MessageDigest
            elementFromString(h_rp, comp.attr);

            element_random(rp);
            element_pow_zn(h_rp, h_rp, rp);

            element_init_same_as(comp.d, g_r);
            element_mul(comp.d, comp.d, h_rp);
            element_init_same_as(comp.dp, pk.g);
            element_pow_zn(comp.dp, comp.dp, rp);

            prv_key.comps.push_back(comp);
        }

        return prv_key;
    }

    // dep functions
    void elementFromString(element_t &h, string s)
    {
        hashwrapper *myWrapper = new md5wrapper();
        string bytes = myWrapper->getHashFromString(s);
        char *bytes_byte = (char *)malloc(sizeof(char) * bytes.size());
        for (int i = 0; i < bytes.size(); i++)
            bytes_byte[i] = (char)bytes[i];
        element_from_bytes(h, (const unsigned char *)bytes_byte);
        // MessageDigest md = MessageDigest.getInstance("SHA-1");
        // byte[] digest = md.digest(s.getBytes());
        // h.setFromHash(digest, 0, digest.length);
    }
};

class cpabe
{
public:
    bswabe bs;
    bswabePubKey pub;
    bswabeMskKey msk;
    bswabePrvKey prv;
    common cm;
    serializeUtils ser;
    langPolicy lan;

    void setup()
    {
        this->bs = bswabe();
        this->pub = bswabePubKey();
        this->msk = bswabeMskKey();
        cm = common();
        ser = serializeUtils();
        lan = langPolicy();
        this->bs.setup(this->pub, this->msk);
    }

    void keygen(string attr)
    {
        this->prv = bswabePrvKey();
        vector<string> attrs = this->lan.parseAttribute(attr);
        this->prv = this->bs.keygen(this->pub, this->msk, attrs);
    }

    void enc(string inputfile, string encfile)
    {
        byte *plt;
        plt = this->cm.suckFile(inputfile);
        
    }
};

int main(int args, char **argv)
{
    string path = "/Users/kamalswami/Documents/ABE/.ABE_DIR";
    string user = "name:kamal age:20";
    string policy = "name:kamal age:20 2of2";
    string test = "test01";
    cpabe abe = cpabe();
    abe.setup();
    abe.keygen(user);
    abe.enc(path + "/input.txt", path + "/input.txt.cpabe");
    return 0;
}

/*
http://gas.dia.unisa.it/projects/jpbc/docs/pairing.html#initializing
https://crypto.stanford.edu/pbc/manual.pdf
https://sourceforge.net/projects/hashlib2plus/files/latest/download
g++ cpabe.cpp -o main -L. -lgmp -lpbc -lhl++
 g++ -std=c++17 /opt/homebrew/opt/openssl@3/lib cpabe.cpp -o main -L. -lgmp -lpbc -lhl++ -lssl
 export LDFLAGS="-L/opt/homebrew/opt/openssl@3/lib"        
  export CPPFLAGS="-I/opt/homebrew/opt/openssl@3/include"
*/

//./main <~/Downloads/pbc/param/a.param
// https://www. youtube.com/watch?v=f7S5vCr_cQY
//git clone git://git.openssl.org/openssl.git

/*
current working function stack
main
cpabe.enc

*/

/*
errors
includeing openssl

*/