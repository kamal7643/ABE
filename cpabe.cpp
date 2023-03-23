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

std::ostream &operator<<(std::ostream &os, std::byte b)
{
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

class bswabePolinomial
{
public:
    int deg;
    element_t coef[1000];
};

class bswabePolicy
{
public:
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

    int simplify(string file_attr)
    {
        cout << "remove file elements\n";
        return 0;
    }
};

class bswabeCph
{
public:
    element_t c;
    element_t cs;
    bswabePolicy p;
};

class bswabeCphKey
{
public:
    element_t key;
    bswabeCph cph;
};

class common
{
public:
vector<char> suckFile(string inputfile) {
    ifstream is(inputfile, ios::binary);
    vector<char> content((istreambuf_iterator<char>(is)), istreambuf_iterator<char>());
    return content;
}

/* write byte[] into outputfile */
void spitFile(string outputfile, vector<char> b) {
    ofstream os(outputfile, ios::binary);
    os.write(&b[0], b.size());
}

void writeCpabeFile(string encfile, vector<char> cphBuf, vector<char> aesBuf) {
    int i;
    ofstream os(encfile, ios::binary);

    /* write aes_buf */
    for (i = 3; i >= 0; i--)
        os.put(((aesBuf.size() & (0xff << 8 * i)) >> 8 * i));
    os.write(&aesBuf[0], aesBuf.size());

    /* write cph_buf */
    for (i = 3; i >= 0; i--)
        os.put(((cphBuf.size() & (0xff << 8 * i)) >> 8 * i));
    os.write(&cphBuf[0], cphBuf.size());

    os.close();
}

vector<vector<char>> readCpabeFile(string encfile) {
    int i, len;
    ifstream is(encfile, ios::binary);
    vector<vector<char>> res(2);
    vector<char> aesBuf, cphBuf;

    /* read aes buf */
    len = 0;
    for (i = 3; i >= 0; i--)
        len |= is.get() << (i * 8);
    aesBuf.resize(len);

    is.read(&aesBuf[0], aesBuf.size());

    /* read cph buf */
    len = 0;
    for (i = 3; i >= 0; i--)
        len |= is.get() << (i * 8);
    cphBuf.resize(len);

    is.read(&cphBuf[0], cphBuf.size());

    is.close();

    res[0] = aesBuf;
    res[1] = cphBuf;

    return res;
}
    /*byte *suckFile(string inputfile)
    {
        ifstream is(inputfile);
        string data = "";
        char buf[4096];
        do
        {
            is.read(buf, sizeof(buf));
            // is >> buf;
            data += buf;
        } while (is);
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
        byte *r = (byte *)malloc(sizeof(byte) * data.size());
        for (int i = 0; i < data.size(); i++)
            r[i] = (byte)data[i];
        return r;
    }

    void spitFile(string outputfile, byte *data)
    {
    }*/
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
    vector<char> serializeBswabeCph(bswabeCph cph)
    {
        vector<char> arr;
        this->serializeElement(arr, cph.cs);
        this->serializeElement(arr, cph.c);

        return arr;
    }

    void serializePolicy(vector<char> & arr, bswabePolicy p){
        this->serializeUint32(arr, p.k);

        if(p.children.size()==0){
            this->serializeUint32(arr, 0);
            
        }else{

        }
    }

    void serializeString(vector<char> &arr, string s){
        
    }
    void serializeUint32(std::vector<char> &arrlist, int k)
    {
        char b;

        for (int i = 3; i >= 0; i--)
        {
            b = static_cast<char>((k & (0x000000ff << (i * 8))) >> (i * 8));
            arrlist.push_back(b);
        }
    }

    int unserializeUint32(vector<char> arr, int offset)
    {
        int i, r = 0;

        for (i = 3; i >= 0; i--)
        {
            r |= (this->byte2int((char)arr[offset++]) << (i * 8));
        }
        return r;
    }
    int byte2int(char b)
    {
        if (b >= 0)
        {
            return b;
        }
        else
        {
            return (256 + b);
        }
    }

    void serializeElement(vector<char>& arr, element_t e){
        char * s;
        element_to_bytes((unsigned char *)s, e);
        int len = strlen((char *)s);
        this->serializeUint32(arr,len );
        this->byteArrListAppend(arr, s);
        

    }

    void byteArrListAppend(vector<char>& arr, char * b){
        int len = strlen(b);
        for(int i=0; i<len; i++){
            arr.push_back(b[i]);
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

    bswabeCphKey enc(bswabePubKey pub, string policy)
    {
        bswabeCphKey cphkey = bswabeCphKey();
        bswabeCph cph = bswabeCph();
        element_t s, m;

        // pairing_t pairing = pub.p;
        element_init_Zr(s, pub.p);
        element_init_GT(m, pub.p);

        element_init_GT(cph.cs, pub.p);
        element_init_G1(cph.c, pub.p);

        cph.p = this->parsePolicyPostfix(policy);


        element_random(m);
        element_random(s);

        element_init_same_as(cph.cs, pub.g_hat_alpha);

        element_pow_zn(cph.cs, cph.cs,s);

        element_mul(cph.cs, cph.cs, m);

        element_init_same_as(cph.c, pub.h);

        element_pow_zn(cph.c, cph.c, s);

        this->fillPolicy(cph.p, pub, s);

        cphkey.cph = cph;
        // cphkey.key = m;
        element_init_same_as(cphkey.key, m);

        return cphkey;
    }

    // dep functions

    void fillPolicy(bswabePolicy & p, bswabePubKey pub, element_t e){
        int i;
        element_t r, t, h;

        // pairing_t pairing = pub.p;

        element_init_Zr(r, pub.p);
        element_init_Zr(t, pub.p);
        element_init_G2(h, pub.p);

        p.q = this->randPoly(p.k-1, e);

        if(p.children.size()==0){
            element_init_G1(p.c, pub.p);
            element_init_G2(p.cp, pub.p);

            this->elementFromString(h, p.attr);
            element_init_same_as(p.c, pub.g);
            element_pow_zn(p.c, p.c, p.q.coef[0]);
            element_init_same_as(p.cp, h);
            element_pow_zn(p.cp, p.cp, p.q.coef[0]);
        }else{
            for(int i=0; i<p.children.size(); i++){
                element_set_si(r, (signed long)(i+1));
                evalPoly(t, p.q, r);
                this->fillPolicy(p.children[i], pub, t);
            }
        }
    }

    void evalPoly(element_t r, bswabePolinomial q, element_t x)
    {
        int i;
        element_t s, t;

        element_init_same_as(s, r);
        element_init_same_as(t, r);

        element_set0(r);
        element_set1(t);

        for (int i = 0; i < q.deg + 1; i++)
        {
            element_init_same_as(s, q.coef[i]);
            element_mul(s, s, t);
            element_add(r, r, s);
            element_mul(t, t, x);
        }
    }

    bswabePolinomial randPoly(int deg, element_t zeroVal){
        int i;
        bswabePolinomial q = bswabePolinomial();
        q.deg = deg;
        // q.coef = new element_t[deg+1];

        for(int i=0; i<deg+1; i++){
            element_init_same_as(q.coef[i], zeroVal);
        }

        element_set(q.coef[0], zeroVal);

        for(int i=1; i<deg+1; i++){
            element_random(q.coef[i]);
        }

        return q;
    }

    bswabePolicy parsePolicyPostfix(string s)
    {
        vector<string> toks;
        string tok;

        vector<bswabePolicy> stack;

        bswabePolicy root;

        toks = this->splitBySpace(s);

        int toks_cnt = toks.size();

        for (int index = 0; index < toks_cnt; index++)
        {
            int i, k, n;
            tok = toks[index];

            if (tok.find("of") == string::npos)
            {
                stack.push_back(this->baseNode(1, tok));
            }
            else
            {
                bswabePolicy node;
                vector<string> k_n = this->splitByOf(tok);
                k = stoi(k_n[0]);
                n = stoi(k_n[1]);

                if (k < 1)
                {
                    cout << "error parsing " + s + ": trivially satisfied operator " + tok;
                    return root;
                }
                else if (k > n)
                {
                    cout << "error parsing " + s + ": unsatisfiable operator " + tok;
                    return root;
                }
                else if (n == 1)
                {
                    cout << "error parsing " + s + ": indentity operator " + tok;
                    return root;
                }
                else if (n > stack.size())
                {
                    cout << "error parsing " + s + ": stack underflow at  " + tok;
                    return root;
                }

                node = this->baseNode(k, "");
                node.children = vector<bswabePolicy>(n);

                for (i = n - 1; i >= 0; i--)
                {
                    node.children[i] = stack[i];
                    stack.pop_back();
                }

                stack.push_back(node);
            }
        }

        if (stack.size() > 1)
        {
            cout << "error parsing " + s + ": extra node left on the stack";
            return root;
        }
        else if (stack.size() < 1)
        {
            cout << "error parsing " + s + ": s empty policy";
            return root;
        }
        root = stack[0];
        return root;
    }

    vector<string> splitByOf(string tok)
    {
        vector<string> res(2);
        int found = tok.find("of");
        res[0] = tok.substr(0, found);
        res[1] = tok.substr(found + 2, tok.size());
        return res;
    }

    bswabePolicy baseNode(int k, string s)
    {
        bswabePolicy p = bswabePolicy();
        p.k = k;
        p.attr = s;

        return p;
    }
    vector<string> splitBySpace(string s)
    {
        s += " ";
        vector<string> res;
        string temp = "";
        for (int i = 0; i < s.size(); i++)
        {
            if (s[i] == ' ')
            {
                if (temp != "")
                {
                    res.push_back(temp);
                    temp = "";
                }
            }
            else
            {
                temp += s[i];
            }
        }
        return res;
    }
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
    bswabeCph cph;
    bswabeCphKey cphkey;
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

    void enc(string inputfile, string encfile, string policy)
    {
        vector<char> plt, cphBuf, aesBuf, pub_byte;
        element_t m;
        plt = this->cm.suckFile(inputfile);
        this->cph = bswabeCph();
        this->cphkey = bswabeCphKey();

        this->cphkey = this->bs.enc(this->pub, policy);
        this->cph = this->cphkey.cph;
        element_init_same_as(m, this->cphkey.key);

        cphBuf = this->ser.serializeBswabeCph(this->cph);

        // cphkey = this->bs.
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
// git clone git://git.openssl.org/openssl.git

/*
current working function stack
main
cpabe.enc

*/

/*
errors
includeing openssl

*/