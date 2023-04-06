#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <pbc/pbc.h>
#include <glib.h>
#include <assert.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#define MAX_LINE_LENGTH 1000
#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"
#define TYPE_A_PARAMS                                          \
    "type a\n"                                                 \
    "q 87807107996633125224377819847540498158068831994142082"  \
    "1102865339926647563088022295707862517942266222142315585"  \
    "8769582317459277713367317481324925129998224791\n"         \
    "h 12016012264891146079388821366740534204802954401251311"  \
    "822919615131047207289359704531102844802183906537786776\n" \
    "r 730750818665451621361119245571504901405976559617\n"     \
    "exp2 159\n"                                               \
    "exp1 107\n"                                               \
    "sign1 1\n"                                                \
    "sign0 1\n"

struct bswabe_pub_s
{
    char *pairing_desc;
    pairing_t p;
    element_t g;           /* G_1 */
    element_t h;           /* G_1 */
    element_t gp;          /* G_2 */
    element_t g_hat_alpha; /* G_T */
};

struct bswabe_msk_s
{
    element_t beta;    /* Z_r */
    element_t g_alpha; /* G_2 */
};

typedef struct
{
    /* these actually get serialized */
    char *attr;
    element_t d;  /* G_2 */
    element_t dp; /* G_2 */

    /* only used during dec (only by dec_merge) */
    int used;
    element_t z;  /* G_1 */
    element_t zp; /* G_1 */
} bswabe_prv_comp_t;

struct bswabe_prv_s
{
    element_t d;   /* G_2 */
    GArray *comps; /* bswabe_prv_comp_t's */
};

typedef struct
{
    int deg;
    /* coefficients from [0] x^0 to [deg] x^deg */
    element_t *coef; /* G_T (of length deg + 1) */
} bswabe_polynomial_t;

typedef struct
{
    /* serialized */
    int k;               /* one if leaf, otherwise threshold */
    char *attr;          /* attribute string if leaf, otherwise null */
    element_t c;         /* G_1, only for leaves */
    element_t cp;        /* G_1, only for leaves */
    GPtrArray *children; /* pointers to bswabe_policy_t's, len == 0 for leaves */

    /* only used during encryption */
    bswabe_polynomial_t *q;

    /* only used during decryption */
    int satisfiable;
    int min_leaves;
    int attri;
    GArray *satl;
} bswabe_policy_t;

struct bswabe_cph_s
{
    element_t cs; /* G_T */
    element_t c;  /* G_1 */
    bswabe_policy_t *p;
};

typedef struct bswabe_pub_s bswabe_pub_t;

/*
  A master secret key.
*/
typedef struct bswabe_msk_s bswabe_msk_t;

/*
  A private key.
*/
typedef struct bswabe_prv_s bswabe_prv_t;

/*
  A ciphertext. Note that this library only handles encrypting a
  single group element, so if you want to encrypt something bigger,
  you will have to use that group element as a symmetric key for
  hybrid encryption (which you do yourself).
*/
typedef struct bswabe_cph_s bswabe_cph_t;

void bswabe_setup(bswabe_pub_t **pub, bswabe_msk_t **msk)
{
    element_t alpha;

    /* initialize */

    *pub = malloc(sizeof(bswabe_pub_t));
    *msk = malloc(sizeof(bswabe_msk_t));

    (*pub)->pairing_desc = strdup(TYPE_A_PARAMS);
    pairing_init_set_buf((*pub)->p, (*pub)->pairing_desc, strlen((*pub)->pairing_desc));

    element_init_G1((*pub)->g, (*pub)->p);
    element_init_G1((*pub)->h, (*pub)->p);
    element_init_G2((*pub)->gp, (*pub)->p);
    element_init_GT((*pub)->g_hat_alpha, (*pub)->p);
    element_init_Zr(alpha, (*pub)->p);
    element_init_Zr((*msk)->beta, (*pub)->p);
    element_init_G2((*msk)->g_alpha, (*pub)->p);

    /* compute */

    element_random(alpha);
    element_random((*msk)->beta);
    element_random((*pub)->g);
    element_random((*pub)->gp);

    element_pow_zn((*msk)->g_alpha, (*pub)->gp, alpha);
    element_pow_zn((*pub)->h, (*pub)->g, (*msk)->beta);
    pairing_apply((*pub)->g_hat_alpha, (*pub)->g, (*msk)->g_alpha, (*pub)->p);

    // printf("setup done\n");
}

void element_from_string(element_t *h, char *s)
{
    unsigned char *r;
    // printf("%lu", strlen(s));
    r = (unsigned char *)malloc(SHA_DIGEST_LENGTH);
    SHA1((unsigned char *)s, strlen(s), r);
    // SHA1
    element_from_hash(*h, r, SHA_DIGEST_LENGTH);

    free(r);
}

bswabe_prv_t *bswabe_keygen(bswabe_pub_t *pub, bswabe_msk_t *msk, char **attributes, int size_tt)
{
    bswabe_prv_t *prv;
    element_t g_r;
    element_t r;
    element_t beta_inv;

    /* initialize */

    prv = malloc(sizeof(bswabe_prv_t));

    element_init_G2(prv->d, pub->p);
    element_init_G2(g_r, pub->p);
    element_init_Zr(r, pub->p);
    element_init_Zr(beta_inv, pub->p);

    prv->comps = g_array_new(0, 1, sizeof(bswabe_prv_comp_t));

    /* compute */

    element_random(r);
    element_pow_zn(g_r, pub->gp, r);

    element_mul(prv->d, msk->g_alpha, g_r);
    element_invert(beta_inv, msk->beta);
    element_pow_zn(prv->d, prv->d, beta_inv);

    int i;
    for (i = 0; i < size_tt; i++)
    {
        bswabe_prv_comp_t c;
        element_t h_rp;
        element_t rp;

        c.attr = (attributes[i]);
        // printf("%lu\t%s\n", strlen(c.attr), c.attr);
        element_init_G2(c.d, pub->p);
        element_init_G1(c.dp, pub->p);
        element_init_G2(h_rp, pub->p);
        element_init_Zr(rp, pub->p);

        element_from_string(&h_rp, c.attr);
        element_random(rp);

        element_pow_zn(h_rp, h_rp, rp);

        element_mul(c.d, g_r, h_rp);
        element_pow_zn(c.dp, pub->g, rp);

        element_clear(h_rp);
        element_clear(rp);

        g_array_append_val(prv->comps, c);
    }
    // printf("kegen done \n");
    return prv;
}

int key_gen_parse_attrs(char *s, char **attrs)
{
    int n = 0;
    int len = strlen((char *)s);

    attrs = (char **)malloc(sizeof(char *) * len);
    char *temp = (char *)malloc(sizeof(char) * len);

    int i = 0;
    int j = 0;
    for (i = 0; i < len; i++)
    {
        // printf("%c\n", s[i]);
        if (s[i] == ' ')
        {
            if (strcmp(temp, (char *)""))
            {
                attrs[n] = (char *)malloc(sizeof(char) * len);
                // strcpy(attrs[n], temp);
                // strcat(attrs[n], temp);
                // attrs[n] = temp;
                int k;
                for (k = 0; k <= j; k++)
                    attrs[n][k] = temp[k];
                n++;
                memset(temp, 0, j + 1);
                j = 0;
            }
        }
        else
        {
            // temp[strlen(temp)] = s[i];
            temp[j] = s[i];
            j++;
        }
    }
    if (strcmp(temp, (char *)""))
    {
        // strcpy(attrs[n], temp);
        // strcat(attrs[n], temp);
        attrs[n] = temp;
        n++;
        memset(temp, 0, j + 1);
        j = 0;
    }

    return n;
}

bswabe_policy_t *base_node(int k, char *s)
{
    bswabe_policy_t *p;

    p = (bswabe_policy_t *)malloc(sizeof(bswabe_policy_t));
    p->k = k;
    p->attr = s ? strdup(s) : 0;
    p->children = g_ptr_array_new();
    p->q = 0;

    return p;
}

bswabe_policy_t *parse_policy_postfix(char *s)
{
    char **toks;
    char **cur_toks;
    char *tok;
    GPtrArray *stack; /* pointers to bswabe_policy_t's */
    bswabe_policy_t *root;

    toks = g_strsplit(s, " ", 0);
    cur_toks = toks;
    stack = g_ptr_array_new();

    while (*cur_toks)
    {
        int i, k, n;

        tok = *(cur_toks++);

        if (!*tok)
            continue;

        if (sscanf(tok, "%dof%d", &k, &n) != 2)
            /* push leaf token */
            g_ptr_array_add(stack, base_node(1, tok));
        else
        {
            bswabe_policy_t *node;

            /* parse "kofn" operator */

            if (k < 1)
            {
                printf("error parsing \"%s\": trivially satisfied operator \"%s\"\n", s, tok);
                return 0;
            }
            else if (k > n)
            {
                printf("error parsing \"%s\": unsatisfiable operator \"%s\"\n", s, tok);
                return 0;
            }
            else if (n == 1)
            {
                printf("error parsing \"%s\": identity operator \"%s\"\n", s, tok);
                return 0;
            }
            else if (n > stack->len)
            {
                printf("error parsing \"%s\": stack underflow at \"%s\"\n", s, tok);
                return 0;
            }

            /* pop n things and fill in children */
            node = base_node(k, 0);
            g_ptr_array_set_size(node->children, n);
            for (i = n - 1; i >= 0; i--)
                node->children->pdata[i] = g_ptr_array_remove_index(stack, stack->len - 1);

            /* push result */
            g_ptr_array_add(stack, node);
        }
    }

    if (stack->len > 1)
    {
        printf("error parsing \"%s\": extra tokens left on stack\n", s);
        return 0;
    }
    else if (stack->len < 1)
    {
        printf("error parsing \"%s\": empty policy\n", s);
        return 0;
    }

    root = g_ptr_array_index(stack, 0);

    g_strfreev(toks);
    g_ptr_array_free(stack, 0);

    return root;
}

bswabe_polynomial_t *rand_poly(int deg, element_t zero_val)
{
    int i;
    bswabe_polynomial_t *q;

    q = (bswabe_polynomial_t *)malloc(sizeof(bswabe_polynomial_t));
    q->deg = deg;
    q->coef = (element_t *)malloc(sizeof(element_t) * (deg + 1));

    for (i = 0; i < q->deg + 1; i++)
        element_init_same_as(q->coef[i], zero_val);

    element_set(q->coef[0], zero_val);

    for (i = 1; i < q->deg + 1; i++)
        element_random(q->coef[i]);

    return q;
}

void eval_poly(element_t r, bswabe_polynomial_t *q, element_t x)
{
    int i;
    element_t s, t;

    element_init_same_as(s, r);
    element_init_same_as(t, r);

    element_set0(r);
    element_set1(t);

    for (i = 0; i < q->deg + 1; i++)
    {
        /* r += q->coef[i] * t */
        element_mul(s, q->coef[i], t);
        element_add(r, r, s);

        /* t *= x */
        element_mul(t, t, x);
    }

    element_clear(s);
    element_clear(t);
}

void fill_policy(bswabe_policy_t *p, bswabe_pub_t *pub, element_t e)
{
    int i;
    element_t r;
    element_t t;
    element_t h;

    element_init_Zr(r, pub->p);
    element_init_Zr(t, pub->p);
    element_init_G2(h, pub->p);

    p->q = rand_poly(p->k - 1, e);

    if (p->children->len == 0)
    {
        element_init_G1(p->c, pub->p);
        element_init_G2(p->cp, pub->p);

        element_from_string(&h, p->attr);
        element_pow_zn(p->c, pub->g, p->q->coef[0]);
        element_pow_zn(p->cp, h, p->q->coef[0]);
    }
    else
        for (i = 0; i < p->children->len; i++)
        {
            element_set_si(r, i + 1);
            eval_poly(t, p->q, r);
            fill_policy(g_ptr_array_index(p->children, i), pub, t);
        }

    element_clear(r);
    element_clear(t);
    element_clear(h);
}

bswabe_cph_t *bswabe_enc(bswabe_pub_t *pub, element_t *m, char *policy)
{
    bswabe_cph_t *cph;
    element_t s;

    /* initialize */

    cph = malloc(sizeof(bswabe_cph_t));

    element_init_Zr(s, pub->p);
    element_init_GT(*m, pub->p);
    element_init_GT(cph->cs, pub->p);
    element_init_G1(cph->c, pub->p);
    cph->p = parse_policy_postfix(policy);

    /* compute */

    element_random(*m);
    element_random(s);
    element_pow_zn(cph->cs, pub->g_hat_alpha, s);
    element_mul(cph->cs, cph->cs, *m);

    element_pow_zn(cph->c, pub->h, s);

    fill_policy(cph->p, pub, s);

    return cph;
}

FILE *fopen_read_or_die(char *file)
{
    FILE *f;

    if (!(f = fopen(file, "r")))
        printf("can't read file: %s\n", file);

    return f;
}

FILE *
fopen_write_or_die(char *file)
{
    FILE *f;

    if (!(f = fopen(file, "w")))
        printf("can't write file: %s\n", file);

    return f;
}

GByteArray *suck_file(char *file)
{
    FILE *f;
    GByteArray *a;
    struct stat s;

    a = g_byte_array_new();
    stat(file, &s);
    g_byte_array_set_size(a, s.st_size);

    f = fopen_read_or_die(file);
    fread(a->data, 1, s.st_size, f);
    fclose(f);

    return a;
}

void spit_file(char *file, GByteArray *b, int free)
{
    FILE *f;

    f = fopen_write_or_die(file);
    fwrite(b->data, 1, b->len, f);
    fclose(f);

    if (free)
        g_byte_array_free(b, 1);
}

void read_cpabe_file(char *file, GByteArray **cph_buf,
                     int *file_len, GByteArray **aes_buf)
{
    FILE *f;
    int i;
    int len;

    *cph_buf = g_byte_array_new();
    *aes_buf = g_byte_array_new();

    f = fopen_read_or_die(file);

    /* read real file len as 32-bit big endian int */
    *file_len = 0;
    for (i = 3; i >= 0; i--)
        *file_len |= fgetc(f) << (i * 8);

    /* read aes buf */
    len = 0;
    for (i = 3; i >= 0; i--)
        len |= fgetc(f) << (i * 8);
    g_byte_array_set_size(*aes_buf, len);
    fread((*aes_buf)->data, 1, len, f);

    /* read cph buf */
    len = 0;
    for (i = 3; i >= 0; i--)
        len |= fgetc(f) << (i * 8);
    g_byte_array_set_size(*cph_buf, len);
    fread((*cph_buf)->data, 1, len, f);

    fclose(f);
}

void write_cpabe_file(char *file, GByteArray *cph_buf,
                      int file_len, GByteArray *aes_buf)
{
    FILE *f;
    int i;

    f = fopen_write_or_die(file);

    /* write real file len as 32-bit big endian int */
    for (i = 3; i >= 0; i--)
        fputc((file_len & 0xff << (i * 8)) >> (i * 8), f);

    /* write aes_buf */
    for (i = 3; i >= 0; i--)
        fputc((aes_buf->len & 0xff << (i * 8)) >> (i * 8), f);
    fwrite(aes_buf->data, 1, aes_buf->len, f);

    /* write cph_buf */
    for (i = 3; i >= 0; i--)
        fputc((cph_buf->len & 0xff << (i * 8)) >> (i * 8), f);
    fwrite(cph_buf->data, 1, cph_buf->len, f);

    fclose(f);
}

void init_aes(element_t k, int enc, AES_KEY *key, unsigned char *iv)
{
    int key_len;
    unsigned char *key_buf;

    key_len = element_length_in_bytes(k) < 17 ? 17 : element_length_in_bytes(k);
    key_buf = (unsigned char *)malloc(key_len);
    element_to_bytes(key_buf, k);

    if (enc)
        AES_set_encrypt_key(key_buf + 1, 128, key);
    else
        AES_set_decrypt_key(key_buf + 1, 128, key);
    free(key_buf);

    memset(iv, 0, 16);
}

GByteArray *aes_128_cbc_encrypt(GByteArray *pt, element_t k)
{
    AES_KEY key;
    unsigned char iv[16];
    GByteArray *ct;
    guint8 len[4];
    guint8 zero;

    init_aes(k, 1, &key, iv);

    /* TODO make less crufty */

    /* stuff in real length (big endian) before padding */
    len[0] = (pt->len & 0xff000000) >> 24;
    len[1] = (pt->len & 0xff0000) >> 16;
    len[2] = (pt->len & 0xff00) >> 8;
    len[3] = (pt->len & 0xff) >> 0;
    g_byte_array_prepend(pt, len, 4);

    /* pad out to multiple of 128 bit (16 byte) blocks */
    zero = 0;
    while (pt->len % 16)
        g_byte_array_append(pt, &zero, 1);

    ct = g_byte_array_new();
    g_byte_array_set_size(ct, pt->len);

    AES_cbc_encrypt(pt->data, ct->data, pt->len, &key, iv, AES_ENCRYPT);

    return ct;
}

GByteArray *
aes_128_cbc_decrypt(GByteArray *ct, element_t k)
{
    AES_KEY key;
    unsigned char iv[16];
    GByteArray *pt;
    unsigned int len;

    init_aes(k, 0, &key, iv);

    pt = g_byte_array_new();
    g_byte_array_set_size(pt, ct->len);

    AES_cbc_encrypt(ct->data, pt->data, ct->len, &key, iv, AES_DECRYPT);

    /* TODO make less crufty */

    /* get real length */
    len = 0;
    len = len | ((pt->data[0]) << 24) | ((pt->data[1]) << 16) | ((pt->data[2]) << 8) | ((pt->data[3]) << 0);
    g_byte_array_remove_index(pt, 0);
    g_byte_array_remove_index(pt, 0);
    g_byte_array_remove_index(pt, 0);
    g_byte_array_remove_index(pt, 0);

    /* truncate any garbage from the padding */
    g_byte_array_set_size(pt, len);

    return pt;
}

void check_sat(bswabe_policy_t *p, bswabe_prv_t *prv)
{
    int i, l;

    p->satisfiable = 0;
    if (p->children->len == 0)
    {
        for (i = 0; i < prv->comps->len; i++)
            if (!strcmp(g_array_index(prv->comps, bswabe_prv_comp_t, i).attr,
                        p->attr))
            {
                p->satisfiable = 1;
                p->attri = i;
                break;
            }
    }
    else
    {
        for (i = 0; i < p->children->len; i++)
            check_sat(g_ptr_array_index(p->children, i), prv);

        l = 0;
        for (i = 0; i < p->children->len; i++)
            if (((bswabe_policy_t *)g_ptr_array_index(p->children, i))->satisfiable)
                l++;

        if (l >= p->k)
            p->satisfiable = 1;
    }
}
bswabe_policy_t *cur_comp_pol;

int cmp_int(const void *a, const void *b)
{
    int k, l;

    k = ((bswabe_policy_t *)g_ptr_array_index(cur_comp_pol->children, *((int *)a)))->min_leaves;
    l = ((bswabe_policy_t *)g_ptr_array_index(cur_comp_pol->children, *((int *)b)))->min_leaves;

    return k < l ? -1 : k == l ? 0
                               : 1;
}

void dec_leaf_flatten(element_t r, element_t exp,
                      bswabe_policy_t *p, bswabe_prv_t *prv, bswabe_pub_t *pub)
{
    bswabe_prv_comp_t *c;
    element_t s;
    element_t t;

    c = &(g_array_index(prv->comps, bswabe_prv_comp_t, p->attri));

    element_init_GT(s, pub->p);
    element_init_GT(t, pub->p);

    pairing_apply(s, p->c, c->d, pub->p);   /* num_pairings++; */
    pairing_apply(t, p->cp, c->dp, pub->p); /* num_pairings++; */
    element_invert(t, t);
    element_mul(s, s, t);      /* num_muls++; */
    element_pow_zn(s, s, exp); /* num_exps++; */

    element_mul(r, r, s); /* num_muls++; */

    element_clear(s);
    element_clear(t);
}

void pick_sat_min_leaves(bswabe_policy_t *p, bswabe_prv_t *prv)
{
    int i, k, l;
    int *c;

    assert(p->satisfiable == 1);

    if (p->children->len == 0)
        p->min_leaves = 1;
    else
    {
        for (i = 0; i < p->children->len; i++)
            if (((bswabe_policy_t *)g_ptr_array_index(p->children, i))->satisfiable)
                pick_sat_min_leaves(g_ptr_array_index(p->children, i), prv);

        c = alloca(sizeof(int) * p->children->len);
        for (i = 0; i < p->children->len; i++)
            c[i] = i;

        cur_comp_pol = p;
        qsort(c, p->children->len, sizeof(int), cmp_int);

        p->satl = g_array_new(0, 0, sizeof(int));
        p->min_leaves = 0;
        l = 0;

        for (i = 0; i < p->children->len && l < p->k; i++)
            if (((bswabe_policy_t *)g_ptr_array_index(p->children, c[i]))->satisfiable)
            {
                l++;
                p->min_leaves += ((bswabe_policy_t *)g_ptr_array_index(p->children, c[i]))->min_leaves;
                k = c[i] + 1;
                g_array_append_val(p->satl, k);
            }
        assert(l == p->k);
    }
}

void lagrange_coef(element_t r, GArray *s, int i)
{
    int j, k;
    element_t t;

    element_init_same_as(t, r);

    element_set1(r);
    for (k = 0; k < s->len; k++)
    {
        j = g_array_index(s, int, k);
        if (j == i)
            continue;
        element_set_si(t, -j);
        element_mul(r, r, t); /* num_muls++; */
        element_set_si(t, i - j);
        element_invert(t, t);
        element_mul(r, r, t); /* num_muls++; */
    }

    element_clear(t);
}
void dec_node_flatten(element_t r, element_t exp,
                      bswabe_policy_t *p, bswabe_prv_t *prv, bswabe_pub_t *pub);

void dec_internal_flatten(element_t r, element_t exp,
                          bswabe_policy_t *p, bswabe_prv_t *prv, bswabe_pub_t *pub)
{
    int i;
    element_t t;
    element_t expnew;

    element_init_Zr(t, pub->p);
    element_init_Zr(expnew, pub->p);

    for (i = 0; i < p->satl->len; i++)
    {
        lagrange_coef(t, p->satl, g_array_index(p->satl, int, i));
        element_mul(expnew, exp, t); /* num_muls++; */
        dec_node_flatten(r, expnew, g_ptr_array_index(p->children, g_array_index(p->satl, int, i) - 1), prv, pub);
    }

    element_clear(t);
    element_clear(expnew);
}

void dec_node_flatten(element_t r, element_t exp,
                      bswabe_policy_t *p, bswabe_prv_t *prv, bswabe_pub_t *pub)
{
    assert(p->satisfiable);
    if (p->children->len == 0)
        dec_leaf_flatten(r, exp, p, prv, pub);
    else
        dec_internal_flatten(r, exp, p, prv, pub);
}

void dec_flatten(element_t r, bswabe_policy_t *p, bswabe_prv_t *prv, bswabe_pub_t *pub)
{
    element_t one;

    element_init_Zr(one, pub->p);

    element_set1(one);
    element_set1(r);

    dec_node_flatten(r, one, p, prv, pub);

    element_clear(one);
}

int bswabe_dec(bswabe_pub_t *pub, bswabe_prv_t *prv, bswabe_cph_t *cph, element_t *m)
{
    element_t t;

    element_init_GT(*m, pub->p);
    element_init_GT(t, pub->p);

    check_sat(cph->p, prv);
    if (!cph->p->satisfiable)
    {
        // printf("")
        printf("%scannot decrypt, attributes in key do not satisfy policy\n%s", KRED, KNRM);
        return 0;
    }

    /* 	if( no_opt_sat ) */
    /* 		pick_sat_naive(cph->p, prv); */
    /* 	else */
    pick_sat_min_leaves(cph->p, prv);

    /* 	if( dec_strategy == DEC_NAIVE ) */
    /* 		dec_naive(t, cph->p, prv, pub); */
    /* 	else if( dec_strategy == DEC_FLATTEN ) */
    dec_flatten(t, cph->p, prv, pub);
    /* 	else */
    /* 		dec_merge(t, cph->p, prv, pub); */

    element_mul(*m, cph->cs, t); /* num_muls++; */

    pairing_apply(t, cph->c, prv->d, pub->p); /* num_pairings++; */
    element_invert(t, t);
    element_mul(*m, *m, t); /* num_muls++; */

    return 1;
}

void serialize_uint32(GByteArray *b, uint32_t k)
{
    int i;
    guint8 byte;

    for (i = 3; i >= 0; i--)
    {
        byte = (k & 0xff << (i * 8)) >> (i * 8);
        g_byte_array_append(b, &byte, 1);
    }
}

uint32_t
unserialize_uint32(GByteArray *b, int *offset)
{
    int i;
    uint32_t r;

    r = 0;
    for (i = 3; i >= 0; i--)
        r |= (b->data[(*offset)++]) << (i * 8);

    return r;
}

void serialize_element(GByteArray *b, element_t e)
{
    uint32_t len;
    unsigned char *buf;

    len = element_length_in_bytes(e);
    serialize_uint32(b, len);

    buf = (unsigned char *)malloc(len);
    element_to_bytes(buf, e);
    g_byte_array_append(b, buf, len);
    free(buf);
}

void unserialize_element(GByteArray *b, int *offset, element_t e)
{
    uint32_t len;
    unsigned char *buf;

    len = unserialize_uint32(b, offset);

    buf = (unsigned char *)malloc(len);
    memcpy(buf, b->data + *offset, len);
    *offset += len;

    element_from_bytes(e, buf);
    free(buf);
}

void serialize_string(GByteArray *b, char *s)
{
    g_byte_array_append(b, (unsigned char *)s, strlen(s) + 1);
}

char *
unserialize_string(GByteArray *b, int *offset)
{
    GString *s;
    char *r;
    char c;

    s = g_string_sized_new(32);
    while (1)
    {
        c = b->data[(*offset)++];
        if (c && c != EOF)
            g_string_append_c(s, c);
        else
            break;
    }

    r = s->str;
    g_string_free(s, 0);

    return r;
}

GByteArray *
bswabe_pub_serialize(bswabe_pub_t *pub)
{
    GByteArray *b;

    b = g_byte_array_new();
    serialize_string(b, pub->pairing_desc);
    serialize_element(b, pub->g);
    serialize_element(b, pub->h);
    serialize_element(b, pub->gp);
    serialize_element(b, pub->g_hat_alpha);

    return b;
}

bswabe_pub_t *
bswabe_pub_unserialize(GByteArray *b, int free)
{
    bswabe_pub_t *pub;
    int offset;

    pub = (bswabe_pub_t *)malloc(sizeof(bswabe_pub_t));
    offset = 0;

    pub->pairing_desc = unserialize_string(b, &offset);
    pairing_init_set_buf(pub->p, pub->pairing_desc, strlen(pub->pairing_desc));

    element_init_G1(pub->g, pub->p);
    element_init_G1(pub->h, pub->p);
    element_init_G2(pub->gp, pub->p);
    element_init_GT(pub->g_hat_alpha, pub->p);

    unserialize_element(b, &offset, pub->g);
    unserialize_element(b, &offset, pub->h);
    unserialize_element(b, &offset, pub->gp);
    unserialize_element(b, &offset, pub->g_hat_alpha);

    if (free)
        g_byte_array_free(b, 1);

    return pub;
}

GByteArray *
bswabe_msk_serialize(bswabe_msk_t *msk)
{
    GByteArray *b;

    b = g_byte_array_new();
    serialize_element(b, msk->beta);
    serialize_element(b, msk->g_alpha);

    return b;
}

bswabe_msk_t *
bswabe_msk_unserialize(bswabe_pub_t *pub, GByteArray *b, int free)
{
    bswabe_msk_t *msk;
    int offset;

    msk = (bswabe_msk_t *)malloc(sizeof(bswabe_msk_t));
    offset = 0;

    element_init_Zr(msk->beta, pub->p);
    element_init_G2(msk->g_alpha, pub->p);

    unserialize_element(b, &offset, msk->beta);
    unserialize_element(b, &offset, msk->g_alpha);

    if (free)
        g_byte_array_free(b, 1);

    return msk;
}

GByteArray *
bswabe_prv_serialize(bswabe_prv_t *prv)
{
    GByteArray *b;
    int i;

    b = g_byte_array_new();

    serialize_element(b, prv->d);
    serialize_uint32(b, prv->comps->len);

    for (i = 0; i < prv->comps->len; i++)
    {
        serialize_string(b, g_array_index(prv->comps, bswabe_prv_comp_t, i).attr);
        serialize_element(b, g_array_index(prv->comps, bswabe_prv_comp_t, i).d);
        serialize_element(b, g_array_index(prv->comps, bswabe_prv_comp_t, i).dp);
    }

    return b;
}

bswabe_prv_t *
bswabe_prv_unserialize(bswabe_pub_t *pub, GByteArray *b, int free)
{
    bswabe_prv_t *prv;
    int i;
    int len;
    int offset;

    prv = (bswabe_prv_t *)malloc(sizeof(bswabe_prv_t));
    offset = 0;

    element_init_G2(prv->d, pub->p);
    unserialize_element(b, &offset, prv->d);

    prv->comps = g_array_new(0, 1, sizeof(bswabe_prv_comp_t));
    len = unserialize_uint32(b, &offset);

    for (i = 0; i < len; i++)
    {
        bswabe_prv_comp_t c;

        c.attr = unserialize_string(b, &offset);

        element_init_G2(c.d, pub->p);
        element_init_G2(c.dp, pub->p);

        unserialize_element(b, &offset, c.d);
        unserialize_element(b, &offset, c.dp);

        g_array_append_val(prv->comps, c);
    }

    if (free)
        g_byte_array_free(b, 1);

    return prv;
}

void serialize_policy(GByteArray *b, bswabe_policy_t *p)
{
    int i;

    serialize_uint32(b, (uint32_t)p->k);

    serialize_uint32(b, (uint32_t)p->children->len);
    if (p->children->len == 0)
    {
        serialize_string(b, p->attr);
        serialize_element(b, p->c);
        serialize_element(b, p->cp);
    }
    else
        for (i = 0; i < p->children->len; i++)
            serialize_policy(b, g_ptr_array_index(p->children, i));
}

bswabe_policy_t *
unserialize_policy(bswabe_pub_t *pub, GByteArray *b, int *offset)
{
    int i;
    int n;
    bswabe_policy_t *p;

    p = (bswabe_policy_t *)malloc(sizeof(bswabe_policy_t));

    p->k = (int)unserialize_uint32(b, offset);
    p->attr = 0;
    p->children = g_ptr_array_new();

    n = unserialize_uint32(b, offset);
    if (n == 0)
    {
        p->attr = unserialize_string(b, offset);
        element_init_G1(p->c, pub->p);
        element_init_G1(p->cp, pub->p);
        unserialize_element(b, offset, p->c);
        unserialize_element(b, offset, p->cp);
    }
    else
        for (i = 0; i < n; i++)
            g_ptr_array_add(p->children, unserialize_policy(pub, b, offset));

    return p;
}

GByteArray *
bswabe_cph_serialize(bswabe_cph_t *cph)
{
    GByteArray *b;

    b = g_byte_array_new();
    serialize_element(b, cph->cs);
    serialize_element(b, cph->c);
    serialize_policy(b, cph->p);

    return b;
}

bswabe_cph_t *
bswabe_cph_unserialize(bswabe_pub_t *pub, GByteArray *b, int free)
{
    bswabe_cph_t *cph;
    int offset;

    cph = (bswabe_cph_t *)malloc(sizeof(bswabe_cph_t));
    offset = 0;

    element_init_GT(cph->cs, pub->p);
    element_init_G1(cph->c, pub->p);
    unserialize_element(b, &offset, cph->cs);
    unserialize_element(b, &offset, cph->c);
    cph->p = unserialize_policy(pub, b, &offset);

    if (free)
        g_byte_array_free(b, 1);

    return cph;
}

void bswabe_pub_free(bswabe_pub_t *pub)
{
    element_clear(pub->g);
    element_clear(pub->h);
    element_clear(pub->gp);
    element_clear(pub->g_hat_alpha);
    pairing_clear(pub->p);
    free(pub->pairing_desc);
    free(pub);
}

void bswabe_msk_free(bswabe_msk_t *msk)
{
    element_clear(msk->beta);
    element_clear(msk->g_alpha);
    free(msk);
}

void bswabe_prv_free(bswabe_prv_t *prv)
{
    int i;

    element_clear(prv->d);

    for (i = 0; i < prv->comps->len; i++)
    {
        bswabe_prv_comp_t c;

        c = g_array_index(prv->comps, bswabe_prv_comp_t, i);
        free(c.attr);
        element_clear(c.d);
        element_clear(c.dp);
    }

    g_array_free(prv->comps, 1);

    free(prv);
}

void bswabe_policy_free(bswabe_policy_t *p)
{
    int i;

    if (p->attr)
    {
        free(p->attr);
        element_clear(p->c);
        element_clear(p->cp);
    }

    for (i = 0; i < p->children->len; i++)
        bswabe_policy_free(g_ptr_array_index(p->children, i));

    g_ptr_array_free(p->children, 1);

    free(p);
}

void bswabe_cph_free(bswabe_cph_t *cph)
{
    element_clear(cph->cs);
    element_clear(cph->c);
    bswabe_policy_free(cph->p);
}

char **get_user_attrs(int *len)
{
    FILE    *textfile;
    char    line[MAX_LINE_LENGTH];
    char ** attrs = (char ** )malloc(sizeof(char *)*20);
    textfile = fopen("/Users/kamalswami/Documents/ABE/.ABE_DIR/attribute.txt", "r");
    if(textfile == NULL){
        printf("cannot read attributes |||");
        exit(1);
    }
    int k=0;
    while(fgets(line, MAX_LINE_LENGTH, textfile)){
        attrs[k]=(char *)malloc(sizeof(char)*(strlen(line)));
        // strcat(attrs[k], line);
        int i, l= strlen(line);
        int j=0;
        
        for(i=0; i<l; i++){
            if(line[i]==10 || line[i]==13){

            }else{
                attrs[k][j]=line[i];
                j++;
            }
        }
        // printf("%s\n", line);
        k++;
    }
    fclose(textfile);
    *len =k;
    return attrs;
}

char *itoa(int num, char *buffer, int base)
{
    int current = 0;
    if (num == 0)
    {
        buffer[current++] = '0';
        buffer[current] = '\0';
        return buffer;
    }
    int num_digits = 0;
    if (num < 0)
    {
        if (base == 10)
        {
            num_digits++;
            buffer[current] = '-';
            current++;
            num *= -1;
        }
        else
            return NULL;
    }
    num_digits += (int)floor(log(num) / log(base)) + 1;
    while (current < num_digits)
    {
        int base_val = (int)pow(base, num_digits - 1 - current);
        int num_val = num / base_val;
        char value = num_val + '0';
        buffer[current] = value;
        current++;
        num -= base_val * num_val;
    }
    buffer[current] = '\0';
    return buffer;
}

char *get_encryption_rule()
{
    FILE    *textfile;
    char    line[MAX_LINE_LENGTH];
    char ** attrs = (char ** )malloc(sizeof(char *)*20);
    textfile = fopen("/Users/kamalswami/Documents/ABE/.ABE_DIR/rules.txt", "r");
    if(textfile == NULL){
        printf("cannot read rules |||");
        exit(1);
    }
    char * rule = (char *)malloc(sizeof(char)*MAX_LINE_LENGTH);
    int k=0;
    while(fgets(line, MAX_LINE_LENGTH, textfile)){
        char * imp = (char *)malloc(sizeof(char)*strlen(line));
        int j=0;
        int l = strlen(line);
        int i;
        for(i=0; i<l; i++){
            if(line[i]==10 || line[i]==13){

            }else{
                imp[j]=line[i];
                j++;
            }
        }
        if(k==0){
            strcat(rule, imp);
        }else{
            strcat(rule, " ");
            strcat(rule, imp);
        }

        k++;
    }
    strcat(rule, " 1of");
    rule[strlen(rule)]='0'+k;
    // printf("new : %s\n",rule);
    fclose(textfile);
    return rule;


    // char *policy;
    // int n;
    // GByteArray *b = suck_file((char *)"/Users/kamalswami/Documents/ABE/.ABE_DIR/rules.txt");
    // policy = unserialize_string(b, &n);
    // int i;
    // int j=0;
    // int k=0;
    // for(i=0; i<n; i++){
    //     // printf("%d\t%c\n", policy[i], policy[i]);
    //     if(policy[i]==13){
    //         policy[j]=' ';
    //         j++;
    //         }
    //     else if(policy[i]==10){
    //         // printf("here");
    //         // printf("%d\t%c\n", policy[i], policy[i]);
    //         // j--;
    //         k++;
    //     }
    //     else if(policy[i]==0){
    //         // k++;
    //     }
    //     else{
    //         policy[j]=policy[i];
    //         j++;
    //     }
    // }
    // policy[j]=' ';
    // policy[++j]='1';
    // policy[++j]='o';
    // policy[++j]='f';
    // policy[++j]='0'+k+1;
    // // printf("%s", policy);
    // return policy;
}


char ** get_object_attrs(int *len, char *file){
    char ** attrs=(char **)malloc(sizeof(char *)*2);
    char *ext = strrchr(file, '.');
    if (ext == NULL) {
        printf("File has no extension\n");
    } else {
        // printf("File extension: %s\n", ext+1);
    }
    attrs[0]=(char *)malloc(sizeof(char)*20);
    strcat(attrs[0], "obj-type:");
    strcat(attrs[0], ext+1);

    struct stat sb;
    if (stat(file, &sb) == -1) {
        printf("error stat");
        return attrs;
    }
    // printf("File size: %lld bytes\n", sb.st_size);
    attrs[1]=(char *)malloc(sizeof(char)*20);
    strcat(attrs[1], "obj-size:");
    char str[100];
    strcat(attrs[1], itoa(sb.st_size, str, 10));
    strcat(attrs[1], "b");
    *len =2;
    return attrs;
}

int sim_bswabe_policy(bswabe_policy_t * p, char **obj_attrs, int len){
    int rem =0;
    int i;
    int count = p->children->len;
    // printf("%s%s%s", KGRN, p->attr, KNRM);
    if(count==0){
        
        for(i=0; i<len; i++){
            if(strcmp(p->attr, obj_attrs[i])==0){
                p->k--;
                rem++;
            }
        }
    }else{
        for(i=0; i<count; i++){
            rem = sim_bswabe_policy(g_ptr_array_index(p->children, i), obj_attrs, len);
            p->k-=rem;
            rem=0;
        }
    }

    return rem;
}

char * policy_to_string(bswabe_policy_t* p){
    char * st = (char *)malloc(sizeof(char)*MAX_LINE_LENGTH);
    int count = p->children->len;
    if(count==0){
        strcat(st, p->attr);
    }else{
        int i;
        for(i=0; i<count; i++){
            if(strlen(st)==0){
                strcat(st, policy_to_string(g_ptr_array_index(p->children, i)));
            }else{
                strcat(st, " ");
                strcat(st, policy_to_string(g_ptr_array_index(p->children, i)));
            }
        }
        strcat(st, " ");
        char str[100];
        strcat(st, itoa(p->k, str, 10));
        strcat(st, "of");
        strcat(st, itoa(count, str, 10));
    }

    return st;
}

char * simplify_policy(char *policy, char ** obj_attrs, int len){

    int i;
    printf("File : [");
    for(i=0; i<len; i++){
        if(i!=0)printf("   ");
        printf("%s", obj_attrs[i]);
    }
    printf("]\n");

    bswabe_policy_t *p = parse_policy_postfix(policy);
    int x =sim_bswabe_policy(p,  obj_attrs, len);
    policy = policy_to_string(p);
    return policy;
}





// int main()
// {
//     char *pub_file = (char *)"pub_key";
//     char *msk_file = (char *)"master_key";
//     char *in_file = (char *)"test_case_01.txt";
//     char *out_file = (char *)"test_case_01.txt.cpabe";
//     char *dec_file = (char *)"dec_test_case_01.txt";
//     bswabe_pub_t *pub;
//     bswabe_msk_t *msk;
//     bswabe_prv_t *prv;
//     bswabe_setup(&pub, &msk);
//     char **attrs = (char **)malloc(sizeof(char *) * 2);
//     attrs[0] = (char *)malloc(sizeof(char) * 50);
//     attrs[1] = (char *)malloc(sizeof(char) * 50);
//     attrs[0] = (char *)"name:kamal";
//     attrs[1] = (char *)"age:20";
//     char *policy = (char *)malloc(sizeof(char) * 100);
//     policy = (char *)"name:kamal age:20 2of2";
//     // policy = parse_policy_lang(policy);
//     printf("policy : %s\n", policy);
//     // int n = key_gen_parse_attrs((char *)"name:kamal age:20", attrs);
//     // printf("%d\n", n);
//     // printf("%s", attrs[0]);
//     prv = bswabe_keygen(pub, msk, attrs, 2);
//     bswabe_cph_t *cph;
//     element_t m;
//     cph = bswabe_enc(pub, &m, policy);
//     GByteArray *aes_buf;
//     GByteArray *plt;
//     int file_len;
//     plt = suck_file(in_file);
//     file_len = plt->len;
//     aes_buf = aes_128_cbc_encrypt(plt, m);
//     element_t m1;
//     if (!bswabe_dec(pub, prv, cph, &m1))
//     {
//         printf("error");
//         return 0;
//     }
//     GByteArray *plt1 = aes_128_cbc_decrypt(aes_buf, m1);
//     spit_file(dec_file, plt1, 1);

//     printf("done...");
//     return 0;
// }

char *pub_file = (char *)".ABE_DIR/pub_key";
char *msk_file = (char *)".ABE_DIR/master_key";
char *prv_file = (char *)".ABE_DIR/prv_key";
// char *in_file ;
// char *out_file;
// char *dec_file ;
bswabe_pub_t *pub;
bswabe_msk_t *msk;
bswabe_prv_t *prv;
bswabe_cph_t *cph;
element_t m;
GByteArray *aes_buf;
GByteArray *cph_buf;
GByteArray *plt;
int file_len;
element_t m1;

void setup()
{
    printf("\n\n++++++++++++++++++++ setup start ++++++++++++++++++++\n");
    bswabe_setup(&pub, &msk);
    // time_t t;
    // time(&t);
    // printf("\nSetup completed at : %s", ctime(&t));
    spit_file(pub_file, bswabe_pub_serialize(pub), 1);
    spit_file(msk_file, bswabe_msk_serialize(msk), 1);
    printf("Public key is in : [%s]\n", pub_file);
    printf("Master key is in : [%s]\n", msk_file);
    printf("++++++++++++++++++++ setup done ++++++++++++++++++++\n\n");
}

void keygen()
{
    printf("\n\n++++++++++++++++++++ keygen start ++++++++++++++++++++\n");
    char **attrs = (char **)malloc(sizeof(char *) * 2);
    attrs[0] = (char *)malloc(sizeof(char) * 50);
    attrs[1] = (char *)malloc(sizeof(char) * 50);
    attrs[0] = (char *)"name:kamal";
    attrs[1] = (char *)"age:20";
    int n;
    attrs = get_user_attrs(&n);
    int i;
    printf("user(%d) : [", n);
    for(i=0; i<n; i++){
        if(i!=0)printf("   ");
        printf("%s", attrs[i]);
        
    }
    printf("]\n");
    pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
    msk = bswabe_msk_unserialize(pub, suck_file(msk_file), 1);
    prv = bswabe_keygen(pub, msk, attrs, n);
    spit_file(prv_file, bswabe_prv_serialize(prv), 1);
    printf("Private key is in : [%s]\n", prv_file);
    printf("++++++++++++++++++++ keygen done ++++++++++++++++++++\n\n");
}

void enc(const char *in_file, const char *out_file)
{
    printf("\n\n++++++++++++++++++++ encryption start ++++++++++++++++++++\n");
    // in_file = (char *)malloc(sizeof(char)*100);
    // out_file = (char *)malloc(sizeof(char)*100);
    // in_file = (char *)".ABE_DIR/files/";
    // strcat(in_file,filename);
    // printf("in_file : %s\n", in_file);
    // out_file = (char *)".ABE_DIR/encryption/";
    // strcat(out_file, filename);
    // strcat(out_file, (char *)".cpabe");
    pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
    char *policy ;//= (char *)malloc(sizeof(char) * 100);
    // policy = (char *)"name:kamal age:20 2of2";
    policy = get_encryption_rule();
    printf("Policy : [%s]\n", policy);


    int obj_attrs_len;
    char ** obj_attrs = get_object_attrs(&obj_attrs_len, in_file);
    policy = simplify_policy(policy, obj_attrs, obj_attrs_len);
    printf("Updated policy : [%s]\n", policy);




    printf("In-file : [%s]\n", in_file);
    printf("Cpabe-file : [%s]\n", out_file);
    cph = bswabe_enc(pub, &m, policy);
    cph_buf = bswabe_cph_serialize(cph);
    plt = suck_file(in_file);
    file_len = plt->len;
    aes_buf = aes_128_cbc_encrypt(plt, m);
    write_cpabe_file(out_file, cph_buf, file_len, aes_buf);
    printf("++++++++++++++++++++ encryption done ++++++++++++++++++++\n\n");
}

void dec(const char *out_file, const char *dec_file)
{
    printf("\n\n++++++++++++++++++++ decryption start ++++++++++++++++++++\n");
    printf("Capbe file : [%s]\n", out_file);
    printf("Out-file : [%s]\n", dec_file);
    // out_file = (char *)".ABE_DIR/encryption/";
    // strcat(out_file, (char *)filename);
    // strcat(out_file, (char *)".cpabe");
    // dec_file = (char *)".ABE_DIR/decryption/";
    // strcat(dec_file, (char *)filename);
    pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
    prv = bswabe_prv_unserialize(pub, suck_file(prv_file), 1);
    read_cpabe_file(out_file, &cph_buf, &file_len, &aes_buf);
    cph = bswabe_cph_unserialize(pub, cph_buf, 1);
    if (!bswabe_dec(pub, prv, cph, &m1))
    {
        printf("++++++++++++++++++++ decryption done ++++++++++++++++++++\n\n");
        return;
    }
    GByteArray *plt1 = aes_128_cbc_decrypt(aes_buf, m1);
    spit_file(dec_file, plt1, 1);
    printf("++++++++++++++++++++ decryption done ++++++++++++++++++++\n\n");
}

void reciver(const char *str)
{
    printf("msg recived : %s\n", str);
}

int main()
{
    printf("main function doing nothing\n");
    return 0;
}
// int main()
// {

//     int k;
//     char *s1 = get_encryption_rule();
//     char **s2 = get_user_attrs(&k);
//     // printf("%s", s1);
//     return 0;
// }
/*
 gcc -I/opt/homebrew/include/glib-2.0/ -I/opt/homebrew//Cellar/glib/2.76.1/lib/glib-2.0/include/ -I/opt/homebrew/Cellar/openssl@3/3.1.0/include/ -I/opt/homebrew/Cellar/openssl@3/3.1.0/include/openssl/ -fPIC -shared -o app.so app.c -L. -lgmp -lpbc -lcrypto `pkg-config --cflags --libs glib-2.0`

  gcc -I/opt/homebrew/include/glib-2.0/ -I/opt/homebrew//Cellar/glib/2.76.1/lib/glib-2.0/include/ -I/opt/homebrew/Cellar/openssl@3/3.1.0/include/ -I/opt/homebrew/Cellar/openssl@3/3.1.0/include/openssl/ -fPIC -shared -o app.so app.c -L. -lgmp -lpbc -lcrypto `pkg-config --cflags --libs glib-2.0`
*/