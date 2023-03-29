#include <stdio.h>
#include <pbc/pbc.h>
#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

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

    printf("setup done\n");
}


void
element_from_string( element_t h, char* s )
{
	unsigned char* r;

	r = (unsigned char *)malloc(SHA_DIGEST_LENGTH);
	SHA1((unsigned char*) s, strlen(s), r);
	element_from_hash(h, r, SHA_DIGEST_LENGTH);

	free(r);
}

bswabe_prv_t* bswabe_keygen( bswabe_pub_t* pub,
														 bswabe_msk_t* msk,
														 char** attributes )
{
	bswabe_prv_t* prv;
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

	while( *attributes )
	{
		bswabe_prv_comp_t c;
		element_t h_rp;
		element_t rp;

		c.attr = *(attributes++);

		element_init_G2(c.d,  pub->p);
		element_init_G1(c.dp, pub->p);
		element_init_G2(h_rp, pub->p);
		element_init_Zr(rp,   pub->p);
		
 		element_from_string(h_rp, c.attr);
 		element_random(rp);

		element_pow_zn(h_rp, h_rp, rp);

		element_mul(c.d, g_r, h_rp);
		element_pow_zn(c.dp, pub->g, rp);

		element_clear(h_rp);
		element_clear(rp);

		g_array_append_val(prv->comps, c);
	}
    printf("kegen done \n");
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
                attrs[n]=(char *)malloc(sizeof(char)*len);
                // strcpy(attrs[n], temp);
                // strcat(attrs[n], temp);
                // attrs[n] = temp;
                int k;
                for(k=0; k<=j; k++)attrs[n][k]=temp[k];
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

int main()
{
    char *pub_file = (char *)"pub_key";
    char *msk_file = (char *)"master_key";
    bswabe_pub_t *pub;
    bswabe_msk_t *msk;
    bswabe_prv_t* prv;
    bswabe_setup(&pub, &msk);
    char **attrs = (char **)malloc(sizeof(char *)*2);
    attrs[0]= (char *)malloc(sizeof(char)*50);
    attrs[1]= (char *)malloc(sizeof(char)*50);
    attrs[0] = (char *)"name:kamal";
    attrs[1] = (char *)"age:20";
    // int n = key_gen_parse_attrs((char *)"name:kamal age:20", attrs);
    // printf("%d\n", n);
    // printf("%s", attrs[0]);
    prv = bswabe_keygen(pub, msk, attrs);
    printf("done...");
    return 0;
}