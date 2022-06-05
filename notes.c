// Call KEM_KeyGen
// Call ZKeyGen
// Call XKeyGen
//

/*
assuming 1 <= m < 16384:
q = int32_div_uint14(x,m) means q = x/m
r = int32_mod_uint14(x,m) means r = x/m
int32_moddiv_uint14(&q,&r,x,m) means q = x/m, r = x%m
*/

/* ----- encoding small polynomials (including short polynomials) */

#define Small_bytes ((p+3)/4)

/* these are the only functions that rely on p mod 4 = 1 */

static void Small_encode(unsigned char *s,const small *f)
{
    small x;
    int i;

    for (i = 0;i < p/4;++i) {
        x = *f++ + 1;
        x += (*f++ + 1)<<2;
        x += (*f++ + 1)<<4;
        x += (*f++ + 1)<<6;
        *s++ = x;
    }
    x = *f++ + 1;
    *s++ = x;
}

void Encode(unsigned char *out,const uint16 *R,const uint16 *M,long long len)
{
    if (len == 1) {
        uint16 r = R[0];
        uint16 m = M[0];
        while (m > 1) {
            *out++ = r;
            r >>= 8;
            m = (m+255)>>8;
        }
    }
    if (len > 1) {
        uint16 R2[(len+1)/2];
        uint16 M2[(len+1)/2];
        long long i;
        for (i = 0;i < len-1;i += 2) {
            uint32 m0 = M[i];
            uint32 r = R[i]+R[i+1]*m0;
            uint32 m = M[i+1]*m0;
            while (m >= 16384) {
                *out++ = r;
                r >>= 8;
                m = (m+255)>>8;
            }
            R2[i/2] = r;
            M2[i/2] = m;
        }
        if (i < len) {
            R2[i/2] = R[i];
            M2[i/2] = M[i];
        }
        Encode(out,R2,M2,(len+1)/2);
    }
}



static void Rounded_encode(unsigned char *s,const Fq *r)
{
    uint16 R[p],M[p];
    int i;

    for (i = 0;i < p;++i) R[i] = ((r[i]+q12)*10923)>>15;
    for (i = 0;i < p;++i) M[i] = (q+2)/3;
    Encode(s,R,M,p);
}

/* ----- arithmetic mod 3 */

typedef int8 small;

/* F3 is always represented as -1,0,1 */
/* so ZZ_fromF3 is a no-op */

/* x must not be close to top int16 */
static small F3_freeze(int16 x)
{
    return int32_mod_uint14(x+1,3)-1;
}


static void Round(Fq *out,const Fq *a)
{
    int i;
    for (i = 0;i < p;++i) out[i] = a[i]-F3_freeze(a[i]);
}


/* h = f*g in the ring Rq */
static void Rq_mult_small(Fq *h,const Fq *f,const small *g)
{
    Fq fg[p+p-1];
    Fq result;
    int i,j;

    for (i = 0;i < p;++i) {
        result = 0;
        for (j = 0;j <= i;++j) result = Fq_freeze(result+f[j]*(int32)g[i-j]);
        fg[i] = result;
    }
    for (i = p;i < p+p-1;++i) {
        result = 0;
        for (j = i-p+1;j < p;++j) result = Fq_freeze(result+f[j]*(int32)g[i-j]);
        fg[i] = result;
    }

    for (i = p+p-2;i >= p;--i) {
        fg[i-p] = Fq_freeze(fg[i-p]+fg[i]);
        fg[i-p+1] = Fq_freeze(fg[i-p+1]+fg[i]);
    }

    for (i = 0;i < p;++i) h[i] = fg[i];
}


static void Short_random(small *out)
{
    uint32 L[p];
    int i;

    for (i = 0;i < p;++i) L[i] = urandom32();
    Short_fromlist(out,L);
}


static const unsigned char aes_nonce[16] = {0};

static void Expand(uint32 *L,const unsigned char *k)
{
    int i;
    if (crypto_stream_aes256ctr((unsigned char *) L,4*p,aes_nonce,k) != 0) abort();


    for (i = 0;i < p;++i) {
        uint32 L0 = ((unsigned char *) L)[4*i];
        uint32 L1 = ((unsigned char *) L)[4*i+1];
        uint32 L2 = ((unsigned char *) L)[4*i+2];
        uint32 L3 = ((unsigned char *) L)[4*i+3];
        L[i] = L0+(L1<<8)+(L2<<16)+(L3<<24);
    }
}

static void KeyGen(Fq *A,small *a,const Fq *G)
{
    Fq aG[p];

    Short_random(a);
    Rq_mult_small(aG,G,a);
    Round(A,aG);
}

static void Generator(Fq *G,const unsigned char *k)
{
    uint32 L[p];
    int i;

    Expand(L,k);
    for (i = 0;i < p;++i) G[i] = uint32_mod_uint14(L[i],q)-q12;
}

static void Seeds_random(unsigned char *s)
{
    // s Seeds_bytes
    randombytes(s,Seeds_bytes);
}

/* (S,A),a = XKeyGen() */
static void XKeyGen(unsigned char *S,Fq *A,small *a)
{
    Fq G[p];

    Seeds_random(S);
    Generator(G,S);
    KeyGen(A,a,G);
}

/* pk,sk = ZKeyGen() */
static void ZKeyGen(unsigned char *pk,unsigned char *sk)
{
    Fq A[p];
    small a[p];

    XKeyGen(pk,A,a);
    print("PK = %X",pk);
    pk += Seeds_bytes;
    print("PK = %X",pk);
    Rounded_encode(pk,A);
    Small_encode(sk,a);
}

static void KEM_KeyGen(unsigned char *pk,unsigned char *sk)
{
    int i;
    printf("KEM_KeyGen\n");
    ZKeyGen(pk,sk); sk += SecretKeys_bytes;
    for (i = 0;i < PublicKeys_bytes;++i) *sk++ = pk[i];
    randombytes(sk,Inputs_bytes); sk += Inputs_bytes;
    Hash_prefix(sk,4,pk,PublicKeys_bytes);
}
// Process: KEM_KeyGen
// ZKeyGen(pk,sk)
//  XKeyGen(pk,A,a)
//   Seeds_random(S)
//   Generator(G,S)
//    Expand(L,k)
//   KeyGen(A,a,G)
//    Short_random(a)
//     urandom32 -> Short_fromlist(a,L)
//    Rq_mult_small(aG,G,a)
//    Round(A,aG)
//     Fq_freeze(a[i)
//      int32_mod_uint14(L[i],q)
//
//  Rounded_encode(pk,A)
//   Encode(s,R,M,p)
//  Small_encode(sk,a)





