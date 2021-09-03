#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	unsigned long total[2];	/*!< number of bytes processed  */
	unsigned long state[5];	/*!< intermediate digest state  */
	unsigned char buffer[64];	/*!< data block being processed */

	unsigned char ipad[64];	/*!< HMAC: inner padding        */
	unsigned char opad[64];	/*!< HMAC: outer padding        */
} sha1_context;

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
        | ( (unsigned long) (b)[(i) + 1] << 16 )        \
        | ( (unsigned long) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

/*
 * SHA-1 context setup
 */
void sha1_starts(sha1_context * ctx)
{
	ctx->total[0] = 0;
	ctx->total[1] = 0;

	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xC3D2E1F0;
}

static void sha1_process(sha1_context * ctx, const unsigned char data[64])
{
	unsigned long temp, W[16], A, B, C, D, E;

	GET_ULONG_BE(W[0], data, 0);
	GET_ULONG_BE(W[1], data, 4);
	GET_ULONG_BE(W[2], data, 8);
	GET_ULONG_BE(W[3], data, 12);
	GET_ULONG_BE(W[4], data, 16);
	GET_ULONG_BE(W[5], data, 20);
	GET_ULONG_BE(W[6], data, 24);
	GET_ULONG_BE(W[7], data, 28);
	GET_ULONG_BE(W[8], data, 32);
	GET_ULONG_BE(W[9], data, 36);
	GET_ULONG_BE(W[10], data, 40);
	GET_ULONG_BE(W[11], data, 44);
	GET_ULONG_BE(W[12], data, 48);
	GET_ULONG_BE(W[13], data, 52);
	GET_ULONG_BE(W[14], data, 56);
	GET_ULONG_BE(W[15], data, 60);

#define S(x,n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))

#define R(t)                                            \
(                                                       \
    temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^     \
           W[(t - 14) & 0x0F] ^ W[ t      & 0x0F],      \
    ( W[t & 0x0F] = S(temp,1) )                         \
)

#define P(a,b,c,d,e,x)                                  \
{                                                       \
    e += S(a,5) + F(b,c,d) + K + x; b = S(b,30);        \
}

	A = ctx->state[0];
	B = ctx->state[1];
	C = ctx->state[2];
	D = ctx->state[3];
	E = ctx->state[4];

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

	P(A, B, C, D, E, W[0]);
	P(E, A, B, C, D, W[1]);
	P(D, E, A, B, C, W[2]);
	P(C, D, E, A, B, W[3]);
	P(B, C, D, E, A, W[4]);
	P(A, B, C, D, E, W[5]);
	P(E, A, B, C, D, W[6]);
	P(D, E, A, B, C, W[7]);
	P(C, D, E, A, B, W[8]);
	P(B, C, D, E, A, W[9]);
	P(A, B, C, D, E, W[10]);
	P(E, A, B, C, D, W[11]);
	P(D, E, A, B, C, W[12]);
	P(C, D, E, A, B, W[13]);
	P(B, C, D, E, A, W[14]);
	P(A, B, C, D, E, W[15]);
	P(E, A, B, C, D, R(16));
	P(D, E, A, B, C, R(17));
	P(C, D, E, A, B, R(18));
	P(B, C, D, E, A, R(19));

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

	P(A, B, C, D, E, R(20));
	P(E, A, B, C, D, R(21));
	P(D, E, A, B, C, R(22));
	P(C, D, E, A, B, R(23));
	P(B, C, D, E, A, R(24));
	P(A, B, C, D, E, R(25));
	P(E, A, B, C, D, R(26));
	P(D, E, A, B, C, R(27));
	P(C, D, E, A, B, R(28));
	P(B, C, D, E, A, R(29));
	P(A, B, C, D, E, R(30));
	P(E, A, B, C, D, R(31));
	P(D, E, A, B, C, R(32));
	P(C, D, E, A, B, R(33));
	P(B, C, D, E, A, R(34));
	P(A, B, C, D, E, R(35));
	P(E, A, B, C, D, R(36));
	P(D, E, A, B, C, R(37));
	P(C, D, E, A, B, R(38));
	P(B, C, D, E, A, R(39));

#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

	P(A, B, C, D, E, R(40));
	P(E, A, B, C, D, R(41));
	P(D, E, A, B, C, R(42));
	P(C, D, E, A, B, R(43));
	P(B, C, D, E, A, R(44));
	P(A, B, C, D, E, R(45));
	P(E, A, B, C, D, R(46));
	P(D, E, A, B, C, R(47));
	P(C, D, E, A, B, R(48));
	P(B, C, D, E, A, R(49));
	P(A, B, C, D, E, R(50));
	P(E, A, B, C, D, R(51));
	P(D, E, A, B, C, R(52));
	P(C, D, E, A, B, R(53));
	P(B, C, D, E, A, R(54));
	P(A, B, C, D, E, R(55));
	P(E, A, B, C, D, R(56));
	P(D, E, A, B, C, R(57));
	P(C, D, E, A, B, R(58));
	P(B, C, D, E, A, R(59));

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

	P(A, B, C, D, E, R(60));
	P(E, A, B, C, D, R(61));
	P(D, E, A, B, C, R(62));
	P(C, D, E, A, B, R(63));
	P(B, C, D, E, A, R(64));
	P(A, B, C, D, E, R(65));
	P(E, A, B, C, D, R(66));
	P(D, E, A, B, C, R(67));
	P(C, D, E, A, B, R(68));
	P(B, C, D, E, A, R(69));
	P(A, B, C, D, E, R(70));
	P(E, A, B, C, D, R(71));
	P(D, E, A, B, C, R(72));
	P(C, D, E, A, B, R(73));
	P(B, C, D, E, A, R(74));
	P(A, B, C, D, E, R(75));
	P(E, A, B, C, D, R(76));
	P(D, E, A, B, C, R(77));
	P(C, D, E, A, B, R(78));
	P(B, C, D, E, A, R(79));

#undef K
#undef F

	ctx->state[0] += A;
	ctx->state[1] += B;
	ctx->state[2] += C;
	ctx->state[3] += D;
	ctx->state[4] += E;
}

/*
 * SHA-1 process buffer
 */
void sha1_update(sha1_context * ctx, const unsigned char *input, int ilen)
{
	int fill;
	unsigned long left;

	if (ilen <= 0)
		return;

	left = ctx->total[0] & 0x3F;
	fill = 64 - left;

	ctx->total[0] += (unsigned long) ilen;
	ctx->total[0] &= 0xFFFFFFFF;

	if (ctx->total[0] < (unsigned long) ilen)
		ctx->total[1]++;

	if (left && ilen >= fill) {
		memcpy((void *) (ctx->buffer + left), (void *) input, fill);
		sha1_process(ctx, ctx->buffer);
		input += fill;
		ilen -= fill;
		left = 0;
	}

	while (ilen >= 64) {
		sha1_process(ctx, input);
		input += 64;
		ilen -= 64;
	}

	if (ilen > 0) {
		memcpy((void *) (ctx->buffer + left), (void *) input, ilen);
	}
}

static const unsigned char sha1_padding[64] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * SHA-1 final digest
 */
void sha1_finish(sha1_context * ctx, unsigned char output[20])
{
	unsigned long last, padn;
	unsigned long high, low;
	unsigned char msglen[8];

	high = (ctx->total[0] >> 29)
	    | (ctx->total[1] << 3);
	low = (ctx->total[0] << 3);

	PUT_ULONG_BE(high, msglen, 0);
	PUT_ULONG_BE(low, msglen, 4);

	last = ctx->total[0] & 0x3F;
	padn = (last < 56) ? (56 - last) : (120 - last);

	sha1_update(ctx, (unsigned char *) sha1_padding, padn);
	sha1_update(ctx, msglen, 8);

	PUT_ULONG_BE(ctx->state[0], output, 0);
	PUT_ULONG_BE(ctx->state[1], output, 4);
	PUT_ULONG_BE(ctx->state[2], output, 8);
	PUT_ULONG_BE(ctx->state[3], output, 12);
	PUT_ULONG_BE(ctx->state[4], output, 16);
}

/*
 * output = SHA-1( input buffer )
 */
void sha1(const unsigned char *input, int ilen, unsigned char output[20])
{
	sha1_context ctx;

	sha1_starts(&ctx);
	sha1_update(&ctx, input, ilen);
	sha1_finish(&ctx, output);

}


/*
 * SHA-1 HMAC context setup
 */
void sha1_hmac_starts(sha1_context * ctx, const unsigned char *key, int keylen)
{
	int i;
	unsigned char sum[20];

	if (keylen > 64) {
		sha1(key, keylen, sum);
		keylen = 20;
		key = sum;
	}

	memset(ctx->ipad, 0x36, 64);
	memset(ctx->opad, 0x5C, 64);

	for (i = 0; i < keylen; i++) {
		ctx->ipad[i] = (unsigned char) (ctx->ipad[i] ^ key[i]);
		ctx->opad[i] = (unsigned char) (ctx->opad[i] ^ key[i]);
	}

	sha1_starts(ctx);
	sha1_update(ctx, ctx->ipad, 64);

}

/*
 * SHA-1 HMAC process buffer
 */
void sha1_hmac_update(sha1_context * ctx, const unsigned char *input, int ilen)
{
	sha1_update(ctx, input, ilen);
}

/*
 * SHA-1 HMAC final digest
 */
void sha1_hmac_finish(sha1_context * ctx, unsigned char output[20])
{
	unsigned char tmpbuf[20];

	sha1_finish(ctx, tmpbuf);
	sha1_starts(ctx);
	sha1_update(ctx, ctx->opad, 64);
	sha1_update(ctx, tmpbuf, 20);
	sha1_finish(ctx, output);

}

/*
 * SHA1 HMAC context reset
 */
void sha1_hmac_reset(sha1_context * ctx)
{
	sha1_starts(ctx);
	sha1_update(ctx, ctx->ipad, 64);
}

/*
 * output = HMAC-SHA-1( hmac key, input buffer )
 */
void sha1_hmac(const unsigned char *key, int keylen,
    const unsigned char *input, int ilen, unsigned char output[20])
{
	sha1_context ctx;

	sha1_hmac_starts(&ctx, key, keylen);
	sha1_hmac_update(&ctx, input, ilen);
	sha1_hmac_finish(&ctx, output);

}


#ifndef min
#define min( a, b ) ( ((a) < (b)) ? (a) : (b) )
#endif

void Self_PKCS5_PBKDF2_HMAC(const unsigned char *password, size_t plen,
    const unsigned char *salt, size_t slen,
    const unsigned long iteration_count, const unsigned long key_length,
    unsigned char *output)
{
	sha1_context ctx;
	sha1_starts(&ctx);

	// Size of the generated digest
	unsigned char md_size = 20;
	unsigned char md1[20];
	unsigned char work[20];

	unsigned long counter = 1;
	unsigned long generated_key_length = 0;
	while (generated_key_length < key_length) {
		// U1 ends up in md1 and work
		unsigned char c[4];
		c[0] = (counter >> 24) & 0xff;
		c[1] = (counter >> 16) & 0xff;
		c[2] = (counter >> 8) & 0xff;
		c[3] = (counter >> 0) & 0xff;

		sha1_hmac_starts(&ctx, password, plen);
		sha1_hmac_update(&ctx, salt, slen);
		sha1_hmac_update(&ctx, c, 4);
		sha1_hmac_finish(&ctx, md1);
		memcpy(work, md1, md_size);

		unsigned long ic = 1;
		for (ic = 1; ic < iteration_count; ic++) {
			// U2 ends up in md1
			sha1_hmac_starts(&ctx, password, plen);
			sha1_hmac_update(&ctx, md1, md_size);
			sha1_hmac_finish(&ctx, md1);
			// U1 xor U2
			unsigned long i = 0;
			for (i = 0; i < md_size; i++) {
				work[i] ^= md1[i];
			}
			// and so on until iteration_count
		}

		// Copy the generated bytes to the key
		unsigned long bytes_to_write =
		    min((key_length - generated_key_length), md_size);
		memcpy(output + generated_key_length, work, bytes_to_write);
		generated_key_length += bytes_to_write;
		++counter;
	}
}

static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
	printf("\n");
}

char* textFromHexString(char* hexinput)
{
    char temp[3];
    int index = 0;
    int i=0;
    int len = strlen(hexinput);
    char text[(len/2)+1];
    temp[2] = '\0';
    while (hexinput[index])
    {
        if(hexinput[index])
        strncpy(temp, &hexinput[index], 2);
        text[i] = (char)strtol(temp, NULL, 16);
        i++;
        index += 2;
    }
    text[i] = '\0';
    char* txtoutput = text;
    return(txtoutput);
}

char base46_map[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                     'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                     'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                     'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};


static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};
 
void build_decoding_table() 
{ 
    decoding_table = malloc(256);
 
    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) base46_map[i]] = i;
}
 
void base64_cleanup() 
{
    free(decoding_table);
} 

char* encodeBase64(const unsigned char *data) 
{
	int input_length = strlen(data);
    int output_length = 4 * ((input_length + 2) / 3);
 
    char *encoded_data = malloc(output_length);
    if (encoded_data == NULL) return NULL;
 
    for (int i = 0, j = 0; i < input_length;) {
 
        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;
 
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
 
        encoded_data[j++] = base46_map[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = base46_map[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = base46_map[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = base46_map[(triple >> 0 * 6) & 0x3F];
    }
 
    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[output_length - 1 - i] = '=';
 
	// printf("Encode data: %s\n", encoded_data);
    return encoded_data;
}

char* decodeBase64(const char *data) 
{
    int input_length = strlen(data);
 
    if (decoding_table == NULL) build_decoding_table();
 
    if (input_length % 4 != 0) return NULL;
 
    int output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (output_length)--;
    if (data[input_length - 2] == '=') (output_length)--;
 
    unsigned char *decoded_data = malloc(output_length);
    if (decoded_data == NULL) return NULL;
 
    for (int i = 0, j = 0; i < input_length;) 
	{
 
        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
 
        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);
 
        if (j < output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }
 
    return decoded_data;
}

char* randomNonce(int length) 
{    
    char *string = "0123456789abcdef";
    size_t stringlength = 16;   
    char *randomstring;
    randomstring = malloc(sizeof(char) * (length +1));
    if (!randomstring) 
    {
        printf("Nonce Genaration Failed!\n");
        return (char*)0;
    }
    srand (time(NULL));
    unsigned int key = 0;
    for (int n=0;n<length;n++)
    {            
        key = rand() % stringlength;          
        randomstring[n] = string[key];
    }
    randomstring[length] = '\0';
    return randomstring;
}