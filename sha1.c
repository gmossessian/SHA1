/*
 * SHA1.c
 *
 *  Created on: Dec 15, 2015
 *      Author: George Mossessian
 *
 *      Following NIST FIPS-180-4 http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 *
 *	Do not use in production code. This was written for learning purposes only.
 *
 */

#include "sha1.h"

uint32_t h0 = 0x67452301UL;
uint32_t h1 = 0xEFCDAB89UL;
uint32_t h2 = 0x98BADCFEUL;
uint32_t h3 = 0x10325476UL;
uint32_t h4 = 0xC3D2E1F0UL;

int debuggingSHA1=0;

uint32_t SHA1Logicalf(uint32_t b, uint32_t c, uint32_t d, int t);
uint32_t const_k(int t);
void resetSHA1Registers(void);

void setSHA1Registers(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e){
	h0=a;
	h1=b;
	h2=c;
	h3=d;
	h4=e;
}

void resetSHA1Registers(void){
	h0 = 0x67452301UL;
	h1 = 0xEFCDAB89UL;
	h2 = 0x98BADCFEUL;
	h3 = 0x10325476UL;
	h4 = 0xC3D2E1F0UL;
}

string SHA1(string message){
	return SHA1Digest(SHA1Preprocessing(message));
}



uint32_t SHA1Logicalf(uint32_t b, uint32_t c, uint32_t d, int t){
	if(t>=0 && t<=19) return (b & c ) ^ ((~b) & d);
	if(t>=20 && t<=39) return b ^ c ^ d;
	if(t>=40 && t<=59) return (b & c) ^ (b & d) ^ (c & d);
	if(t>=60 && t<=79) return b ^ c ^ d;
	return 0;
}

uint32_t const_k(int t){
	if(t>=0 && t<=19) return 0x5a827999UL;
	if(t>=20 && t<=39) return 0x6ed9eba1UL;
	if(t>=40 && t<=59) return 0x8f1bbcdcUL;
	if(t>=60 && t<=79) return 0xca62c1d6UL;
	return 0;
}

string SHA1Preprocessing(string message){
	string m=LOCALSTRING(message);
	char tempChar;
	string t;
	uint64_t ml=8*m.len;
	int i;

	//append the bit '1' to the message e.g. by adding 0x80 if message length is a multiple of 8 bits.
	tempChar = 0x80;
	m=stringCat(m, newString(&tempChar,1));


	//append 0 ≤ k < 512 bits '0', such that the resulting message length in bits
	//	is congruent to −64 ≡ 448 (mod 512)4
	i=((56-m.len)%64);
	if(i<0) i+=64;
	m=stringCat(m,newString(NULL, i));

	//append ml, in a 64-bit big-endian integer. Thus, the total length is a multiple of 512 bits.
	t=newString(NULL,8);
	for(i=0; i<8; i++){
		t.c[i] = (ml >> ((7-i)*8)) & 0xFF;
	}
	return stringCat(m,t);
}

string SHA1Digest(string message){
	string m=LOCALSTRING(message);
	string *chunks;
	string *w;
	int numChunks;
	int i,j;
	uint32_t a,b,c,d,e,f,k,temp;
	string digest;

	//	break message into 512-bit chunks
	chunks = blockString(m,64);
	numChunks = numBlocks(m,64);

	for(i=0; i<numChunks; i++){
		w = blockString(chunks[i],4);
		w = (string *)realloc(w, sizeof(string)*80);
		for(j=16; j<80; j++){
			w[j]=stringLeftRotate(stringXOR(stringXOR(stringXOR(w[j-3],w[j-8]),w[j-14]),w[j-16]),1);
		}

	    a = h0;
	    b = h1;
	    c = h2;
	    d = h3;
	    e = h4;

	    if(debuggingSHA1){
	    	for(j=0; j<80; j++){
	    		printf("w[%02i]: ",j); printsint(w[j]); PRINTNL;
	    	}
	    }

	    for(j=0; j<80; j++){

	    	f=SHA1Logicalf(b,c,d,j);
	    	k=const_k(j);

	    	temp = ((a<<5)|(a>>27)) + f + e + k + stringToUint32(w[j]);
	    	e = d;
	        d = c;
	        c = ((b<<30)|(b>>2));
	        b = a;
	        a = temp;

	        if(debuggingSHA1) printf("%i: %x %x %x %x %x\n", j, a, b, c, d, e);
	    }
	    h0 += a;
	    h1 += b;
	    h2 += c;
	    h3 += d;
	    h4 += e;
	}
	digest=stringCat(stringCat(stringCat(stringCat(
			uint32ToString(h0),uint32ToString(h1)),uint32ToString(h2)),uint32ToString(h3)),uint32ToString(h4));
	resetSHA1Registers();
	return digest;
}

string SHA1HMAC(string key, string message){
	int blocksize=64;
	unsigned char o = 0x5c;
	unsigned char i = 0x36;
	string okey_pad, ikey_pad;

	if(key.len > blocksize) key = SHA1(key);
	if(key.len < blocksize) key = stringCat(key, newString(NULL, blocksize - key.len));

	okey_pad = stringXOR(key, newString((char *)&o,1));
	ikey_pad = stringXOR(key, newString((char *)&i,1));

	return SHA1(stringCat(okey_pad , SHA1(stringCat(ikey_pad, message))));
}
