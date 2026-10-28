/* Emit chacha20-poly1305@openssh.com packet vectors from OpenSSH's own implementation.
 * Linked against the objects of the pinned OpenSSH build (see scripts/gen-chachapoly-vectors.sh). */
#include "includes.h"
#include <stdio.h>
#include <string.h>
#include "cipher-chachapoly.h"

static unsigned long long state = 0x9e3779b97f4a7c15ULL;

static unsigned char next_byte(void)
{
	state ^= state << 13;
	state ^= state >> 7;
	state ^= state << 17;
	return (unsigned char)(state >> 32);
}

static void hex(const unsigned char *p, size_t n)
{
	for (size_t i = 0; i < n; i++)
		printf("%02x", p[i]);
}

int main(void)
{
	static const unsigned int seqs[] = {
		0, 1, 2, 255, 256, 65535, 65536, 0x7fffffffU, 0x80000000U, 0xfffffffeU, 0xffffffffU,
	};
	static const unsigned int lens[] = {
		4, 12, 28, 60, 64, 124, 252, 1020, 4092, 32764,
	};

	for (size_t k = 0; k < 4; k++) {
		unsigned char key[64];
		for (int i = 0; i < 64; i++)
			key[i] = next_byte();
		struct chachapoly_ctx *ctx = chachapoly_new(key, sizeof(key));
		if (ctx == NULL)
			return 1;
		for (size_t s = 0; s < sizeof(seqs) / sizeof(seqs[0]); s++) {
			for (size_t l = 0; l < sizeof(lens) / sizeof(lens[0]); l++) {
				unsigned int payload = lens[l];
				unsigned char *pt = malloc(4 + payload);
				unsigned char *ct = malloc(4 + payload + 16);
				for (unsigned int i = 0; i < 4 + payload; i++)
					pt[i] = next_byte();
				if (chachapoly_crypt(ctx, seqs[s], ct, pt, payload, 4, 16, 1) != 0)
					return 2;
				printf("key=");
				hex(key, 64);
				printf(" seq=%u pt=", seqs[s]);
				hex(pt, 4 + payload);
				printf(" ct=");
				hex(ct, 4 + payload + 16);
				printf("\n");
				free(pt);
				free(ct);
			}
		}
		chachapoly_free(ctx);
	}
	return 0;
}
