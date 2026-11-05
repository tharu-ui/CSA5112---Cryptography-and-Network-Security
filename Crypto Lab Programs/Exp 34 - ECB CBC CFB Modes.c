
#include <stdio.h>
#include <string.h>

#define N 8

void encryptBlock(unsigned char in[], unsigned char out[],
                  unsigned char key[])
{
    for (int i = 0; i < N; i++)
        out[i] = in[i] ^ key[i];
}

void decryptBlock(unsigned char in[], unsigned char out[],
                  unsigned char key[])
{
    encryptBlock(in, out, key);
}

int main()
{
    unsigned char p[N] = "ABCDEFGH";
    unsigned char key[N] = "12345678";
    unsigned char iv[N] = "87654321";
    unsigned char c[N], d[N], temp[N];
    int i;

    printf("Plaintext: %s\n", p);

    /* ECB */
    encryptBlock(p, c, key);
    decryptBlock(c, d, key);

    printf("\nECB encrypted: ");
    for (i = 0; i < N; i++) printf("%02X ", c[i]);

    printf("\nECB decrypted: ");
    for (i = 0; i < N; i++) printf("%c", d[i]);

    /* CBC */
    for (i = 0; i < N; i++)
        temp[i] = p[i] ^ iv[i];

    encryptBlock(temp, c, key);

    for (i = 0; i < N; i++)
        temp[i] = c[i];

    decryptBlock(temp, d, key);

    for (i = 0; i < N; i++)
        d[i] ^= iv[i];

    printf("\n\nCBC encrypted: ");
    for (i = 0; i < N; i++) printf("%02X ", c[i]);

    printf("\nCBC decrypted: ");
    for (i = 0; i < N; i++) printf("%c", d[i]);

    /* CFB */
    encryptBlock(iv, temp, key);

    for (i = 0; i < N; i++)
        c[i] = p[i] ^ temp[i];

    encryptBlock(iv, temp, key);

    for (i = 0; i < N; i++)
        d[i] = c[i] ^ temp[i];

    printf("\n\nCFB encrypted: ");
    for (i = 0; i < N; i++) printf("%02X ", c[i]);

    printf("\nCFB decrypted: ");
    for (i = 0; i < N; i++) printf("%c", d[i]);

    printf("\n");
    return 0;
}
