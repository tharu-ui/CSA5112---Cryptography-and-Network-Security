
#include <stdio.h>
#include <string.h>
#include <openssl/des.h>

int main()
{
    char plain[65], recovered[80];
    unsigned char cipher[80];
    unsigned char key[24] = "123456789012345678901234";
    unsigned char iv[8] = "12345678";
    unsigned char iv2[8] = "12345678";
    DES_key_schedule k1, k2, k3;
    int len, padded, i;

    printf("Enter plaintext:\n");
    fgets(plain, sizeof(plain), stdin);

    len = strlen(plain);

    if (len > 0 && plain[len - 1] == '\n')
        len--;

    padded = ((len / 8) + 1) * 8;

    for (i = len; i < padded; i++)
        plain[i] = padded - len;

    DES_set_key_unchecked((DES_cblock *)(key), &k1);
    DES_set_key_unchecked((DES_cblock *)(key + 8), &k2);
    DES_set_key_unchecked((DES_cblock *)(key + 16), &k3);

    DES_ede3_cbc_encrypt(
        (unsigned char *)plain, cipher, padded,
        &k1, &k2, &k3, (DES_cblock *)iv, DES_ENCRYPT
    );

    printf("Encrypted ciphertext: ");
    for (i = 0; i < padded; i++)
        printf("%02X", cipher[i]);

    DES_ede3_cbc_encrypt(
        cipher, (unsigned char *)recovered, padded,
        &k1, &k2, &k3, (DES_cblock *)iv2, DES_DECRYPT
    );

    recovered[padded] = '\0';

    printf("\nDecrypted plaintext: ");
    for (i = 0; i < len; i++)
        printf("%c", recovered[i]);

    printf("\n");

    return 0;
}
