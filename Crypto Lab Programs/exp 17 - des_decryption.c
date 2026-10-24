#include <stdio.h>
#include <string.h>
#include <openssl/des.h>

int main()
{
    DES_cblock key = {'1','2','3','4','5','6','7','8'};
    DES_key_schedule ks;
    DES_cblock plain, cipher, recovered;

    printf("Enter 8 characters of plaintext:\n");
    scanf("%8s", plain);

    DES_set_key_unchecked(&key, &ks);

    DES_ecb_encrypt(&plain, &cipher, &ks, DES_ENCRYPT);
    DES_ecb_encrypt(&cipher, &recovered, &ks, DES_DECRYPT);

    printf("Encrypted block: ");
    for (int i = 0; i < 8; i++)
        printf("%02X ", cipher[i]);

    printf("\nDecrypted block: ");
    for (int i = 0; i < 8; i++)
        printf("%c", recovered[i]);

    printf("\n");
    return 0;
}