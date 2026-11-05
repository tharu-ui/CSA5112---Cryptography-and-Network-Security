
#include <stdio.h>
#include <string.h>
#include <openssl/des.h>

int main()
{
    DES_cblock key;
    DES_key_schedule schedule;

    DES_cblock plaintext;
    DES_cblock ciphertext;
    DES_cblock decrypted;

    int i;

    printf("Enter 8-character key: ");
    scanf("%8s", (char *)key);

    printf("Enter 8-character plaintext: ");
    scanf("%8s", (char *)plaintext);

    DES_set_key_unchecked(&key, &schedule);

    DES_ecb_encrypt(&plaintext, &ciphertext, &schedule, DES_ENCRYPT);

    printf("\nEncrypted ciphertext: ");

    for (i = 0; i < 8; i++)
        printf("%02X", ciphertext[i]);

    DES_ecb_encrypt(&ciphertext, &decrypted, &schedule, DES_DECRYPT);

    printf("\nDecrypted plaintext: ");

    for (i = 0; i < 8; i++)
        printf("%c", decrypted[i]);

    printf("\n");

    return 0;
}
