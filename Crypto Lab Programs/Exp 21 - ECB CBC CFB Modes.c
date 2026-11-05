
#include <stdio.h>
#include <string.h>

int main()
{
    unsigned char data[200], ecb[200], cbc[200], cfb[200];
    unsigned char dec[200];
    unsigned char key, iv, temp, reg;
    char plain[200];
    int n, i;

    printf("Enter plaintext: ");
    scanf("%199s", plain);

    printf("Enter key (0-255): ");
    scanf("%hhu", &key);

    printf("Enter IV (0-255): ");
    scanf("%hhu", &iv);

    n = strlen(plain);

    for (i = 0; i < n; i++)
        data[i] = plain[i];

    /* Add 1 bit followed by zero bits.
       Each block is 8 bits, so append 10000000. */
    data[n] = 128;
    n++;

    /* ECB Encryption */
    for (i = 0; i < n; i++)
        ecb[i] = data[i] ^ key;

    /* CBC Encryption */
    temp = iv;
    for (i = 0; i < n; i++)
    {
        cbc[i] = (data[i] ^ temp) ^ key;
        temp = cbc[i];
    }

    /* CFB Encryption */
    reg = iv;
    for (i = 0; i < n; i++)
    {
        cfb[i] = data[i] ^ (reg ^ key);
        reg = cfb[i];
    }

    printf("\nECB Ciphertext: ");
    for (i = 0; i < n; i++)
        printf("%02X ", ecb[i]);

    printf("\nCBC Ciphertext: ");
    for (i = 0; i < n; i++)
        printf("%02X ", cbc[i]);

    printf("\nCFB Ciphertext: ");
    for (i = 0; i < n; i++)
        printf("%02X ", cfb[i]);

    /* ECB Decryption */
    for (i = 0; i < n; i++)
        dec[i] = ecb[i] ^ key;

    printf("\n\nECB Decrypted: ");
    for (i = 0; i < n; i++)
        printf("%02X ", dec[i]);

    /* CBC Decryption */
    temp = iv;
    for (i = 0; i < n; i++)
    {
        dec[i] = (cbc[i] ^ key) ^ temp;
        temp = cbc[i];
    }

    printf("\nCBC Decrypted: ");
    for (i = 0; i < n; i++)
        printf("%02X ", dec[i]);

    /* CFB Decryption */
    reg = iv;
    for (i = 0; i < n; i++)
    {
        dec[i] = cfb[i] ^ (reg ^ key);
        reg = cfb[i];
    }

    printf("\nCFB Decrypted: ");
    for (i = 0; i < n; i++)
        printf("%02X ", dec[i]);

    printf("\n\nPadding is added to identify the message ending.");
    printf("\nIt also distinguishes messages with complete blocks.");

    return 0;
}
