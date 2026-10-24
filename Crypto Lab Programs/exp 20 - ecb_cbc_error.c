#include <stdio.h>

int main()
{
    int p[10], c[10], d[10];
    int n, i, key, error;

    printf("Enter number of blocks: ");
    scanf("%d", &n);

    printf("Enter plaintext blocks: ");
    for (i = 0; i < n; i++)
    {
        scanf("%d", &p[i]);
    }

    printf("Enter key: ");
    scanf("%d", &key);

    printf("Enter error block number: ");
    scanf("%d", &error);

    printf("\nECB Mode:\n");

    for (i = 0; i < n; i++)
        c[i] = p[i] ^ key;

    c[error - 1] = c[error - 1] ^ 1;

    for (i = 0; i < n; i++)
        d[i] = c[i] ^ key;

    printf("Decrypted blocks: ");
    for (i = 0; i < n; i++)
        printf("%d ", d[i]);

    printf("\n\nCBC Mode:\n");

    for (i = 0; i < n; i++)
    {
        if (i == 0)
            c[i] = p[i] ^ key;
        else
            c[i] = p[i] ^ key ^ c[i - 1];
    }

    c[error - 1] = c[error - 1] ^ 1;

    for (i = 0; i < n; i++)
    {
        if (i == 0)
            d[i] = c[i] ^ key;
        else
            d[i] = c[i] ^ key ^ c[i - 1];
    }

    printf("Decrypted blocks: ");
    for (i = 0; i < n; i++)
        printf("%d ", d[i]);

    return 0;
}