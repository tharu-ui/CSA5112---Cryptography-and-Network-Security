
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

int main()
{
    char text[100], encrypted[100], decrypted[100];
    int key[100], i, n;

    srand(time(NULL));

    printf("Enter plaintext: ");
    scanf("%99s", text);

    n = strlen(text);

    printf("\nGenerated key: ");
    for (i = 0; i < n; i++)
    {
        key[i] = rand() % 26;
        printf("%d ", key[i]);
    }

    for (i = 0; i < n; i++)
    {
        encrypted[i] = ((text[i] - 'A' + key[i]) % 26) + 'A';
    }
    encrypted[n] = '\0';

    for (i = 0; i < n; i++)
    {
        decrypted[i] = ((encrypted[i] - 'A' - key[i] + 26) % 26) + 'A';
    }
    decrypted[n] = '\0';

    printf("\nEncrypted text: %s", encrypted);
    printf("\nDecrypted text: %s\n", decrypted);

    return 0;
}

