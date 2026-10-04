#include <stdio.h>

int main()
{
    char text[100], key[100];
    char ch;
    int i, j = 0, k;

    printf("Enter text: ");
    scanf(" %[^\n]", text);

    printf("Enter key: ");
    scanf("%s", key);

    /* Encryption */
    for (i = 0; text[i] != '\0'; i++)
    {
        ch = text[i];

        if (ch >= 'A' && ch <= 'Z')
        {
            k = key[j % 3] - 'A';
            text[i] = (ch - 'A' + k) % 26 + 'A';
            j++;
        }
        else if (ch >= 'a' && ch <= 'z')
        {
            k = key[j % 3] - 'A';
            text[i] = (ch - 'a' + k) % 26 + 'a';
            j++;
        }
    }

    printf("Encrypted text: %s\n", text);

    /* Decryption */
    j = 0;

    for (i = 0; text[i] != '\0'; i++)
    {
        ch = text[i];

        if (ch >= 'A' && ch <= 'Z')
        {
            k = key[j % 3] - 'A';
            text[i] = (ch - 'A' - k + 26) % 26 + 'A';
            j++;
        }
        else if (ch >= 'a' && ch <= 'z')
        {
            k = key[j % 3] - 'A';
            text[i] = (ch - 'a' - k + 26) % 26 + 'a';
            j++;
        }
    }

    printf("Decrypted text: %s\n", text);

    return 0;
}