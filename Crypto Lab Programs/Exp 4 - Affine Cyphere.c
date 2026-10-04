#include <stdio.h>

int main()
{
    char text[100], ch;
    int a, b, i, x, inverse;

    printf("Enter text: ");
    scanf(" %[^\n]", text);

    printf("Enter a: ");
    scanf("%d", &a);

    printf("Enter b: ");
    scanf("%d", &b);

    /* Find inverse of a */
    for (i = 0; i < 26; i++)
    {
        if ((a * i) % 26 == 1)
        {
            inverse = i;
            break;
        }
    }

    /* Encryption */
    for (i = 0; text[i] != '\0'; i++)
    {
        ch = text[i];

        if (ch >= 'A' && ch <= 'Z')
        {
            x = ch - 'A';
            text[i] = (a * x + b) % 26 + 'A';
        }

        else if (ch >= 'a' && ch <= 'z')
        {
            x = ch - 'a';
            text[i] = (a * x + b) % 26 + 'a';
        }
    }

    printf("Encrypted text: %s\n", text);

    /* Decryption */
    for (i = 0; text[i] != '\0'; i++)
    {
        ch = text[i];

        if (ch >= 'A' && ch <= 'Z')
        {
            x = ch - 'A';
            text[i] = (inverse * (x - b + 26)) % 26 + 'A';
        }

        else if (ch >= 'a' && ch <= 'z')
        {
            x = ch - 'a';
            text[i] = (inverse * (x - b + 26)) % 26 + 'a';
        }
    }

    printf("Decrypted text: %s\n", text);

    return 0;
}