#include <stdio.h>

int main()
{
    char text[100], ch;
    int shift, i;

    printf("Enter text: ");
    scanf(" %[^\n]", text);

    printf("Enter shift: ");
    scanf("%d", &shift);

    for (i = 0; text[i] != '\0'; i++)
    {
        ch = text[i];

        if (ch >= 'A' && ch <= 'Z')
            text[i] = (ch - 'A' + shift) % 26 + 'A';

        else if (ch >= 'a' && ch <= 'z')
            text[i] = (ch - 'a' + shift) % 26 + 'a';
    }

    printf("Encrypted text: %s\n", text);

    for (i = 0; text[i] != '\0'; i++)
    {
        ch = text[i];

        if (ch >= 'A' && ch <= 'Z')
            text[i] = (ch - 'A' - shift + 26) % 26 + 'A';

        else if (ch >= 'a' && ch <= 'z')
            text[i] = (ch - 'a' - shift + 26) % 26 + 'a';
    }

    printf("Decrypted text: %s\n", text);

    return 0;
}