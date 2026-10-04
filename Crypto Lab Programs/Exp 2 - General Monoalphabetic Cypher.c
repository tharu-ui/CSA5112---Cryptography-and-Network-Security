#include <stdio.h>

int main()
{
    char text[100], key[27], ch;
    int i, j;

    printf("Enter text: ");
    scanf(" %[^\n]", text);

    printf("Enter 26-letter key: ");
    scanf("%s", key);

    /* Encryption */
    for (i = 0; text[i] != '\0'; i++)
    {
        ch = text[i];

        if (ch >= 'A' && ch <= 'Z')
        {
            text[i] = key[ch - 'A'];
        }
        else if (ch >= 'a' && ch <= 'z')
        {
            text[i] = key[ch - 'a'] + 32;
        }
    }

    printf("Encrypted text: %s\n", text);

    /* Decryption */
    for (i = 0; text[i] != '\0'; i++)
    {
        ch = text[i];

        if (ch >= 'A' && ch <= 'Z')
        {
            for (j = 0; j < 26; j++)
            {
                if (key[j] == ch)
                {
                    text[i] = 'A' + j;
                    break;
                }
            }
        }
        else if (ch >= 'a' && ch <= 'z')
        {
            for (j = 0; j < 26; j++)
            {
                if (key[j] + 32 == ch)
                {
                    text[i] = 'a' + j;
                    break;
                }
            }
        }
    }

    printf("Decrypted text: %s\n", text);

    return 0;
}