
#include <stdio.h>
#include <ctype.h>
#include <string.h>

int main()
{
    char plain[100], cipher[27], encrypted[100], decrypted[100];
    char keyword[] = "CIPHER";
    int i, k = 0, used[26] = {0};

    for (i = 0; keyword[i] != '\0'; i++)
    {
        char ch = toupper((unsigned char)keyword[i]);

        if (!used[ch - 'A'])
        {
            cipher[k++] = ch;
            used[ch - 'A'] = 1;
        }
    }

    for (i = 0; i < 26; i++)
    {
        if (!used[i])
        {
            cipher[k++] = 'A' + i;
        }
    }

    cipher[26] = '\0';

    printf("Enter plaintext: ");
    fgets(plain, sizeof(plain), stdin);

    plain[strcspn(plain, "\n")] = '\0';

    for (i = 0; plain[i] != '\0'; i++)
    {
        if (isalpha((unsigned char)plain[i]))
        {
            char ch = toupper((unsigned char)plain[i]);
            char enc = cipher[ch - 'A'];

            if (islower((unsigned char)plain[i]))
                encrypted[i] = tolower((unsigned char)enc);
            else
                encrypted[i] = enc;
        }
        else
        {
            encrypted[i] = plain[i];
        }
    }

    encrypted[i] = '\0';

    for (i = 0; encrypted[i] != '\0'; i++)
    {
        if (isalpha((unsigned char)encrypted[i]))
        {
            char ch = toupper((unsigned char)encrypted[i]);

            for (k = 0; k < 26; k++)
            {
                if (cipher[k] == ch)
                {
                    char dec = 'A' + k;

                    if (islower((unsigned char)encrypted[i]))
                        decrypted[i] = tolower((unsigned char)dec);
                    else
                        decrypted[i] = dec;

                    break;
                }
            }
        }
        else
        {
            decrypted[i] = encrypted[i];
        }
    }

    decrypted[i] = '\0';

    printf("Cipher sequence: %s\n", cipher);
    printf("Original text: %s\n", plain);
    printf("Encrypted text: %s\n", encrypted);
    printf("Decrypted text: %s\n", decrypted);

    return 0;
}
