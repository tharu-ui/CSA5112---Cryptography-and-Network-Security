#include <stdio.h>
#include <ctype.h>
#include <string.h>

int main()
{
    char plain[100], cipher[27];
    char keyword[] = "CIPHER";
    int i, j, k = 0, used[26] = {0};

    for (i = 0; keyword[i] != '\0'; i++)
    {
        char ch = toupper(keyword[i]);

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

    for (i = 0; plain[i] != '\0'; i++)
    {
        if (isalpha(plain[i]))
        {
            char ch = toupper(plain[i]);
            plain[i] = cipher[ch - 'A'];
        }
    }

    printf("Cipher sequence: %s\n", cipher);
    printf("Encrypted text: %s", plain);

    return 0;
}
