
#include <stdio.h>
#include <ctype.h>
#include <string.h>

char key[5][5], used[26];

void makeKey(char k[])
{
    int i, n = 0;
    char c;

    for (i = 0; k[i] != '\0'; i++)
    {
        c = toupper((unsigned char)k[i]);

        if (c == 'J')
            c = 'I';

        if (c >= 'A' && c <= 'Z' && !used[c - 'A'])
        {
            key[n / 5][n % 5] = c;
            used[c - 'A'] = 1;
            n++;
        }
    }

    for (c = 'A'; c <= 'Z'; c++)
    {
        if (c != 'J' && !used[c - 'A'])
        {
            key[n / 5][n % 5] = c;
            n++;
        }
    }
}

void find(char c, int *r, int *col)
{
    int i, j;

    if (c == 'J')
        c = 'I';

    for (i = 0; i < 5; i++)
    {
        for (j = 0; j < 5; j++)
        {
            if (key[i][j] == c)
            {
                *r = i;
                *col = j;
                return;
            }
        }
    }
}

void process(char s[], char out[], int decrypt)
{
    int i, r1, c1, r2, c2, shift;
    char a, b;

    shift = decrypt ? 4 : 1;

    for (i = 0; s[i] != '\0'; i += 2)
    {
        find(s[i], &r1, &c1);
        find(s[i + 1], &r2, &c2);

        if (r1 == r2)
        {
            a = key[r1][(c1 + shift) % 5];
            b = key[r2][(c2 + shift) % 5];
        }
        else if (c1 == c2)
        {
            a = key[(r1 + shift) % 5][c1];
            b = key[(r2 + shift) % 5][c2];
        }
        else
        {
            a = key[r1][c2];
            b = key[r2][c1];
        }

        out[i] = a;
        out[i + 1] = b;
    }

    out[i] = '\0';
}

int main()
{
    char k[100], text[500], plain[500];
    char prepared[1000], encrypted[1000], decrypted[1000];
    int i, j = 0, n = 0;

    printf("Enter key: ");
    fgets(k, sizeof(k), stdin);

    makeKey(k);

    printf("Enter plaintext: ");
    fgets(text, sizeof(text), stdin);

    for (i = 0; text[i] != '\0'; i++)
    {
        char c = toupper((unsigned char)text[i]);

        if (c >= 'A' && c <= 'Z')
        {
            if (c == 'J')
                c = 'I';

            plain[j++] = c;
        }
    }

    plain[j] = '\0';

    for (i = 0; i < j; )
    {
        char a = plain[i++];
        prepared[n++] = a;

        if (i == j || plain[i] == a)
            prepared[n++] = (a == 'X') ? 'Q' : 'X';
        else
            prepared[n++] = plain[i++];
    }

    prepared[n] = '\0';

    process(prepared, encrypted, 0);
    process(encrypted, decrypted, 1);

    printf("\nOriginal input: %s", text);
    printf("Encrypted text: %s\n", encrypted);

    printf("Decrypted text: ");

    j = 0;

    for (i = 0; text[i] != '\0'; i++)
    {
        if (isalpha((unsigned char)text[i]))
        {
            char c = decrypted[j++];

            if (text[i] >= 'a' && text[i] <= 'z')
                c = tolower((unsigned char)c);

            printf("%c", c);
        }
        else
        {
            printf("%c", text[i]);
        }
    }

    printf("\n");

    return 0;
}
