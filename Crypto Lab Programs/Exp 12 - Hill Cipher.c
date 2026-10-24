
#include <stdio.h>
#include <ctype.h>

int main()
{
    char p[100], c[100], d[100];
    int i, n = 0, a, b;

    printf("Enter plaintext: ");
    scanf(" %[^\n]", p);

    for (i = 0; p[i] != '\0'; i++)
        if (isalpha(p[i]))
            c[n++] = toupper(p[i]);

    if (n % 2 != 0)
        c[n++] = 'X';

    c[n] = '\0';

    for (i = 0; i < n; i += 2)
    {
        a = c[i] - 'A';
        b = c[i + 1] - 'A';

        d[i] = (9 * a + 4 * b) % 26 + 'A';
        d[i + 1] = (5 * a + 7 * b) % 26 + 'A';
    }
    d[n] = '\0';

    printf("Encrypted text: %s\n", d);

    for (i = 0; i < n; i += 2)
    {
        a = d[i] - 'A';
        b = d[i + 1] - 'A';

        c[i] = (5 * a + 12 * b) % 26 + 'A';
        c[i + 1] = (15 * a + 25 * b) % 26 + 'A';
    }
    c[n] = '\0';

    printf("Decrypted text: %s\n", c);

    return 0;
}
