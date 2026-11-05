
#include <stdio.h>
#include <string.h>

int gcd(int a, int b)
{
    while (b != 0)
    {
        int t = b;
        b = a % b;
        a = t;
    }
    return a;
}

int inverse(int a)
{
    for (int i = 1; i < 26; i++)
        if ((a * i) % 26 == 1)
            return i;
    return -1;
}

int main()
{
    char text[100], encrypted[100], decrypted[100];
    int a, b, inv, i;

    printf("Enter plaintext: ");
    scanf("%99s", text);

    printf("Enter a and b: ");
    scanf("%d%d", &a, &b);

    a = (a % 26 + 26) % 26;
    b = (b % 26 + 26) % 26;

    if (gcd(a, 26) != 1)
    {
        printf("Invalid key. a must be coprime with 26.\n");
        return 1;
    }

    inv = inverse(a);

    for (i = 0; text[i] != '\0'; i++)
    {
        encrypted[i] =
            ((a * (text[i] - 'A') + b) % 26) + 'A';
    }
    encrypted[i] = '\0';

    for (i = 0; encrypted[i] != '\0'; i++)
    {
        int c = encrypted[i] - 'A';
        decrypted[i] = ((inv * (c - b + 26)) % 26) + 'A';
    }
    decrypted[i] = '\0';

    printf("\nEncrypted text: %s", encrypted);
    printf("\nDecrypted text: %s\n", decrypted);

    return 0;
}

