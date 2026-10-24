
#include <stdio.h>
#include <ctype.h>

int main()
{
    char p[100], c[100], d[100], target[100];
    int key[100], newkey[100];
    int i, n = 0, j = 0;

    printf("Enter plaintext: ");
    fgets(p, sizeof(p), stdin);

    printf("Enter key numbers (13 numbers):\n");
    for (i = 0; i < 13; i++)
        scanf("%d", &key[i]);

    for (i = 0; p[i] != '\0'; i++)
        if (isalpha(p[i]))
            c[n++] = p[i];

    for (i = 0; i < n; i++)
    {
        int base = islower(c[i]) ? 'a' : 'A';
        c[i] = (c[i] - base + key[i]) % 26 + base;
    }
    c[n] = '\0';

    printf("Ciphertext: %s\n", c);

    for (i = 0; i < n; i++)
    {
        int base = islower(c[i]) ? 'a' : 'A';
        d[i] = (c[i] - base - key[i] + 26) % 26 + base;
    }
    d[n] = '\0';

    printf("Decrypted text: %s\n", d);

    printf("Enter target plaintext (13 letters): ");
    scanf("%s", target);

    for (i = 0; i < n; i++)
    {
        int x = tolower(c[i]) - 'a';
        int y = tolower(target[i]) - 'a';
        newkey[i] = (x - y + 26) % 26;
    }

    printf("New key stream: ");
    for (i = 0; i < n; i++)
        printf("%d ", newkey[i]);

    printf("\n");
    return 0;
}
