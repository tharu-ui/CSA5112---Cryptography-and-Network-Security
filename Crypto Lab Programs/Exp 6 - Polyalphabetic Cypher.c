
#include <stdio.h>
#include <ctype.h>
#include <string.h>

int main()
{
    char text[500], key[100];
    char encrypted[500], decrypted[500];
    int i, j = 0, shift;

    printf("Enter plaintext: ");
    fgets(text, sizeof(text), stdin);

    printf("Enter key: ");
    fgets(key, sizeof(key), stdin);

    key[strcspn(key, "\n")] = '\0';

    if (key[0] == '\0')
    {
        printf("Key cannot be empty.\n");
        return 1;
    }

    for (i = 0; text[i] != '\0'; i++)
    {
        char c = text[i];

        if (isalpha((unsigned char)c))
        {
            shift = toupper((unsigned char)key[j % strlen(key)]) - 'A';

            if (islower((unsigned char)c))
                encrypted[i] = 'a' + (c - 'a' + shift) % 26;
            else
                encrypted[i] = 'A' + (c - 'A' + shift) % 26;

            j++;
        }
        else
        {
            encrypted[i] = c;
        }
    }

    encrypted[i] = '\0';

    j = 0;

    for (i = 0; encrypted[i] != '\0'; i++)
    {
        char c = encrypted[i];

        if (isalpha((unsigned char)c))
        {
            shift = toupper((unsigned char)key[j % strlen(key)]) - 'A';

            if (islower((unsigned char)c))
                decrypted[i] = 'a' + (c - 'a' - shift + 26) % 26;
            else
                decrypted[i] = 'A' + (c - 'A' - shift + 26) % 26;

            j++;
        }
        else
        {
            decrypted[i] = c;
        }
    }

    decrypted[i] = '\0';

    printf("\nOriginal text: %s", text);
    printf("Encrypted text: %s", encrypted);
    printf("Decrypted text: %s", decrypted);

    return 0;
}
