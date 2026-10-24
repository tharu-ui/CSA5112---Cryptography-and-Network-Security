
#include <stdio.h>
#include <ctype.h>

int main()
{
    char c[500];
    char english[] = "ETAOINSHRDLCUMWFGYPBVKJXQZ";
    int freq[26] = {0}, used[26] = {0};
    char map[26];
    int i, j, max, letter;

    printf("Enter ciphertext: ");
    fgets(c, sizeof(c), stdin);

    for (i = 0; c[i] != '\0'; i++)
        if (isalpha(c[i]))
            freq[toupper(c[i]) - 'A']++;

    for (i = 0; i < 26; i++)
    {
        max = -1;
        letter = 0;

        for (j = 0; j < 26; j++)
            if (!used[j] && freq[j] > max)
            {
                max = freq[j];
                letter = j;
            }

        used[letter] = 1;
        map[letter] = english[i];
    }

    printf("Possible plaintext: ");

    for (i = 0; c[i] != '\0'; i++)
    {
        if (isupper(c[i]))
            putchar(map[c[i] - 'A']);
        else if (islower(c[i]))
            putchar(tolower(map[c[i] - 'a']));
        else
            putchar(c[i]);
    }

    return 0;
}
