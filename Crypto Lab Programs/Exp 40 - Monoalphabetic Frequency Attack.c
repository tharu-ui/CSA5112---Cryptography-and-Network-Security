
#include <stdio.h>
#include <string.h>

#define MAX 1000

char english[] = "ETAOINSHRDLCUMWFGYPBVKJXQZ";

int count[26];
int order[26];
char cipher[MAX];
char result[10][MAX];
int score[10];

void decrypt(char text[], int map[], char output[])
{
    int i;
    for (i = 0; text[i] != '\0'; i++)
    {
        if (text[i] >= 'A' && text[i] <= 'Z')
            output[i] = map[text[i] - 'A'];
        else if (text[i] >= 'a' && text[i] <= 'z')
            output[i] = map[text[i] - 'a'] + 32;
        else
            output[i] = text[i];
    }
    output[i] = '\0';
}

int evaluate(char text[])
{
    int s = 0;
    for (int i = 0; text[i + 2] != '\0'; i++)
    {
        if (text[i] == 'T' && text[i+1] == 'H' && text[i+2] == 'E')
            s += 10;
        if (text[i] == 'A' && text[i+1] == 'N' && text[i+2] == 'D')
            s += 8;
        if (text[i] == 'I' && text[i+1] == 'N' && text[i+2] == 'G')
            s += 7;
    }
    return s;
}

int main()
{
    int map[26], i, j, temp;
    char base[MAX], candidate[MAX];

    printf("Enter ciphertext:\n");
    fgets(cipher, MAX, stdin);

    for (i = 0; cipher[i] != '\0'; i++)
    {
        if (cipher[i] >= 'A' && cipher[i] <= 'Z')
            count[cipher[i] - 'A']++;
        else if (cipher[i] >= 'a' && cipher[i] <= 'z')
            count[cipher[i] - 'a']++;
    }

    for (i = 0; i < 26; i++)
        order[i] = i;

    for (i = 0; i < 25; i++)
    {
        for (j = i + 1; j < 26; j++)
        {
            if (count[order[j]] > count[order[i]])
            {
                temp = order[i];
                order[i] = order[j];
                order[j] = temp;
            }
        }
    }

    for (i = 0; i < 26; i++)
        map[order[i]] = english[i];

    decrypt(cipher, map, base);

    for (i = 0; i < 10; i++)
    {
        int a = i % 5;
        int b = (i + 2) % 5;

        int mapCopy[26];
        for (j = 0; j < 26; j++)
            mapCopy[j] = map[j];

        if (i > 0)
        {
            char t = mapCopy[order[a]];
            mapCopy[order[a]] = mapCopy[order[b]];
            mapCopy[order[b]] = t;
        }

        decrypt(cipher, mapCopy, candidate);
        strcpy(result[i], candidate);
        score[i] = evaluate(candidate);
    }

    for (i = 0; i < 10; i++)
    {
        for (j = i + 1; j < 10; j++)
        {
            if (score[j] > score[i])
            {
                temp = score[i];
                score[i] = score[j];
                score[j] = temp;

                char t[MAX];
                strcpy(t, result[i]);
                strcpy(result[i], result[j]);
                strcpy(result[j], t);
            }
        }
    }

    printf("\nTop 10 possible plaintexts:\n");
    for (i = 0; i < 10; i++)
        printf("%d. %s\n", i + 1, result[i]);

    return 0;
}
