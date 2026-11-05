
#include <stdio.h>
#include <string.h>

#define MAX 1000

char cipher[MAX];

char *frequency = "ETAOINSHRDLCUMWFGYPBVKJXQZ";

double english[26] = {
    8.12, 1.49, 2.71, 4.32, 12.02, 2.30,
    2.03, 5.92, 7.31, 0.10, 0.69, 3.98,
    2.61, 6.95, 7.68, 1.82, 0.11, 6.02,
    6.28, 9.10, 2.88, 1.11, 2.09, 0.17,
    2.11, 0.07
};

void decrypt(int key, char output[])
{
    int i;
    for (i = 0; cipher[i] != '\0'; i++)
    {
        if (cipher[i] >= 'A' && cipher[i] <= 'Z')
            output[i] = (cipher[i] - 'A' - key + 26) % 26 + 'A';
        else if (cipher[i] >= 'a' && cipher[i] <= 'z')
            output[i] = (cipher[i] - 'a' - key + 26) % 26 + 'a';
        else
            output[i] = cipher[i];
    }
    output[i] = '\0';
}

double calculateScore(char text[])
{
    int count[26] = {0};
    int total = 0;
    double score = 0;

    for (int i = 0; text[i] != '\0'; i++)
    {
        if (text[i] >= 'A' && text[i] <= 'Z')
        {
            count[text[i] - 'A']++;
            total++;
        }
        else if (text[i] >= 'a' && text[i] <= 'z')
        {
            count[text[i] - 'a']++;
            total++;
        }
    }

    if (total == 0)
        return 999999;

    for (int i = 0; i < 26; i++)
    {
        double expected = english[i] * total / 100.0;
        double difference = count[i] - expected;

        score += difference * difference / (expected + 0.01);
    }

    return score;
}

int main()
{
    char text[26][MAX];
    double scores[26], tempScore;
    char temp[MAX];

    printf("Enter ciphertext:\n");
    fgets(cipher, MAX, stdin);

    for (int i = 0; i < 26; i++)
    {
        decrypt(i, text[i]);
        scores[i] = calculateScore(text[i]);
    }

    for (int i = 0; i < 26; i++)
    {
        for (int j = i + 1; j < 26; j++)
        {
            if (scores[j] < scores[i])
            {
                tempScore = scores[i];
                scores[i] = scores[j];
                scores[j] = tempScore;

                strcpy(temp, text[i]);
                strcpy(text[i], text[j]);
                strcpy(text[j], temp);
            }
        }
    }

    printf("\nTop 10 possible plaintexts:\n");

    for (int i = 0; i < 10; i++)
        printf("%d. %s\n", i + 1, text[i]);

    return 0;
}

