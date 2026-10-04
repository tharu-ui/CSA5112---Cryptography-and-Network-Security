#include <stdio.h>
#include <string.h>

char matrix[5][5];

void createMatrix(char key[])
{
    int used[26] = {0};
    int i, j, k = 0;
    char ch;

    used['J' - 'A'] = 1;

    for (i = 0; key[i] != '\0'; i++)
    {
        ch = key[i];

        if (ch >= 'a' && ch <= 'z')
            ch = ch - 32;

        if (ch == 'J')
            ch = 'I';

        if (ch >= 'A' && ch <= 'Z' && used[ch - 'A'] == 0)
        {
            matrix[k / 5][k % 5] = ch;
            used[ch - 'A'] = 1;
            k++;
        }
    }

    for (i = 0; i < 26; i++)
    {
        if (used[i] == 0)
        {
            matrix[k / 5][k % 5] = 'A' + i;
            used[i] = 1;
            k++;
        }
    }
}

void findPosition(char ch, int *row, int *col)
{
    int i, j;

    if (ch == 'J')
        ch = 'I';

    for (i = 0; i < 5; i++)
    {
        for (j = 0; j < 5; j++)
        {
            if (matrix[i][j] == ch)
            {
                *row = i;
                *col = j;
                return;
            }
        }
    }
}

void encrypt(char text[], char result[])
{
    int i, r1, c1, r2, c2;

    for (i = 0; text[i] != '\0'; i += 2)
    {
        findPosition(text[i], &r1, &c1);
        findPosition(text[i + 1], &r2, &c2);

        if (r1 == r2)
        {
            result[i] = matrix[r1][(c1 + 1) % 5];
            result[i + 1] = matrix[r2][(c2 + 1) % 5];
        }
        else if (c1 == c2)
        {
            result[i] = matrix[(r1 + 1) % 5][c1];
            result[i + 1] = matrix[(r2 + 1) % 5][c2];
        }
        else
        {
            result[i] = matrix[r1][c2];
            result[i + 1] = matrix[r2][c1];
        }
    }

    result[i] = '\0';
}

void decrypt(char text[], char result[])
{
    int i, r1, c1, r2, c2;

    for (i = 0; text[i] != '\0'; i += 2)
    {
        findPosition(text[i], &r1, &c1);
        findPosition(text[i + 1], &r2, &c2);

        if (r1 == r2)
        {
            result[i] = matrix[r1][(c1 + 4) % 5];
            result[i + 1] = matrix[r2][(c2 + 4) % 5];
        }
        else if (c1 == c2)
        {
            result[i] = matrix[(r1 + 4) % 5][c1];
            result[i + 1] = matrix[(r2 + 4) % 5][c2];
        }
        else
        {
            result[i] = matrix[r1][c2];
            result[i + 1] = matrix[r2][c1];
        }
    }

    result[i] = '\0';
}

int main()
{
    char key[50], text[100], prepared[100];
    char encrypted[100], decrypted[100];
    int i, j = 0;

    printf("Enter key: ");
    scanf("%s", key);

    printf("Enter text: ");
    scanf("%s", text);

    createMatrix(key);

    /* Prepare plaintext */
    for (i = 0; text[i] != '\0'; i++)
    {
        if (text[i] >= 'a' && text[i] <= 'z')
            text[i] = text[i] - 32;

        if (text[i] == 'J')
            text[i] = 'I';
    }

    for (i = 0; text[i] != '\0'; i++)
    {
        prepared[j++] = text[i];

        if (text[i + 1] != '\0' && text[i] == text[i + 1])
            prepared[j++] = 'X';
    }

    if (j % 2 != 0)
        prepared[j++] = 'X';

    prepared[j] = '\0';

    encrypt(prepared, encrypted);

    printf("Encrypted text: %s\n", encrypted);

    decrypt(encrypted, decrypted);

    printf("Decrypted text: %s\n", decrypted);

    return 0;
}