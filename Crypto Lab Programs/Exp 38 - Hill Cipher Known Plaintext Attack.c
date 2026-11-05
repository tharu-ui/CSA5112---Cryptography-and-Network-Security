
#include <stdio.h>
#include <string.h>

int inverse(int n)
{
    for (int i = 1; i < 26; i++)
        if ((n * i) % 26 == 1)
            return i;
    return -1;
}

int mod26(int n)
{
    return (n % 26 + 26) % 26;
}

int main()
{
    char p[5], c[5];
    int P[2][2], C[2][2], K[2][2];
    int det, invDet;

    printf("Enter 4 plaintext letters: ");
    scanf("%4s", p);

    printf("Enter corresponding 4 ciphertext letters: ");
    scanf("%4s", c);

    for (int i = 0; i < 4; i++)
    {
        if (p[i] < 'A' || p[i] > 'Z' ||
            c[i] < 'A' || c[i] > 'Z')
        {
            printf("Use uppercase letters only.\n");
            return 1;
        }
    }

    P[0][0] = p[0] - 'A';
    P[1][0] = p[1] - 'A';
    P[0][1] = p[2] - 'A';
    P[1][1] = p[3] - 'A';

    C[0][0] = c[0] - 'A';
    C[1][0] = c[1] - 'A';
    C[0][1] = c[2] - 'A';
    C[1][1] = c[3] - 'A';

    det = mod26(P[0][0] * P[1][1] -
                P[0][1] * P[1][0]);

    invDet = inverse(det);

    if (invDet == -1)
    {
        printf("Plaintext matrix has no inverse modulo 26.\n");
        return 1;
    }

    int Pinv[2][2];

    Pinv[0][0] = mod26(P[1][1] * invDet);
    Pinv[0][1] = mod26(-P[0][1] * invDet);
    Pinv[1][0] = mod26(-P[1][0] * invDet);
    Pinv[1][1] = mod26(P[0][0] * invDet);

    for (int i = 0; i < 2; i++)
    {
        for (int j = 0; j < 2; j++)
        {
            K[i][j] = 0;
            for (int k = 0; k < 2; k++)
                K[i][j] += C[i][k] * Pinv[k][j];

            K[i][j] = mod26(K[i][j]);
        }
    }

    printf("\nRecovered Hill Key Matrix:\n");
    for (int i = 0; i < 2; i++)
    {
        for (int j = 0; j < 2; j++)
            printf("%d ", K[i][j]);
        printf("\n");
    }

    return 0;
}
