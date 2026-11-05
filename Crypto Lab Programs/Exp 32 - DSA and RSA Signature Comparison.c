
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

long power(long a, long b, long m)
{
    long result = 1;
    while (b > 0)
    {
        if (b % 2)
            result = (result * a) % m;
        a = (a * a) % m;
        b /= 2;
    }
    return result;
}

int inverse(int a, int m)
{
    int i;
    for (i = 1; i < m; i++)
        if ((a * i) % m == 1)
            return i;
    return -1;
}

int hashMessage(char message[])
{
    int h = 0, i;
    for (i = 0; message[i] != '\0'; i++)
        h = (h + message[i]) % 11;
    return h;
}

int main()
{
    char message[100];
    int x = 3, p = 23, q = 11, g = 2;
    int h, k, r, s;
    int n = 143, e = 7, d = 103;
    int rsa1, rsa2;

    srand(time(NULL));

    printf("Enter message: ");
    scanf(" %[^\n]", message);

    h = hashMessage(message);

    printf("\nDSA signatures:\n");

    for (int i = 1; i <= 2; i++)
    {
        do
        {
            k = rand() % 10 + 1;
            r = power(g, k, p) % q;
            s = (inverse(k, q) * (h + x * r)) % q;
        } while (r == 0 || s == 0);

        printf("Signature %d: (%d, %d), k = %d\n",
               i, r, s, k);
    }

    rsa1 = power(h, d, n);
    rsa2 = power(h, d, n);

    printf("\nRSA signatures:\n");
    printf("Signature 1: %d\n", rsa1);
    printf("Signature 2: %d\n", rsa2);

    return 0;
}

