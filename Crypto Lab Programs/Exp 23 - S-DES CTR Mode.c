
#include <stdio.h>
#include <string.h>

int P10[] = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
int P8[] = {6, 3, 7, 4, 8, 5, 10, 9};
int IP[] = {2, 6, 3, 1, 4, 8, 5, 7};
int IP_INV[] = {4, 1, 3, 5, 7, 2, 8, 6};
int EP[] = {4, 1, 2, 3, 2, 3, 4, 1};
int P4[] = {2, 4, 3, 1};

int S0[4][4] = {
    {1, 0, 3, 2},
    {3, 2, 1, 0},
    {0, 2, 1, 3},
    {3, 1, 3, 2}
};

int S1[4][4] = {
    {0, 1, 2, 3},
    {2, 0, 1, 3},
    {3, 0, 1, 0},
    {2, 1, 0, 3}
};

int permute(int n, int *p, int size, int bits)
{
    int result = 0, i;

    for (i = 0; i < size; i++)
        result = (result << 1) | ((n >> (bits - p[i])) & 1);

    return result;
}

int leftShift(int n, int shifts)
{
    return ((n << shifts) | (n >> (5 - shifts))) & 31;
}

void generateKeys(int key, int *k1, int *k2)
{
    int p = permute(key, P10, 10, 10);
    int l = (p >> 5) & 31;
    int r = p & 31;

    l = leftShift(l, 1);
    r = leftShift(r, 1);

    *k1 = permute((l << 5) | r, P8, 8, 10);

    l = leftShift(l, 2);
    r = leftShift(r, 2);

    *k2 = permute((l << 5) | r, P8, 8, 10);
}

int sbox(int value, int box[4][4])
{
    int row = ((value & 8) >> 2) | (value & 1);
    int col = (value >> 1) & 3;

    return box[row][col];
}

int fk(int value, int key)
{
    int l = value >> 4;
    int r = value & 15;

    int temp = permute(r, EP, 8, 4) ^ key;

    int s = (sbox(temp >> 4, S0) << 2)
          | sbox(temp & 15, S1);

    return ((l ^ permute(s, P4, 4, 4)) << 4) | r;
}

int swap(int n)
{
    return ((n & 15) << 4) | (n >> 4);
}

int encrypt(int plain, int key)
{
    int k1, k2;

    generateKeys(key, &k1, &k2);

    int x = permute(plain, IP, 8, 8);
    x = fk(x, k1);
    x = swap(x);
    x = fk(x, k2);

    return permute(x, IP_INV, 8, 8);
}

int binaryToDecimal(char *s)
{
    int n = 0, i;

    for (i = 0; i < 8; i++)
        n = n * 2 + (s[i] - '0');

    return n;
}

void decimalToBinary(int n, char *s)
{
    int i;

    for (i = 7; i >= 0; i--)
    {
        s[i] = (n % 2) + '0';
        n /= 2;
    }

    s[8] = '\0';
}

int main()
{
    char plain[100], keyStr[11], cipher[100], decrypted[100];
    int key = 0, counter = 0, i, j;
    int p, stream, c;

    printf("Enter 10-bit binary key: ");
    scanf("%10s", keyStr);

    if (strlen(keyStr) != 10)
    {
        printf("Invalid key!\n");
        return 1;
    }

    for (i = 0; i < 10; i++)
    {
        if (keyStr[i] != '0' && keyStr[i] != '1')
        {
            printf("Invalid key!\n");
            return 1;
        }

        key = key * 2 + (keyStr[i] - '0');
    }

    printf("Enter 24-bit binary plaintext: ");
    scanf("%99s", plain);

    if (strlen(plain) != 24)
    {
        printf("Plaintext must contain 24 bits!\n");
        return 1;
    }

    for (i = 0; i < 24; i++)
    {
        if (plain[i] != '0' && plain[i] != '1')
        {
            printf("Invalid plaintext!\n");
            return 1;
        }
    }

    for (i = 0; i < 24; i += 8)
    {
        char block[9];

        strncpy(block, plain + i, 8);
        block[8] = '\0';

        p = binaryToDecimal(block);

        stream = encrypt(counter, key);

        c = p ^ stream;

        decimalToBinary(c, cipher + i);

        decrypted[i] = '\0';

        counter++;
    }

    cipher[24] = '\0';

    printf("\nEncrypted ciphertext: %s\n", cipher);

    counter = 0;

    for (i = 0; i < 24; i += 8)
    {
        char block[9];

        strncpy(block, cipher + i, 8);
        block[8] = '\0';

        c = binaryToDecimal(block);

        stream = encrypt(counter, key);

        p = c ^ stream;

        decimalToBinary(p, decrypted + i);

        counter++;
    }

    decrypted[24] = '\0';

    printf("Decrypted plaintext:  %s\n", decrypted);

    return 0;
}
