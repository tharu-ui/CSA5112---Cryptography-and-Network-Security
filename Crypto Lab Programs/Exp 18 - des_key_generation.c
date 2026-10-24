
#include <stdio.h>
#include <string.h>

int PC1[56] = {
57,49,41,33,25,17,9,1,58,50,42,34,26,18,
10,2,59,51,43,35,27,19,11,3,60,52,44,36,
63,55,47,39,31,23,15,7,62,54,46,38,30,22,
14,6,61,53,45,37,29,21,13,5,28,20,12,4
};

int PC2[48] = {
14,17,11,24,1,5,3,28,15,6,21,10,
23,19,12,4,26,8,16,7,27,20,13,2,
41,52,31,37,47,55,30,40,51,45,33,48,
44,49,39,56,34,53,46,42,50,36,29,32
};

int shift[16] = {
1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1
};

void rotate(int a[], int n)
{
    int i, t;

    for (i = 0; i < n; i++)
    {
        t = a[0];

        for (int j = 0; j < 27; j++)
            a[j] = a[j + 1];

        a[27] = t;
    }
}

int main()
{
    char key[17];
    int bits[64], selected[56];
    int c[28], d[28], combined[56];
    int i, j, value;

    printf("Enter 16 hexadecimal key characters:\n");
    scanf("%16s", key);

    if (strlen(key) != 16)
    {
        printf("Invalid key length\n");
        return 0;
    }

    for (i = 0; i < 16; i++)
    {
        if (key[i] >= '0' && key[i] <= '9')
            value = key[i] - '0';
        else if (key[i] >= 'A' && key[i] <= 'F')
            value = key[i] - 'A' + 10;
        else if (key[i] >= 'a' && key[i] <= 'f')
            value = key[i] - 'a' + 10;
        else
        {
            printf("Invalid hexadecimal key\n");
            return 0;
        }

        for (j = 0; j < 4; j++)
            bits[i * 4 + j] = (value >> (3 - j)) & 1;
    }

    for (i = 0; i < 56; i++)
        selected[i] = bits[PC1[i] - 1];

    for (i = 0; i < 28; i++)
    {
        c[i] = selected[i];
        d[i] = selected[i + 28];
    }

    for (i = 0; i < 16; i++)
    {
        rotate(c, shift[i]);
        rotate(d, shift[i]);

        for (j = 0; j < 28; j++)
        {
            combined[j] = c[j];
            combined[j + 28] = d[j];
        }

        printf("K%d: ", i + 1);

        for (j = 0; j < 48; j += 4)
        {
            int v = 0;

            for (int k = 0; k < 4; k++)
                v = v * 2 + combined[PC2[j + k] - 1];

            printf("%X", v);
        }

        printf("\n");
    }

    return 0;
}

