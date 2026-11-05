
#include <stdio.h>
#include <stdint.h>

void generateSubkey(unsigned char input[], unsigned char output[],
                    int size, unsigned char constant)
{
    int i;
    unsigned char carry = 0, nextCarry;

    for (i = size - 1; i >= 0; i--)
    {
        nextCarry = input[i] >> 7;
        output[i] = (input[i] << 1) | carry;
        carry = nextCarry;
    }

    if (carry)
        output[size - 1] ^= constant;
}

int main()
{
    unsigned char L[16] = {0};
    unsigned char K1[16], K2[16];
    int size, i;
    unsigned char rb;

    printf("Enter block size (64 or 128): ");
    scanf("%d", &size);

    if (size == 64)
    {
        size = 8;
        rb = 0x1B;
    }
    else if (size == 128)
    {
        size = 16;
        rb = 0x87;
    }
    else
    {
        printf("Invalid block size\n");
        return 1;
    }

    printf("Enter encrypted zero block in hexadecimal:\n");
    for (i = 0; i < size; i++)
        scanf("%2hhx", &L[i]);

    generateSubkey(L, K1, size, rb);
    generateSubkey(K1, K2, size, rb);

    printf("First subkey K1: ");
    for (i = 0; i < size; i++)
        printf("%02X", K1[i]);

    printf("\nSecond subkey K2: ");
    for (i = 0; i < size; i++)
        printf("%02X", K2[i]);

    printf("\n");
    return 0;
}

