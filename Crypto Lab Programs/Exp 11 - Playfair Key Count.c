
#include <stdio.h>

int main()
{
    int i;
    double keys = 1;
    double power = 0;

    for (i = 1; i <= 25; i++)
        keys = keys * i;

    printf("Possible Playfair keys = 25!\n");
    printf("Approximate number of keys = %.0f\n", keys);

    while (keys >= 2)
    {
        keys = keys / 2;
        power++;
    }

    printf("Approximate power of 2 = 2^%.0f\n", power);

    return 0;
}
