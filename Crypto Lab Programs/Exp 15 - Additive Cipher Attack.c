
#include <stdio.h>
#include <ctype.h>

int main()
{
    char c[500];
    int top, shift, i;

    printf("Enter ciphertext: ");
    fgets(c, sizeof(c), stdin);

    printf("How many possible plaintexts? ");
    scanf("%d", &top);

    if (top > 26) top = 26;

    for (shift = 0; shift < top; shift++)
    {
        printf("Shift %d: ", shift);

        for (i = 0; c[i] != '\0'; i++)
        {
            if (isupper(c[i]))
                putchar((c[i] - 'A' - shift + 26) % 26 + 'A');
            else if (islower(c[i]))
                putchar((c[i] - 'a' - shift + 26) % 26 + 'a');
            else
                putchar(c[i]);
        }
        printf("\n");
    }

    return 0;
}
