
#include <stdio.h>
#include <ctype.h>

int main()
{
    char c1[10], c2[10];

    printf("Chosen plaintext 1: BA\n");
    printf("Enter its 2-letter ciphertext: ");
    scanf("%s", c1);

    printf("Chosen plaintext 2: AB\n");
    printf("Enter its 2-letter ciphertext: ");
    scanf("%s", c2);

    printf("\nRecovered Hill key matrix:\n");
    printf("| %d %d |\n", (toupper(c1[0])-'A'), (toupper(c2[0])-'A'));
    printf("| %d %d |\n", (toupper(c1[1])-'A'), (toupper(c2[1])-'A'));

    return 0;
}
