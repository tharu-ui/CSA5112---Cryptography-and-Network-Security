
#include <stdio.h>
#include <string.h>

struct Mapping
{
    const char *symbol;
    char letter;
};

struct Mapping key[] =
{
    {"‡", 'o'}, {"†", 'd'}, {"¶", 'v'}, {"—", 'c'},
    {"5", 'a'}, {"3", 'g'}, {"0", 'l'}, {")", 's'},
    {"6", 'i'}, {"*", 'n'}, {";", 't'}, {"4", 'h'},
    {"8", 'e'}, {"2", 'b'}, {".", 'p'}, {"1", 'f'},
    {"(", 'r'}, {":", 'y'}, {"9", 'm'}, {"?", 'u'},
    {"7", 'w'}, {"[", 'j'}, {"]", 'c'}
};

int main()
{
    char cipher[] =
    "53‡‡†305))6*;4826)4‡.)4‡);80"
    "6*;48†8¶60))85;1‡(;:‡*8†83(88)"
    "5*†;46(;88*96*?;8)*‡(;485);5*†"
    "2:*‡(;4956*2(5*—4)8¶8*;40692"
    "85);)6†8)4‡‡;1(‡9;48081;8:8‡1"
    ";48†85;4)485†528806*81(‡9;48"
    ";(88;4(‡?34;48)4‡;161;:188;‡?;";

    int i = 0, j;
    int count = sizeof(key) / sizeof(key[0]);

    printf("Decrypted Plaintext:\n");

    while (cipher[i] != '\0')
    {
        int found = 0;

        for (j = 0; j < count; j++)
        {
            int len = strlen(key[j].symbol);

            if (strncmp(cipher + i, key[j].symbol, len) == 0)
            {
                printf("%c", key[j].letter);
                i += len;
                found = 1;
                break;
            }
        }

        if (!found)
            i++;
    }

    printf("\n");

    return 0;
}
