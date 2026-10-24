
#include <stdio.h>
#include <string.h>
#include <ctype.h>

char key[5][5];
char alphabet[] = "ABCDEFGHIKLMNOPQRSTUVWXYZ";

void makeKey(char k[]) {
    int used[26] = {0}, n = 0, i, j;
    char temp[100];

    strcpy(temp, k);
    strcat(temp, alphabet);

    for (i = 0; temp[i] != '\0'; i++) {
        char c = toupper(temp[i]);
        if (c == 'J') c = 'I';

        if (c >= 'A' && c <= 'Z' && !used[c-'A']) {
            used[c-'A'] = 1;
            key[n/5][n%5] = c;
            n++;
        }
    }
}

void position(char c, int *r, int *col) {
    int i, j;
    if (c == 'J') c = 'I';

    for (i = 0; i < 5; i++)
        for (j = 0; j < 5; j++)
            if (key[i][j] == c) {
                *r = i;
                *col = j;
                return;
            }
}

void playfair(char text[], int decrypt) {
    int i, r1, c1, r2, c2;
    char a, b;

    for (i = 0; text[i] != '\0'; i++)
        text[i] = toupper(text[i]) == 'J' ? 'I' : toupper(text[i]);

    for (i = 0; text[i] != '\0'; i += 2) {
        a = text[i];
        b = text[i+1];

        position(a, &r1, &c1);
        position(b, &r2, &c2);

        if (r1 == r2) {
            key[r1][c1] = key[r1][c1];
            text[i] = key[r1][(c1 + (decrypt ? 4 : 1)) % 5];
            text[i+1] = key[r2][(c2 + (decrypt ? 4 : 1)) % 5];
        } else if (c1 == c2) {
            text[i] = key[(r1 + (decrypt ? 4 : 1)) % 5][c1];
            text[i+1] = key[(r2 + (decrypt ? 4 : 1)) % 5][c2];
        } else {
            text[i] = key[r1][c2];
            text[i+1] = key[r2][c1];
        }
    }
}

int main() {
    char k[100], cipher[300], original[300], verify[300];

    printf("Enter Playfair key: ");
    fgets(k, sizeof(k), stdin);
    k[strcspn(k, "\n")] = '\0';

    printf("Enter ciphertext (letters in pairs): ");
    fgets(cipher, sizeof(cipher), stdin);

    int n = 0;
    for (int i = 0; cipher[i] != '\0'; i++)
        if (isalpha(cipher[i])) {
            char c = toupper(cipher[i]);
            original[n++] = (c == 'J') ? 'I' : c;
        }
    original[n] = '\0';

    if (n == 0 || n % 2 != 0) {
        printf("Ciphertext must contain an even number of letters.\n");
        return 1;
    }

    makeKey(k);

    playfair(original, 1);
    printf("Decrypted text: %s\n", original);

    strcpy(verify, original);
    playfair(verify, 0);
    printf("Re-encrypted text: %s\n", verify);

    return 0;
}
