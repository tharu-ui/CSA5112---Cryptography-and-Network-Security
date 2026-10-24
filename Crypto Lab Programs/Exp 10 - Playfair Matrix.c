
#include <stdio.h>
#include <string.h>
#include <ctype.h>

char key[5][5] = {
    {'M','F','H','I','K'},
    {'U','N','O','P','Q'},
    {'Z','V','W','X','Y'},
    {'E','L','A','R','G'},
    {'D','S','T','B','C'}
};

void pos(char c, int *r, int *col) {
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

void playfair(char s[], int dec) {
    int i, r1, c1, r2, c2;
    for (i = 0; s[i] != '\0'; i += 2) {
        pos(s[i], &r1, &c1);
        pos(s[i+1], &r2, &c2);

        if (r1 == r2) {
            s[i] = key[r1][(c1 + (dec ? 4 : 1)) % 5];
            s[i+1] = key[r2][(c2 + (dec ? 4 : 1)) % 5];
        } else if (c1 == c2) {
            s[i] = key[(r1 + (dec ? 4 : 1)) % 5][c1];
            s[i+1] = key[(r2 + (dec ? 4 : 1)) % 5][c2];
        } else {
            s[i] = key[r1][c2];
            s[i+1] = key[r2][c1];
        }
    }
}

int main() {
    char msg[300], s[300], cipher[300];
    int i, n = 0;

    printf("Enter plaintext: ");
    fgets(msg, sizeof(msg), stdin);

    for (i = 0; msg[i] != '\0'; i++) {
        if (isalpha(msg[i])) {
            char c = toupper(msg[i]);
            if (c == 'J') c = 'I';
            s[n++] = c;
        }
    }
    s[n] = '\0';

    for (i = 0; i < n - 1; i += 2) {
        if (s[i] == s[i+1]) {
            memmove(&s[i+2], &s[i+1], strlen(&s[i+1]) + 1);
            s[i+1] = 'X';
            n++;
        }
    }

    if (n % 2 != 0) s[n++] = 'X';
    s[n] = '\0';

    strcpy(cipher, s);
    playfair(cipher, 0);
    printf("Encrypted text: %s\n", cipher);

    playfair(cipher, 1);
    printf("Decrypted text: %s\n", cipher);

    return 0;
}
