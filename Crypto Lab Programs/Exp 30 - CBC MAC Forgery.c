
#include <stdio.h>

int encrypt(int x,int key)
{
    return (5*x+key)%256;
}

int main()
{
    int key=13;
    int X=42;
    int T;
    int second;
    int forged;

    printf("CBC MAC FORGERY\n");

    /* MAC of one-block message */
    T=encrypt(X,key);

    printf("Message X = %d\n",X);
    printf("MAC T = %d\n",T);

    /* Attacker creates second block */
    second=X^T;

    printf("Second block = X XOR T = %d\n",second);

    /* MAC of two-block message */
    forged=encrypt(second^encrypt(X,key),key);

    printf("Two-block message = %d %d\n",X,second);
    printf("Forged MAC = %d\n",forged);

    if(forged==T)
        printf("Forgery successful!\n");
    else
        printf("Forgery failed.\n");

    return 0;
}

