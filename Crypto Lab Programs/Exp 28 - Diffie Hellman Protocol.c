
#include <stdio.h>

int power(int b,int e,int q)
{
    int result=1;

    while(e>0)
    {
        if(e%2==1)
            result=(result*b)%q;

        b=(b*b)%q;
        e=e/2;
    }

    return result;
}

int main()
{
    int q=23,a=5;
    int xa=6,xb=15;
    int A,B,key;

    printf("DIFFIE HELLMAN PROTOCOL\n");

    printf("Public prime q = %d\n",q);
    printf("Public number a = %d\n",a);

    /* Incorrect method: x^a mod q */
    A=power(xa,a,q);
    B=power(xb,a,q);

    printf("\nUsing x^a mod q:\n");

    printf("Alice sends = %d\n",A);
    printf("Bob sends = %d\n",B);

    key=(A*B)%q;

    printf("Publicly calculated key = %d\n",key);
    printf("Eve can also calculate this key.\n");

    /* Standard Diffie-Hellman */
    {
        int g=5;
        int alice,bob;
        int keyA,keyB;

        alice=power(g,xa,q);
        bob=power(g,xb,q);

        keyA=power(bob,xa,q);
        keyB=power(alice,xb,q);

        printf("\nStandard Diffie-Hellman:\n");

        printf("Alice sends = %d\n",alice);
        printf("Bob sends = %d\n",bob);

        printf("Alice shared key = %d\n",keyA);
        printf("Bob shared key = %d\n",keyB);

        if(keyA==keyB)
            printf("Shared key established successfully.\n");
    }

    return 0;
}

