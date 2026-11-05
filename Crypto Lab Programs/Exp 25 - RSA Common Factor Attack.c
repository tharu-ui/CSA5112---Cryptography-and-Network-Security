
#include <stdio.h>

int gcd(int a,int b)
{
    int t;

    while(b!=0)
    {
        t=b;
        b=a%b;
        a=t;
    }

    return a;
}

int main()
{
    int n=3233;
    int block=122;
    int g;

    printf("RSA COMMON FACTOR ATTACK\n");

    printf("Modulus n = %d\n",n);
    printf("Plaintext block = %d\n",block);

    g=gcd(n,block);

    printf("GCD = %d\n",g);

    if(g>1 && g<n)
    {
        printf("First factor = %d\n",g);
        printf("Second factor = %d\n",n/g);

        printf("RSA modulus is factored.\n");
        printf("Private key can now be calculated.\n");
    }
    else
    {
        printf("No common factor found.\n");
    }

    return 0;
}
