
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
    int e=17,d=2753;
    int p,q,phi;
    int e2=7,d2;

    printf("RSA KEY COMPROMISE\n");

    printf("Original modulus = %d\n",n);
    printf("Leaked private key d = %d\n",d);

    /* Factor the original modulus */
    for(p=2;p*p<=n;p++)
    {
        if(n%p==0)
            break;
    }

    q=n/p;

    phi=(p-1)*(q-1);

    /* Generate a different public exponent */
    while(gcd(e2,phi)!=1)
        e2++;

    /* Calculate the new private exponent */
    for(d2=1;d2<phi;d2++)
    {
        if((e2*d2)%phi==1)
            break;
    }

    printf("Factor p = %d\n",p);
    printf("Factor q = %d\n",q);

    printf("Phi(n) = %d\n",phi);

    printf("\nNew public key e = %d\n",e2);
    printf("New private key d = %d\n",d2);

    printf("\nSame modulus is still being used.\n");
    printf("New key pair is NOT secure.\n");
    printf("A completely new modulus must be generated.\n");

    return 0;
}
