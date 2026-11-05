
#include <stdio.h>

int inverse(int e,int phi)
{
    int t=0,nt=1;
    int r=phi,nr=e;
    int q,temp;

    while(nr!=0)
    {
        q=r/nr;

        temp=t-q*nt;
        t=nt;
        nt=temp;

        temp=r-q*nr;
        r=nr;
        nr=temp;
    }

    if(t<0)
        t+=phi;

    return t;
}

int main()
{
    int n=3599,e=31;
    int p,q,phi,d;

    for(p=2;p*p<=n;p++)
    {
        if(n%p==0)
            break;
    }

    q=n/p;

    phi=(p-1)*(q-1);

    d=inverse(e,phi);

    printf("RSA KEY GENERATION\n");
    printf("Public key e = %d\n",e);
    printf("Modulus n = %d\n",n);

    printf("p = %d\n",p);
    printf("q = %d\n",q);

    printf("Phi(n) = %d\n",phi);
    printf("Private key d = %d\n",d);

    printf("\nPublic Key = (%d,%d)",e,n);
    printf("\nPrivate Key = (%d,%d)",d,n);

    return 0;
}

