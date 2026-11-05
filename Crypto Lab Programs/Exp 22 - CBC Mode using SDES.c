
#include <stdio.h>

int P10[10]={3,5,2,7,4,10,1,9,8,6};
int P8[8]={6,3,7,4,8,5,10,9};
int IP[8]={2,6,3,1,4,8,5,7};
int IPI[8]={4,1,3,5,7,2,8,6};
int EP[8]={4,1,2,3,2,3,4,1};
int P4[4]={2,4,3,1};

int S0[4][4]={
{1,0,3,2},{3,2,1,0},
{0,2,1,3},{3,1,3,2}};

int S1[4][4]={
{0,1,2,3},{2,0,1,3},
{3,0,1,0},{2,1,0,3}};

int perm(int x,int p[],int n,int bits)
{
    int r=0,i;
    for(i=0;i<n;i++)
        r=(r<<1)|((x>>(bits-p[i]))&1);
    return r;
}

void keys(int key,int *k1,int *k2)
{
    int x=perm(key,P10,10,10);
    int l=(x>>5)&31,r=x&31;

    l=((l<<1)|(l>>4))&31;
    r=((r<<1)|(r>>4))&31;

    *k1=perm((l<<5)|r,P8,8,10);

    l=((l<<2)|(l>>3))&31;
    r=((r<<2)|(r>>3))&31;

    *k2=perm((l<<5)|r,P8,8,10);
}

int sb(int x,int box[4][4])
{
    int row=((x>>3)&1)*2+(x&1);
    int col=(x>>1)&3;
    return box[row][col];
}

int fk(int x,int k)
{
    int l=x>>4,r=x&15;
    int t=perm(r,EP,8,4)^k;
    int s=(sb(t>>4,S0)<<2)|sb(t&15,S1);

    return ((l^perm(s,P4,4,4))<<4)|r;
}

int encrypt(int x,int key)
{
    int k1,k2;
    keys(key,&k1,&k2);

    x=perm(x,IP,8,8);
    x=fk(x,k1);
    x=((x&15)<<4)|(x>>4);
    x=fk(x,k2);

    return perm(x,IPI,8,8);
}

int decrypt(int x,int key)
{
    int k1,k2;
    keys(key,&k1,&k2);

    x=perm(x,IP,8,8);
    x=fk(x,k2);
    x=((x&15)<<4)|(x>>4);
    x=fk(x,k1);

    return perm(x,IPI,8,8);
}

void binary(int x)
{
    int i;
    for(i=7;i>=0;i--)
        printf("%d",(x>>i)&1);
}

int main()
{
    int key=509;
    int iv=170;
    int p[2]={1,35};
    int c[2],d[2];
    int prev,i;

    printf("CBC MODE USING S-DES\n");
    printf("Key: 0111111101\n");
    printf("IV : 10101010\n");

    printf("\nPlaintext: ");
    for(i=0;i<2;i++)
    {
        binary(p[i]);
        printf(" ");
    }

    prev=iv;

    for(i=0;i<2;i++)
    {
        c[i]=encrypt(p[i]^prev,key);
        prev=c[i];
    }

    printf("\nCiphertext: ");
    for(i=0;i<2;i++)
    {
        binary(c[i]);
        printf(" ");
    }

    prev=iv;

    for(i=0;i<2;i++)
    {
        d[i]=decrypt(c[i],key)^prev;
        prev=c[i];
    }

    printf("\nDecrypted: ");
    for(i=0;i<2;i++)
    {
        binary(d[i]);
        printf(" ");
    }

    return 0;
}
