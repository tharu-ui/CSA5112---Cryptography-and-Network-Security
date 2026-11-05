
#include <stdio.h>
#include <string.h>

int power(int b,int e,int n)
{
    int result=1;

    while(e>0)
    {
        if(e%2==1)
            result=(result*b)%n;

        b=(b*b)%n;
        e=e/2;
    }

    return result;
}

int main()
{
    int n=3233,e=17;
    int table[26],cipher[100];
    char msg[100];
    int i,j,len;

    printf("Enter uppercase message: ");
    scanf("%99s",msg);

    len=strlen(msg);

    /* Create encryption table */
    for(i=0;i<26;i++)
        table[i]=power(i,e,n);

    /* Encrypt each character */
    for(i=0;i<len;i++)
    {
        int value=msg[i]-'A';
        cipher[i]=power(value,e,n);
    }

    printf("Encrypted message: ");

    for(i=0;i<len;i++)
        printf("%d ",cipher[i]);

    /* Attacker checks all 26 possible characters */
    printf("\nAttacker recovered message: ");

    for(i=0;i<len;i++)
    {
        for(j=0;j<26;j++)
        {
            if(table[j]==cipher[i])
                break;
        }

        if(j<26)
            printf("%c",'A'+j);
    }

    printf("\n");

    printf("Attack: Dictionary or codebook attack.\n");

    return 0;
}
