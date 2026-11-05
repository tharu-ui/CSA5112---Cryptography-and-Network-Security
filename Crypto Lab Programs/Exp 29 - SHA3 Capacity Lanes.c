
#include <stdio.h>

int main()
{
    int state=1600;
    int rate=1024;
    int capacity;
    int totalLanes=25;
    int rateLanes;
    int capacityLanes;
    int i;

    capacity=state-rate;

    rateLanes=rate/64;
    capacityLanes=capacity/64;

    printf("SHA-3 CAPACITY LANE ANALYSIS\n");

    printf("State size = %d bits\n",state);
    printf("Block size = %d bits\n",rate);
    printf("Capacity = %d bits\n",capacity);

    printf("Total lanes = %d\n",totalLanes);
    printf("Rate lanes = %d\n",rateLanes);
    printf("Capacity lanes = %d\n",capacityLanes);

    printf("\nInitial capacity lanes:\n");

    for(i=0;i<capacityLanes;i++)
        printf("0 ");

    printf("\n");

    printf("\nPermutation is ignored.\n");

    printf("Only rate lanes receive message data.\n");

    printf("Capacity lanes remain zero.\n");

    printf("\nTime required: Never.\n");

    return 0;
}

