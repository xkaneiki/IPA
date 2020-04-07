#include <stdio.h>
#include <time.h>
#include "IPAConfig.h"
#include "sniffex.h"
#include "correlation.h"


int main(int argc, char const *argv[])
{
    printf("IPA Version : %d.%d\n",IPA_VERSION_MAJOR,IPA_VERSION_MINOR);
    // char *devName,*Err;
    // get_dev(devName,Err);

    // clock_t start=clock(),end;    
    // int t=20;
    // while(t--)capture();
    // end=clock();
    // double wtime=(double)(end-start)/CLOCKS_PER_SEC*1000;
    // printf("%lf ms\n",wtime);
    correlation();
    
    return 0;
}
