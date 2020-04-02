#include <stdio.h>
#include "IPAConfig.h"
#include "sniffex.h"

int main(int argc, char const *argv[])
{
    printf("IPA Version : %d.%d\n",IPA_VERSION_MAJOR,IPA_VERSION_MINOR);
    char *devName,*Err;
    // getDev(devName,Err);
    capture();
    return 0;
}
