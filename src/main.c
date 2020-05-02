#include <stdio.h>
#include <time.h>
#include "IPAConfig.h"
#include "sniffex.h"
#include "correlation.h"
#include "entrophy.h"


int main(int argc, char const *argv[])
{
    printf("IPA Version : %d.%d\n",IPA_VERSION_MAJOR,IPA_VERSION_MINOR);
    
    // correlation();
    
    entrophy_test();
    return 0;
}
