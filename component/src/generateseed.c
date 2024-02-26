#include "mxc_device.h" 
#include "trng.h"

int wc_GenerateSeed(OS_Seed* os, byte* output, word32 sz)
{
    MXC_TRNG_Init();
    while (sz > 0) {
        if (sz >= sizeof(uint32_t)) {
            uint32_t rnd32 = MXC_TRNG_RandomInt();
            memcpy(output, &rnd32, sizeof(rnd32));
            output += sizeof(rnd32);
            sz -= sizeof(rnd32);
        } else {
            byte rnd8;
            MXC_TRNG_Random(&rnd8, 1);
            *output = rnd8;
            ++output;
            --sz;
        }
    }
    MXC_TRNG_Shutdown();

    return 0;
}