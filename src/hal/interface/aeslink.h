
#ifndef __AES_H__
#define __AES_H__

#include <stdint.h>
#include <stdbool.h>
#include "syslink.h"

void aeslinkInit();
bool aeslinkTest();
void aesEnableTunnel();


struct crtpLinkOperations aeslinkGetLink();
#endif //__AES_H__
