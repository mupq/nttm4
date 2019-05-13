#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include "poly.h"

void cbd(poly *r, const unsigned char *buf);
void cbd_add(poly *r, const unsigned char *buf);

#endif
