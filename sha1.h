
#include <stdint.h>
#include "CStringUtils.h"

string SHA1(string message);													/*SHA1.c*/
void setSHA1Registers(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);		/*SHA1.c*/
string SHA1Preprocessing(string message);										/*SHA1.c*/
string SHA1Digest(string message);												/*SHA1.c*/
string SHA1HMAC(string key, string message);									/*SHA1.c*/

