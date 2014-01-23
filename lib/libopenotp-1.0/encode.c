/*
 RCDevs OpenOTP Development Library
 Copyright (c) 2010-2013 RCDevs SA, All rights reserved.
 
 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either version 2
 of the License, or (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
  
 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "encode.h"

int hex_encode(char *out, const char *in, int len) {
   int i;

   for (i=0; i<len; i++) {
      if (!sprintf(&out[i*2], "%02X", (unsigned char)in[i])) return 0;
   }

   return i*2;
}

int hex_decode(char *out, const char* in) {
   int len = strlen(in);
   int i, x;

   if (len % 2 != 0) return 0;

   for (i=0; i<len; i+=2) {
      if (!sscanf(&in[i],"%02x",&x)) return 0;
      out[i/2] = x;
   }

   return i/2;
}

int base64_encode(char *dst, const char *src, int len) {
   unsigned int x, y = 0;
   unsigned int n = 3;
   char triple[3];
   char quad[4];
   char base64_table[] = {
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz"
      "0123456789+/"
   };

   for(x = 0; x < len; x += 3) {
      if((len - x) / 3 == 0) n = (len - x) % 3;

      memset(triple, 0, 3);
      memcpy(triple, &src[x], n);

      quad[0] = base64_table[(triple[0] & 0xFC) >> 2];
      quad[1] = base64_table[((triple[0] & 0x03) << 4) | ((triple[1] & 0xF0) >> 4)];
      quad[2] = base64_table[((triple[1] & 0x0F) << 2) | ((triple[2] & 0xC0) >> 6)];
      quad[3] = base64_table[triple[2] & 0x3F];

      if(n < 3) quad[3] = '=';
      if(n < 2) quad[2] = '=';

      memcpy(&dst[y], quad, 4);
      y += 4;
   }

   dst[y] = 0;
   return y;
}

int base64_decode(char *dst, const char *src) {
   int x, y = 0;
   char triple[3];
   char quad[4];
   int len = strlen(src);

   #define decode(c) if(c >= 'A' && c <= 'Z') c  = c - 'A'; \
   else if(c >= 'a' && c <= 'z') c  = c - 'a' + 26; \
   else if(c >= '0' && c <= '9') c  = c - '0' + 52; \
   else if(c == '+')             c  = 62; \
   else if(c == '/')             c  = 63; \
   else                          c  = 0; \
   
   for(x = 0; x < len; x += 4) {
      memset(quad, 0, 4);
      memcpy(quad, &src[x], 4 - (len - x) % 4);

      decode(quad[0]);
      decode(quad[1]);
      decode(quad[2]);
      decode(quad[3]);

      triple[0] = (quad[0] << 2) | quad[1] >> 4;
      triple[1] = ((quad[1] << 4) & 0xF0) | quad[2] >> 2;
      triple[2] = ((quad[2] << 6) & 0xC0) | quad[3];

      memcpy(&dst[y], triple, 3);
      y += 3;
   }
   if (src[len-2] == '=') y--;
   if (src[len-1] == '=') y--;
   return y;
}
