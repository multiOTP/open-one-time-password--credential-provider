#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tiqr.h>
#ifndef WIN32
  #include <dlfcn.h>
#endif

#define ANSI_RESET        "\x1B[0m"
#define ANSI_BLACKONGREY  "\x1B[30;47;27m"
#define ANSI_WHITE        "\x1B[27m"
#define ANSI_BLACK        "\x1B[7m"
#define UTF8_BOTH         "\xE2\x96\x88"
#define UTF8_TOPHALF      "\xE2\x96\x80"
#define UTF8_BOTTOMHALF   "\xE2\x96\x84"

void usage(char *prog) {
   printf("Usage: %s <TIQR_URL> <SESSION>\n", prog); 
   fflush(stdout);
   exit(1);
}

typedef struct {
   int version;
   int width;
   unsigned char *data;
} QRcode;

int display_qrcode(const char *url, int unicode) {
   void *qrencode;
   int i, x, y;

#ifndef WIN32
   qrencode = dlopen("libqrencode.so.3", RTLD_NOW | RTLD_LOCAL);
   if (!qrencode) qrencode = dlopen("/usr/lib/libqrencode.so.3", RTLD_NOW | RTLD_LOCAL);
   if (!qrencode) qrencode = dlopen("/usr/lib64/libqrencode.so.3", RTLD_NOW | RTLD_LOCAL);
   if (!qrencode) qrencode = dlopen("/usr/local/lib/libqrencode.so.3", RTLD_NOW | RTLD_LOCAL);
   if (!qrencode) qrencode = dlopen("/usr/local/lib64/libqrencode.so.3", RTLD_NOW | RTLD_LOCAL);
   if (!qrencode) return 0;
   
   QRcode *(*QRcode_encodeString8bit)(const char *, int, int) = (QRcode *(*)(const char *, int, int))dlsym(qrencode, "QRcode_encodeString8bit");
   void (*QRcode_free)(QRcode *qrcode) = (void (*)(QRcode *))dlsym(qrencode, "QRcode_free");
   if (!QRcode_encodeString8bit || !QRcode_free) return 0;
   
   QRcode *qrcode = QRcode_encodeString8bit(url, 0, 1);
   char *ptr = (char *)qrcode->data;

   printf("\n");
   if (!unicode) {
      for (i = 0; i < 2; ++i) {
	 printf(ANSI_BLACKONGREY);
	 for (x = 0; x < qrcode->width + 4; ++x) printf("  ");
	 puts(ANSI_RESET);
      }
      for (y = 0; y < qrcode->width; ++y) {
	 printf(ANSI_BLACKONGREY"    ");
	 int isBlack = 0;
	 for (x = 0; x < qrcode->width; ++x) {
	    if (*ptr++ & 1) {
	       if (!isBlack) printf(ANSI_BLACK);
	       isBlack = 1;
	    } else {
	       if (isBlack) printf(ANSI_WHITE);
	       isBlack = 0;
	    }
	    printf("  ");
	 }
	 if (isBlack) printf(ANSI_WHITE);
	 puts("    "ANSI_RESET);
      }
      for (i = 0; i < 2; ++i) {
	 printf(ANSI_BLACKONGREY);
	 for (x = 0; x < qrcode->width + 4; ++x) printf("  ");
	 puts(ANSI_RESET);
      }
   } else {
      printf(ANSI_BLACKONGREY);
      for (i = 0; i < qrcode->width + 4; ++i) printf(" ");
      puts(ANSI_RESET);
      for (y = 0; y < qrcode->width; y += 2) {
	 printf(ANSI_BLACKONGREY"  ");
	 for (x = 0; x < qrcode->width; ++x) {
	    int top = qrcode->data[y*qrcode->width + x] & 1;
	    int bottom = 0;
	    if (y+1 < qrcode->width) bottom = qrcode->data[(y+1)*qrcode->width + x] & 1;
	    if (top) {
	       if (bottom) printf(UTF8_BOTH);
	       else printf(UTF8_TOPHALF);
	    } else {
	       if (bottom) printf(UTF8_BOTTOMHALF);
	       else printf(" ");
	    }
	 }
	 puts("  "ANSI_RESET);
      }
      printf(ANSI_BLACKONGREY);
      for (i = 0; i < qrcode->width + 4; ++i) printf(" ");
      puts(ANSI_RESET);
   }

   QRcode_free(qrcode);
#else
   return 0;
#endif
   return 1;
}

void print_response(struct tiqr_session_qr_rep_t *rep) {
   printf ("Response Code: ");
   switch (rep->code) {
    case 0: printf ("Failure\n");
      break;
    case 1: printf ("Success\n");
      break;
    default: printf("Unknown (%d)\n", rep->code);
      break;
   }
   if (rep->message) printf ("Message: %s\n", rep->message);
   if (rep->timeout) printf ("Timeout: %d\n", rep->timeout);
   if (rep->QR_data) {
      printf ("QRCode: ");
      if (!display_qrcode(rep->URI, 0)) printf("%d Bytes\n", rep->QR_length);
   }
   fflush(stdout);
}

int main(int argc, char *argv[]) {
   tiqr_session_qr_rep_t *rep;
   tiqr_session_qr_req_t *req;
   int i;
   
   void _log(char *str) {
      printf("%s\n", str);
   }
   
   if (argc<3) usage(argv[0]);
   
   if (!tiqr_initialize(argv[1], NULL, NULL, NULL, 0, &_log)) exit(1);
   
   req = tiqr_session_qr_req_new();
   req->session = strdup(argv[2]);
      
   rep = tiqr_session_qr(req, &_log);
   if (!rep) {
      printf("Invalid tiqrSessionQR response\n");
      exit(1);
   }
   print_response(rep);
   
   tiqr_session_qr_req_free(req);
   tiqr_session_qr_rep_free(rep);
   tiqr_terminate(&_log);
   exit(0);
}
