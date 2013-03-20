#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openotp.h>

void usage(char *prog) {
   printf("Usage: %s <OPENOTP_URL> <USERNAME> [-d | --domain <DOMAIN>] [-lp | --ldapPassword <PASSOWRD>] [-op | --otpPassword <OTP>] [-c | --client <CLIENT>] [-s | --settings <SETTINGS>]\n", prog); 
   fflush(stdout);
   exit(1);
}

void print_login_response(struct openotp_login_rep_t *rep) {
   printf ("Response Code: ");
   switch (rep->code) {
    case 0: printf ("Failure\n");
      break;
    case 1: printf ("Success\n");
      break;
    case 2: printf("Challenge\n");
      break;
    default: printf("Unknown (%d)\n", rep->code);
      break;
   }
   if (rep->message) printf ("Message: %s\n", rep->message);
   if (rep->timeout) printf ("Timeout: %d\n", rep->timeout);
   if (rep->data) printf ("Data: %s\n", rep->data);
   fflush(stdout);
}

void print_challenge_response(struct openotp_challenge_rep_t *rep) {
   printf ("Response Code: ");
   switch (rep->code) {
    case 0: printf ("Failure\n");
      break;
    case 1: printf ("Success\n");
      break;
    case 2: printf("Challenge\n");
      break;
    default: printf("Unknown (%d)\n", rep->code);
      break;
   }
   if (rep->message) printf ("Message: %s\n", rep->message);
   if (rep->data) printf ("Data: %s\n", rep->data);
   fflush(stdout);
}

int main(int argc, char *argv[]) {
   openotp_login_rep_t *lrep;
   openotp_login_req_t *lreq;
   openotp_challenge_rep_t *crep;
   openotp_challenge_req_t *creq;
   char otp[64];
   int i;
   
   void _log(char *str) {
      printf("%s\n", str);
   }
   
   if (argc<3) usage(argv[0]);
   
   if (!openotp_initialize(argv[1], NULL, NULL, NULL, 0, &_log)) exit(1);
   
   lreq = openotp_login_req_new();
   lreq->username = strdup(argv[2]);
   
   for (i=3; i<argc; i+=2) {
      if (i+1==argc) usage(argv[0]);
      if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--domain") == 0) lreq->domain = strdup(argv[i+1]);
      else if (strcmp(argv[i], "-lp") == 0 || strcmp(argv[i], "--ldapPassword") == 0) lreq->ldapPassword = strdup(argv[i+1]);
      else if (strcmp(argv[i], "-op") == 0 || strcmp(argv[i], "--otpPassword") == 0) lreq->otpPassword = strdup(argv[i+1]);
      else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--client") == 0) lreq->client = strdup(argv[i+1]);
      else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--settings") == 0) lreq->settings = strdup(argv[i+1]);
      else usage(argv[0]);
   }
   
   lrep = openotp_login(lreq, &_log);
   if (!lrep) {
      printf("Invalid openotpLogin response\n");
      exit(1);
   }
   print_login_response(lrep);
   
   if (lrep->code == OPENOTP_CHALLENGE) {
      creq = openotp_challenge_req_new();
      
      printf("> ");
      scanf("%s", otp);
      
      creq->session = strdup(lrep->session);
      creq->username = strdup(lreq->username);
      creq->otpPassword = strdup(otp);
      if (lreq->domain) creq->domain = strdup(lreq->domain);
      
      crep = openotp_challenge(creq, &_log);
      if (!crep) exit(1);
      
      print_challenge_response(crep);
      openotp_challenge_req_free(creq);
      openotp_challenge_rep_free(crep);
   }
   
   openotp_login_req_free(lreq);
   openotp_login_rep_free(lrep);
   openotp_terminate(&_log);
   exit(0);
}
