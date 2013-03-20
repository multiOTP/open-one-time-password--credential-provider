#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tiqr.h>

void usage(char *prog) {
   printf("Usage: %s <TIQR_URL> <SESSION> [-p | --password <LDAP_PASSWORD>]\n", prog); 
   fflush(stdout);
   exit(1);
}

void print_response(struct tiqr_check_rep_t *rep) {
   printf ("Response Code: ");
   switch (rep->code) {
    case 0: printf ("Failure\n");
      break;
    case 1: printf ("Success\n");
      break;
    case 2: printf ("Pending\n");
      break;
    default: printf("Unknown (%d)\n", rep->code);
      break;
   }
   if (rep->message) printf ("Message: %s\n", rep->message);
   if (rep->username) printf ("Username: %s\n", rep->username);
   if (rep->domain) printf ("Domain: %s\n", rep->domain);
   if (rep->data) printf ("Data: %s\n", rep->data);
   if (rep->timeout) printf ("Timeout: %d\n", rep->timeout);
   fflush(stdout);
}

int main(int argc, char *argv[]) {
   tiqr_check_rep_t *rep;
   tiqr_check_req_t *req;
   int i;
   
   void _log(char *str) {
      printf("%s\n", str);
   }
   
   if (argc<3) usage(argv[0]);
   
   if (!tiqr_initialize(argv[1], NULL, NULL, NULL, 0, &_log)) exit(1);
   
   req = tiqr_check_req_new();
   req->session = strdup(argv[2]);
   
   for (i=2; i<argc; i+=2) {
      if (i+1==argc) usage(argv[0]);
      if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--password") == 0) req->ldapPassword = strdup(argv[i+1]);
      else usage(argv[0]);
   }
   
   rep = tiqr_check(req, &_log);
   if (!rep) {
      printf("Invalid tiqrCheck response\n");
      exit(1);
   }
   print_response(rep);
   
   tiqr_check_req_free(req);
   tiqr_check_rep_free(rep);
   tiqr_terminate(&_log);
   exit(0);
}
