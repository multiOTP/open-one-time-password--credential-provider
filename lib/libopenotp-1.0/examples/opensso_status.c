#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <opensso.h>

void usage(char *prog) {
   printf("Usage: %s <OPENSSO_URL>\n", prog); 
   fflush(stdout);
   exit(1);
}

void print_response(struct opensso_status_rep_t *rep) {
   printf ("Server Status: ");
   switch (rep->status) {
    case 0: printf ("Failure\n");
      break;
    case 1: printf ("Success\n");
      break;
    default: printf("Unknown (%d)\n", rep->status);
      break;
   }
   if (rep->message) printf ("Message: %s\n", rep->message);
   fflush(stdout);
}

int main(int argc, char *argv[]) {
   opensso_status_rep_t *rep;
   int i;
   
   void _log(char *str) {
      printf("%s\n", str);
   }
   
   if (argc<2) usage(argv[0]);
   
   if (!opensso_initialize(argv[1], NULL, NULL, NULL, 0, &_log)) exit(1);
   
   rep = opensso_status(&_log);
   if (!rep) {
      printf("Invalid openssoStatus response\n");
      exit(1);
   }
   print_response(rep);
   opensso_status_rep_free(rep);
   
   opensso_terminate(&_log);
   exit(0);
}
