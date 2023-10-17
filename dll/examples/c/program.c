 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>

 #include "lbvdll.h"

 int main(int argc, char **argv) {
 if (argc != 3) {
     fprintf(stderr, "Usage: %s [up|down] <wgfile>\n", argv[0]);
     exit(1);
 }

 graal_isolate_t *isolate = NULL;
 graal_isolatethread_t *thread = NULL;

 if (graal_create_isolate(NULL, &isolate, &thread) != 0) {
     fprintf(stderr, "initialization error\n");
     return 1;
 }

 if(strcmp("up", argv[1]) == 0) {
	 long long int hndl = up(thread, argv[2], 0, 0);

	 printf("Handle: %lli\n", hndl);
	 if(hndl == 0) {
		 printf("Code: %i\n", get_error_code(thread));
	 }
 }
 else if(strcmp("down", argv[1]) == 0) {
	 stop(thread, argv[2], 0, 0);
 }
 else {
     fprintf(stderr, "Usage: %s [up|down] <wgfile>\n", argv[0]);
     graal_detach_all_threads_and_tear_down_isolate(thread);
     exit(1);
 }

 fprintf(stderr, "tearing down\n");
 graal_detach_all_threads_and_tear_down_isolate(thread);
 }
