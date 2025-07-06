#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>

int main() {
    int i=0;
    time_t before = time(NULL);
    time_t after;
    pid_t pid = getpid();
    //printf("In program: pid=%d\n", (int)pid);

    for(i=0; i<100000000; i++){
	printf("i:%d\n", i);
	//sleep(1);
    }

    after = time(NULL);
    printf("Time: %ld\n", after - before);
    return 0;
}

