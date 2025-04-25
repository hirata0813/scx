#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>

int main() {
    int i=0;
    pid_t pid = getpid();
    printf("In program: pid=%d\n", (int)pid);

    for(i=0; i<1000; i++){
	printf("i:%d\n", i);
	sleep(1);
    }
    return 0;
}

