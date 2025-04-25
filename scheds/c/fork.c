#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>

int main() {
    pid_t pid = fork();
    if (pid == 0) {
        // 子プロセスで実行
        char *args[] = {"./sl", NULL, NULL};
        printf("PID=%d\n", (int)pid);
        execvp(args[0], args);
        perror("execvp failed");
    } else if (pid > 0) {
        // 親プロセスは子の終了を待つ
        printf("PID=%d\n", (int)pid);
        printf("子プロセス終了\n");
    } else {
        perror("fork failed");
    }
    return 0;
}

