#!/bin/bash -eu
clang -I/usr/include/bpf -I../../build/scheds/c/scx_priority.p/ -O0 -g -Wall -c priority-task.c -o priority-task.o
clang -I/usr/include/bpf -I../../build/scheds/c/scx_priority.p/ -O0 -g -Wall priority-task.o -o priority-task -lbpf

clang -I/usr/include/bpf -I../../build/scheds/c/scx_priority.p/ -O0 -g -Wall -c nonpriority-task.c -o nonpriority-task.o
clang -I/usr/include/bpf -I../../build/scheds/c/scx_priority.p/ -O0 -g -Wall nonpriority-task.o -o nonpriority-task -lbpf

clang -I/usr/include/bpf -I../../build/scheds/c/scx_priority.p/ -O0 -g -Wall -c infinityloop.c -o infinityloop.o
clang -I/usr/include/bpf -I../../build/scheds/c/scx_priority.p/ -O0 -g -Wall infinityloop.o -o infinityloop -lbpf

clang -I/usr/include/bpf -I../../build/scheds/c/scx_priority.p/ -O0 -g -Wall -c rdtsc.c -o rdtsc.o
clang -I/usr/include/bpf -I../../build/scheds/c/scx_priority.p/ -O0 -g -Wall rdtsc.o -o rdtsc -lbpf
rm priority-task.o
rm nonpriority-task.o
rm infinityloop.o

clang -I/usr/include/bpf -I../../build/scheds/c/scx_priority.p/ -O0 -g -Wall -pthread -c io-poll-prio.c -o io-poll-prio.o
clang -I/usr/include/bpf -I../../build/scheds/c/scx_priority.p/ -O0 -g -Wall -pthread io-poll-prio.o -o io-poll-prio -lbpf

clang -I/usr/include/bpf -I../../build/scheds/c/scx_priority.p/ -O0 -g -Wall -pthread -c io-poll-nonprio.c -o io-poll-nonprio.o
clang -I/usr/include/bpf -I../../build/scheds/c/scx_priority.p/ -O0 -g -Wall -pthread io-poll-nonprio.o -o io-poll-nonprio -lbpf

rm io-poll-prio.o
rm io-poll-nonprio.o

#clang -I/usr/include/bpf -I../../build/scheds/c/scx_priority.p/ -O0 -g -Wall -c lock_test.c -o lock_test.o
#clang -I/usr/include/bpf -I../../build/scheds/c/scx_priority.p/ -O0 -g -Wall lock_test.o -o lock_test -lbpf
