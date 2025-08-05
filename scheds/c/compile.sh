#!/bin/bash -eu
clang -I/usr/include/bpf -I../../build/scheds/c/scx_priority.p/ -O0 -g -Wall -c priority-task.c -o priority-task.o
clang -I/usr/include/bpf -I../../build/scheds/c/scx_priority.p/ -O0 -g -Wall priority-task.o -o priority-task -lbpf

clang -I/usr/include/bpf -I../../build/scheds/c/scx_priority.p/ -O0 -g -Wall -c nonpriority-task.c -o nonpriority-task.o
clang -I/usr/include/bpf -I../../build/scheds/c/scx_priority.p/ -O0 -g -Wall nonpriority-task.o -o nonpriority-task -lbpf
