#! /bin/bash

set -ex

gcc wscserv.c -g -o wscserv -lssl -lcrypto -Wall -Wextra -O3
gcc test.c -g -o test -Wall -Wextra -O3
