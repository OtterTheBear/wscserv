#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <ctype.h>

unsigned char hex_to_char(char h) {
    if (h >= '0' && h <= '9') {
        return h - 48;
    }
    if (tolower(h) >= 'a' && tolower(h) <= 'f') {
        return tolower(h) - 'a' + 10;
    }
    printf("ERROR\n");
    return h;
}

int main(int argc, char *argv[]) {
    
    long port_argument;
    uint16_t port = 30002;
    if (argc >= 2) {
        port_argument = strtol(argv[1], NULL, 0);
        if (port_argument < 1 || port_argument > UINT16_MAX) { 
            perror("Invalid port");
            return -1;
        }
        port = port_argument;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0), c = sizeof (struct sockaddr_in);
    struct sockaddr_in serv, client;
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr("0.0.0.0");
    serv.sin_port = htons(port);
    if (connect(fd, (struct sockaddr *) &serv, sizeof(serv)) < 0) {
        perror("connect");
        return -1;
    }

    char s[300] = "Sec-WebSocket-Key: a\r\n\r\n";
    char s2[300] = "\x01\x81\x00\x00\x00\x00" "a";
    printf("hi\n");
    size_t n = 2;
    if (write(fd, s, strlen(s)) < 0) {
        fprintf(stderr, "write error\n");
    }
    sleep(2);
    if (write(fd, s2, n) < 0) {
        fprintf(stderr, "write error 2\n");
    }
    sleep(2);
    printf("length: %zu\n", strlen(s2 + 1));
    if (write(fd, s2 + n, 7 - n) < 0) {
        fprintf(stderr, "write error 3\n");
    }
    char *buf = NULL;
    char *sendbuf = NULL;
    size_t m = 0;
    size_t l;
    ssize_t count;
    for (;;) {
        if ((count = getline(&buf, &m, stdin)) < 1) {
            perror("getline");
            return -1;
        }
        buf[count-1] = '\0';
        l = strlen(buf);
        printf("l: %zu\n", l);
        if (!strcmp(buf, "stop") || l % 3 != 0) {
            printf("hey\n");
            break;
        }
        sendbuf = realloc(sendbuf, l / 3);
        for (size_t i = 0, j = 0; i < l; i += 3) {
            unsigned char x = hex_to_char(buf[i]) * 16 + hex_to_char(buf[i+1]);
            printf("x: %.2hhx\n", x);
            sendbuf[j] = x;
            j++;
        }
        if (write(fd, sendbuf, l / 3) < 0) {
            perror("write");
        }
            
    }
    return 0;
}
