#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <time.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <errno.h>
#include <endian.h>
#include <signal.h>
#define MAX_NAME 256

typedef struct {
    int their_sock;
    char their_name[MAX_NAME];
    int theyre_logged_in;
} user_t;


// https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};

static int mod_table[] = {0, 2, 1};

char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = malloc(*output_length + 1);
    encoded_data[*output_length] = '\0';
    if (encoded_data == NULL) return NULL;
    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++) {
        encoded_data[*output_length - 1 - i] = '=';
    }

    return encoded_data;
}

int64_t websocket_send(int fd, char *buf, int64_t length, char opcode) {
    char sendbuf[10];
    sendbuf[0] = opcode;
    int header_bytes = 0;
    if (length < 126) {
        sendbuf[1] = (char) length;
        header_bytes = 2;
    } else if (length > 125 && length < 65536) {
        sendbuf[1] = 126;
        sendbuf[2] = length >> 8;
        sendbuf[3] = length & 0xFF;
        header_bytes = 4;
    } else if (length > 65535) {
        sendbuf[1] = 127;
        header_bytes = 2;
        for (int j = 56; header_bytes < 10;) {
            sendbuf[header_bytes] = (char) length >> j;
            header_bytes++;
            j -= 8;
        }
    }
    
    ssize_t sendbuf_retval = write(fd, sendbuf, header_bytes);
    if (sendbuf_retval < header_bytes) {
        close(fd);
        return 0;
    }
    
    ssize_t retval = write(fd, buf, length);
    if (retval < 0) {
        perror("websocket_send: write");
    }
    return retval;
}

int64_t websocket_recv(int fd, char *buf, int64_t length) {
    unsigned char lengthbuf[14];
    ssize_t retval = read(fd, lengthbuf, 2); 
    if (retval < 0) {
        perror("read");
        return -1;
    }
    
    if (retval == 0) {
        return 0;
    }

    char opcode = lengthbuf[0] & 0xf;
    printf("Opcode: %.2x\n", opcode);
    if (opcode == 0x8) {
        websocket_send(fd, "", 0, 0x88);
        return 0;
    }
    if ((opcode < 0x1) || (opcode > 0x1 && opcode < 0x9) || (opcode > 0xA) || !(lengthbuf[1] & 0x80)) {
        return 0;
    } else {
        int64_t sent_length = (int64_t) lengthbuf[1] & 0x7F;
        printf("this is the first byte of the sent length: %llu\n", sent_length);
        if (sent_length == 126) {
            read(fd, lengthbuf + 2, 2);
            sent_length = ((int64_t) (lengthbuf[2] * 256)) + ((int64_t) lengthbuf[3]);
            printf("yay!!! more bytes of the sent length %llu\n", sent_length);
        } else if (sent_length == 127) {
            read(fd, lengthbuf + 2, 8);
            sent_length = 0;
            int i = 2;
            int j = 64;
            while (i < 10) {
                sent_length += (int64_t) lengthbuf[i] << j;
                i++;
                j -= 8;
            }
        }
        char mask[4];
        read(fd, mask, 4);
        int64_t i = 0;
        for (; (i < length) && (i < sent_length) && (read(fd, buf + i, 1)) > 0; i++) {
            buf[i] ^= mask[i % 4];
        }
        printf("i: %lld\n", i);
        return i;
    }
}

void reset_user_t(user_t *the_user) {
    the_user->their_name[0] = '\0';
    the_user->their_sock = -1;
    the_user->theyre_logged_in = 0;
}

void log_someone_out(user_t *the_user) { // reset the values of a user_t so onconnect will be able to use it again
    close(the_user->their_sock);
    reset_user_t(the_user);
}


void on_connect(int fd, struct sockaddr_in *clientp, socklen_t *cp, user_t clients[], uintmax_t max_clients) {
    int newfd = accept(fd, (struct sockaddr *) clientp, cp);
    if (newfd < 0) {
        return;
    }
    time_t now = time(NULL);
    printf("\nConnection from %s at %s", inet_ntoa(clientp->sin_addr), ctime(&now));
    char *magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char buf[BUFSIZ + strlen(magic_string) + 1];
    ssize_t retval;
    printf("This many bytes were read: %zd\n", retval = read(newfd, buf, BUFSIZ));
    if (retval < 0) {
        perror("Invalid read");
        return;
    }
    buf[retval + 1] = '\0';
    char *key = strstr(buf, "Sec-WebSocket-Key: ");
    char *closemsg = "the key isn't in the request";
    char *keytooshortmsg = "the key is too short";
    char *theresnonewlinemsg = "You forgot to put a new line";
    if (key == NULL) {
        printf("%s\n", closemsg);
        websocket_send(newfd, closemsg, strlen(closemsg), 0x81);
        close(newfd);
        return;
    }

    if (strlen(key) < 20) {
        printf("%s\n", keytooshortmsg);
        websocket_send(newfd, keytooshortmsg, strlen(keytooshortmsg), 0x81);
        close(newfd);
        return;
    }
    char *the_new_line_in_key = strstr(key, "\r\n");
    if (the_new_line_in_key == NULL) {
        printf("They forgot to put a new line\n");
        websocket_send(newfd, theresnonewlinemsg, strlen(theresnonewlinemsg), 0x81);
        close(newfd);
        return;
    }
    the_new_line_in_key[0] = '\0';    
    memmove(buf, key + 19, strlen(key) - 18);

    strcat(buf, magic_string);
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *) buf, strlen(buf), hash);
    size_t output_length;
    char *the_base64_key = base64_encode(hash, SHA_DIGEST_LENGTH, &output_length);

    if (the_base64_key == NULL) {
        printf("Base64-encoded key was null\n");
        close(newfd);
        return;
    }

    char response[1004 + output_length];
    strcpy(response, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ");
    strcat(strcat(response, the_base64_key), "\r\n\r\n");
    free(the_base64_key);
    write(newfd, response, strlen(response));
    for (int i = 0; i < max_clients; i++) {
        if (clients[i].their_sock < 0) {
            clients[i].their_sock = newfd;
            return;
        }
    }
    char *sorryfullmsg = "Sorry, the server seems to be full right now.";
    websocket_send(newfd, sorryfullmsg, strlen(sorryfullmsg), 0x81);
    close(newfd);
    
}

void wall(user_t clients[], char *msg, int64_t length, uintmax_t max_clients) {
    for (int i = 0; i < max_clients; i++) {
        if (clients[i].theyre_logged_in) {
            if (clients[i].their_sock == 0) {
                printf("what\n");
                printf("%.*s\n", length > 128 ? 128 : (int) length, msg);
            } else if (clients[i].their_sock > 0) {
                if (websocket_send(clients[i].their_sock, msg, length, 0x81) < 0) {
                    log_someone_out(&clients[i]);
                }
            }
        }
    }
}

void on_data(user_t clients[], user_t *the_user, uintmax_t max_clients) {
    char buf[BUFSIZ];
    int64_t retval;
    printf("\nfrom %s, socket: %d, logged in?: %d\n", the_user->their_name, the_user->their_sock, the_user->theyre_logged_in);
    if (the_user->theyre_logged_in) {
        if (the_user->their_sock == 0) {
            retval = read(the_user->their_sock, buf, BUFSIZ);
        } else if (the_user->their_sock > 0) {
            retval = websocket_recv(the_user->their_sock, buf, BUFSIZ);
        }
        printf("This many bytes were received: %lld\n", retval);
        if (retval < 1) {
            printf("retval < 1, logging them out\n");
            log_someone_out(the_user);
            return;
        }
        
        char the_message_with_their_name[strlen(the_user->their_name) + 2 + retval + 1]; // name length + ": " + sent length + null
        strncpy(the_message_with_their_name, the_user->their_name, strlen(the_user->their_name));
        the_message_with_their_name[strlen(the_user->their_name)] = '\0';
        strcat(the_message_with_their_name, ": ");
        strncat(the_message_with_their_name, buf, retval);
        printf("This is the sum: %llu\n", strlen(the_user->their_name) + 2 + retval);
        wall(clients, the_message_with_their_name, strlen(the_user->their_name) + 2 + retval, max_clients);
    } else {
        retval = websocket_recv(the_user->their_sock, the_user->their_name, MAX_NAME - 1);
        printf("Here's how many bytes they sent if they're not logged in: %llu\n", retval);
        if (retval <= 0) {
            printf("logging them out\n");
            log_someone_out(the_user);
            return;
        } else {
            the_user->their_name[retval] = '\0';
            the_user->theyre_logged_in = 1;
        } 
    }
}




int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Max clients not specified\n");
        return -1;
    }
    uintmax_t max_clients = strtoumax(argv[1], NULL, 0);
    printf("max_clients: %ju\n", max_clients);
    if (max_clients == 0 || errno != 0) {
        perror("Invalid amount of clients");
        return -1;
    }

    long port_argument;
    uint16_t port = 30002;
    if (argc >= 3) {
        port_argument = strtol(argv[2], NULL, 0);
        if (port_argument < 1 || port_argument > UINT16_MAX) { 
            perror("Invalid port");
            return -1;
        }
        port = port_argument;
    }
    
    struct sigaction action;
    action.sa_handler = SIG_IGN;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    if (sigaction(SIGPIPE, &action, NULL) < 0) {
        perror("sigaction");
        return -1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0), c = sizeof(struct sockaddr_in), highestfd = fd;
    if (fd < 0) {
        perror("socket failed");
        return -1;
    }
    user_t clients[max_clients];
    for (uintmax_t i = 0; i < max_clients; i++) {
        reset_user_t(&clients[i]);
    }
    strcpy(clients[0].their_name, "Server");
    clients[0].their_sock = 0;
    clients[0].theyre_logged_in = 1;
    
    struct timespec t1, t2;
    t1.tv_sec = 0;
    t1.tv_nsec = 50000000;

    fd_set readfds;
    struct sockaddr_in serv, client;
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr("0.0.0.0");
    serv.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *) &serv, sizeof(serv)) == -1) {
        perror("bind failed");
        return -1;
    }
    listen(fd, 3);
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);
        highestfd = fd;
        uintmax_t user_count = 0;
        for (int i = 0; i < max_clients; i++) {
            if (clients[i].their_sock > -1) {
                printf("%d: their_sock: %d, their_name: %s, theyre_logged_in: %d\n", i, clients[i].their_sock, clients[i].their_name, clients[i].theyre_logged_in);
                FD_SET(clients[i].their_sock, &readfds);
                user_count++;
            }

            if (clients[i].their_sock > highestfd) {
                highestfd = clients[i].their_sock;
            }
        }

        printf(user_count == 1 ? "%ju user" : "%ju users", user_count); 
        printf(" out of %ju\n", max_clients);

        select(highestfd + 1, &readfds, NULL, NULL, NULL);
        if (FD_ISSET(fd, &readfds)) {
            on_connect(fd, (struct sockaddr_in *) &client, (socklen_t *) &c, clients, max_clients);
            
        }
        for (int i = 0; i < max_clients; i++) {
            if (FD_ISSET(clients[i].their_sock, &readfds)) {
                on_data(clients, &clients[i], max_clients);
            }
        }
        nanosleep(&t1, &t2);
    }
    
    return 0;
}
