#include "netbuffer.h"
#include "mailuser.h"
#include "server.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <ctype.h>

#define MAX_LINE_LENGTH 1024

typedef enum state {
    Undefined,
    // TODO: Add additional states as necessary
    AUTHORIZATION,
    AUTHORIZATIONPASS,
    TRANSACTION,
    UPDATE
} State;

typedef struct serverstate {
    int fd;
    net_buffer_t nb;
    char recvbuf[MAX_LINE_LENGTH + 1];
    char *words[MAX_LINE_LENGTH];
    int nwords;
    State state;
    struct utsname my_uname;
    // TODO: Add additional fields as necessary
    char savedUser[MAX_USERNAME_SIZE];
    mail_list_t mailList;
    int deletedSet[100];
} serverstate;
static void handle_client(int fd);

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Invalid arguments. Expected: %s <port>\n", argv[0]);
        return 1;
    }
    run_server(argv[1], handle_client);
    return 0;
}

// syntax_error returns
//   -1 if the server should exit
//    1 otherwise
int syntax_error(serverstate *ss) {
    if (send_formatted(ss->fd, "-ERR %s\r\n", "Syntax error in parameters or arguments") <= 0) return -1;
    return 1;
}

// checkstate returns
//   -1 if the server should exit
//    0 if the server is in the appropriate state
//    1 if the server is not in the appropriate state
int checkstate(serverstate *ss, State s) {
    if (ss->state != s) {
        if (send_formatted(ss->fd, "-ERR %s\r\n", "Bad sequence of commands") <= 0) return -1;
        return 1;
    }
    return 0;
}

// All the functions that implement a single command return
//   -1 if the server should exit
//    0 if the command was successful
//    1 if the command was unsuccessful

int do_quit(serverstate *ss) {
    dlog("Executing quit\n");
    // When the client issues the QUIT command from the transaction state, the POP3 session enters the UPDATE state
    if (ss->state == TRANSACTION) ss->state = UPDATE;
    // Remove all messages marked as deleted from the mail drop
    mail_list_destroy(ss->mailList);
    if (send_formatted(ss->fd, "+OK Service closing transmission channel\r\n") >= 0) return -1;
    return 1;
}

int do_user(serverstate *ss) {
    dlog("Executing user\n");
    // TODO: Implement this function

    if (ss->state == AUTHORIZATION) {
        if (ss->words[1] == NULL) return syntax_error(ss);

        if (is_valid_user(ss->words[1], NULL) == 0) {
            // If not valid user exists, send -ERR message
            send_formatted(ss->fd, "-ERR No such user exist\r\n");
            return 1;
        } else {
            // If valid user exists, save USER name, and update to PASS state
            send_formatted(ss->fd, "+OK User is valid, proceed with password\r\n");
            strcpy(ss->savedUser, ss->words[1]);
            ss->state = AUTHORIZATIONPASS;
            return 0;
        }
    } else {
        return checkstate(ss, AUTHORIZATION);
    }

    return 0;
}

int do_pass(serverstate *ss) {
    dlog("Executing pass\n");
    // TODO: Implement this function

    if (ss->state == AUTHORIZATIONPASS) {
        if (ss->words[1] == NULL) return syntax_error(ss);

        if (is_valid_user(ss->savedUser, ss->words[1]) == 0) {
            // If the USER and PASS combo is invalid, return back to AUTHORIZATION state
            send_formatted(ss->fd, "-ERR Invalid password\r\n");
            ss->state = AUTHORIZATION;
            return 1;
        } else {
            // If the USER and PASS combo is valid, update to TRANSACTION state and load the user mail
            send_formatted(ss->fd, "+OK Password is valid, mail loaded\r\n");
            ss->state = TRANSACTION;
            ss->mailList = load_user_mail(ss->savedUser);
            // Initialize an array to mark emails as deleted or not
            for (int i = 0; i < 100; i++) {
                ss->deletedSet[i] = 0;
            }
            return 0;
        }
    } else {
        return checkstate(ss, AUTHORIZATIONPASS);
    }

    return 1;
}

int do_stat(serverstate *ss) {
    dlog("Executing stat\n");

    if (checkstate(ss, TRANSACTION) == 1) return 1;
    // Assign mail length and size
    int mailLength = mail_list_length(ss->mailList, 0);
    size_t mailSize = mail_list_size(ss->mailList); 
    send_formatted(ss->fd, "+OK %i %zu\r\n", mailLength, mailSize);
    return 0;
}

int do_list(serverstate *ss) {
    dlog("Executing list\n");

    // Seems like for list, we only need to have the case for one message in the mailbox
    // But this also includes list (with arguments) giving an ok response if there is such message
    // Or ERR if there is no such message

    if (checkstate(ss, TRANSACTION) == 1) return 1;
    
    // Assign mail length, mail length with deleted emails, and size
    int mLength = mail_list_length(ss->mailList, 0);
    int mLengthWDeleted = mail_list_length(ss->mailList, 1);
    size_t mSize = mail_list_size(ss->mailList); 

    if (ss->words[1] == NULL) {
        // User called command LIST
        send_formatted(ss->fd, "+OK %i messages (%zu octets)\r\n", mLength, mSize);

        for (int i = 0; i < mLengthWDeleted; i++) {
            if (ss->deletedSet[i] != 1) {
                // If email is not mark as deleted, print position and size
                mail_item_t mItem = mail_list_retrieve(ss->mailList, i);
                if (mItem == NULL) return 1;
                size_t iSize = mail_item_size(mItem);
                send_formatted(ss->fd, "%i %zu\r\n", i + 1, iSize);
            }
        }

        send_formatted(ss->fd, ".\r\n");

    } else {
        // User called command LIST while specifying which position to retrieve information from
        int j = atoi(ss->words[1]);
        mail_item_t mItem = mail_list_retrieve(ss->mailList, j - 1);
        if (mItem == NULL) {
            // If mail item does not exist or is marked for deleted return -ERR
            send_formatted(ss->fd, "-ERR no such message, only %i messages in maildrop\r\n", mLength);
        } else {
            size_t iSize = mail_item_size(mItem);
            send_formatted(ss->fd, "+OK %i %zu\r\n", j, iSize);
        }

    }

    return 0;
}

int do_retr(serverstate *ss) {
    dlog("Executing retr\n");

    if (checkstate(ss, TRANSACTION) == 1) return 1;
    

    if (ss->words[1] == NULL) {
        // Invalid Argument
        return syntax_error(ss);

    } else {

        int j = atoi(ss->words[1]);
        mail_item_t mItem = mail_list_retrieve(ss->mailList, j - 1);
        if (mItem == NULL) {
            // If mail item does not exist or is marked for deleted return -ERR
            send_formatted(ss->fd, "-ERR no such message\r\n");
        } else {
            // Read from file line by line
            send_formatted(ss->fd, "+OK %zu octets\r\n", mail_item_size(mItem));
            FILE* fp = mail_item_contents(mItem);
            
            if (fp == NULL) return 1;
            
            char *line = NULL;
            size_t len = 0;
            ssize_t read;

            while ((read = getline(&line, &len, fp)) != -1) {
                send_formatted(ss->fd, "%s", line);
                free(line);
                line = NULL;
                len = 0;
            }

            send_formatted(ss->fd, ".\r\n");
            fclose(fp);
            return 0;
        }

    }

    return 0;
}
int do_rset(serverstate *ss) {
    dlog("Executing rset\n");

    if (checkstate(ss, TRANSACTION) == 1) return 1;
    // Restore all mail marked as deleted
    int restoredM = mail_list_undelete(ss->mailList);
    // Reinitilize the deletedSet
    for (int i = 0; i < 100; i++) {
        ss->deletedSet[i] = 0;
    }
    send_formatted(ss->fd, "+OK %i messages restored\r\n", restoredM);
    return 0;
}
int do_noop(serverstate *ss) {
    dlog("Executing noop\n");
    if (checkstate(ss, TRANSACTION) == 1) return 1;
    send_formatted(ss->fd, "+OK\r\n");
    return 0;
}

int do_dele(serverstate *ss) {
    dlog("Executing dele\n");

    if (checkstate(ss, TRANSACTION) == 1) return 1;

    if (ss->words[1] == NULL) {
        return syntax_error(ss);
    } else {

        int j = atoi(ss->words[1]);
        mail_item_t mItem = mail_list_retrieve(ss->mailList, j - 1);

        if (mItem == NULL) {
            // If not mail item exists, return -ERR message
            send_formatted(ss->fd, "-ERR no such message\r\n");
        } else {
            // Else mark the item as deleted and add the position to the deleted set
            mail_item_delete(mItem);
            ss->deletedSet[j - 1] = 1;
            send_formatted(ss->fd, "+OK message %i deleted\r\n", j);
        }
    }
    return 0;
}

void handle_client(int fd) {
    size_t len;
    serverstate mstate, *ss = &mstate;
    ss->fd = fd;
    ss->nb = nb_create(fd, MAX_LINE_LENGTH);
    ss->state = Undefined;
    uname(&ss->my_uname);
    if (send_formatted(fd, "+OK POP3 Server on %s ready\r\n", ss->my_uname.nodename) <= 0) return;
    ss->state = AUTHORIZATION;

    while ((len = nb_read_line(ss->nb, ss->recvbuf)) >= 0) {
        if (ss->recvbuf[len - 1] != '\n') {
            // command line is too long, stop immediately
            send_formatted(fd, "-ERR Syntax error, command unrecognized\r\n");
            break;
        }
        if (strlen(ss->recvbuf) < len) {
            // received null byte somewhere in the string, stop immediately.
            send_formatted(fd, "-ERR Syntax error, command unrecognized\r\n");
            break;
        }
        // Remove CR, LF and other space characters from end of buffer
        while (isspace(ss->recvbuf[len - 1])) ss->recvbuf[--len] = 0;
        dlog("Command is %s\n", ss->recvbuf);
        if (strlen(ss->recvbuf) == 0) {
            send_formatted(fd, "-ERR Syntax error, blank command unrecognized\r\n");
            break;
        }
        // Split the command into its component "words"
        ss->nwords = split(ss->recvbuf, ss->words);
        char *command = ss->words[0];
        if (!strcasecmp(command, "QUIT")) {
            if (do_quit(ss) == -1) break;
        } else if (!strcasecmp(command, "USER")) {
            if (do_user(ss) == -1) break;
        } else if (!strcasecmp(command, "PASS")) {
            if (do_pass(ss) == -1) break;
        } else if (!strcasecmp(command, "STAT")) {
            if (do_stat(ss) == -1) break;
        } else if (!strcasecmp(command, "LIST")) {
            if (do_list(ss) == -1) break;
        } else if (!strcasecmp(command, "RETR")) {
            if (do_retr(ss) == -1) break;
        } else if (!strcasecmp(command, "RSET")) {
            if (do_rset(ss) == -1) break;
        } else if (!strcasecmp(command, "NOOP")) {
            if (do_noop(ss) == -1) break;
        } else if (!strcasecmp(command, "DELE")) {
            if (do_dele(ss) == -1) break;
        } else if (!strcasecmp(command, "TOP") ||
                   !strcasecmp(command, "UIDL") ||
                   !strcasecmp(command, "APOP")) {
            dlog("Command not implemented %s\n", ss->words[0]);
            if (send_formatted(fd, "-ERR Command not implemented\r\n") <= 0) break;
        } else {
            // invalid command
            if (send_formatted(fd, "-ERR Syntax error, command unrecognized\r\n") <= 0) break;
        }
    }
    nb_destroy(ss->nb);
}
