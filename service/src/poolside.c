#include "list.h"

#define RAND_LENGTH (16)
#define _NULL ((void *) 0)
#define PFATAL(x) do {    \
    perror(x);            \
    abort();              \
} while(0);
#define FATAL(x) do {     \
    if (x) { printf(x); } \
    abort();              \
} while(0);
#define FILE void
#define INI_LEN_MAX (256)
#define DELIM ('=')
#define NL "\r\n"

#define STORAGE_DIR "../../data/"

#define COOKIE_LEN (64)
#define COOKIE_DIR STORAGE_DIR"cookies/"
#define DATA_DIR STORAGE_DIR"data/"

/* The os will free our memory. */
const char* __asan_default_options() {
    /* The os will free our memory. */
    return "detect_leaks=0";
}

/* 0-9A-Za-z */
int is_alphanumeric(char c) {
    return (c >= '0' && c <= '9') ||
           (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z');
}

/* A random char in 0-9A-Za-z */
char get_rand_alphanumberic() {
    char ret = 0;
    if(!getrandom(&ret, 1, 0)) {
        PFATAL("Couldn't get random");
    }
    if (is_alphanumeric(ret)) {
        return ret;
    }
    return get_rand_alphanumberic();
}

/* returns a random string with the given length */
char *rand_str(int len) {
    int i;
    char *ret = calloc(2, len);
    if (!ret) { PFATAL("calloc") };
    for (i = 0; i < len; i++) {
        ret[i] = get_rand_alphanumberic();
    }
    return ret;
}

/* reads a line */
char *readline(FILE *f) {
    char buf[1024];
    if(!((f && fgets(f, sizeof(buf), buf)) || gets(buf))) {
        PFATAL("Readline");
    }
    char *ret = malloc(strlen(buf)+1);
    strcpy(ret, buf);
    return ret;
}

char *get_val(char** ini, char *key) {
    int i;
    int len = strlen(key) + 1;
    char tok[len + 1];
    strcpy(tok, key);
    tok[len - 1] = DELIM;
    tok[len] = 0;
    for (i = 0; i < INI_LEN_MAX; i++) {
        char *key_pos = strstr(ini[i], tok);
        if (key_pos == ini[i]) {
            return strdup(ini[i] + len);
        }
    }
    return NULL;
}

char *f_get_val(char** ini, char *key) {
    int i;
    int len = strlen(key) + 1;
    char tok[len + 1];
    strcpy(tok, key);
    tok[len - 1] = DELIM;
    tok[len] = 0;
    for (i = 0; i < INI_LEN_MAX; i++) {
        char *key_pos = strstr(ini[i], tok);
        if (key_pos == ini[i]) {
            return strdup(ini[i] + len);
        }
    }
    return NULL;
}

char **read_ini(char *filename) {
    char **ini = calloc(sizeof(char *), 256);
    int linec = 0;
    FILE *f = fopen(filename, "r+");
    if (!f) { PFATAL("Couldn't open ini"); }
    do {
        ini[linec++] = readline(f);
    } while (ini[linec - 1]);
    fclose(f);
    return ini;
}

int cookie_file(cookie) {
    char *cookie_dir[1028];
    sprintf(cookie_dir, COOKIE_DIR, "%s", cookie);
    int fc = fopen(cookie_dir, "w+");
    if (!fc) PFATAL("Cookie");
    return fc;
}

void write_ini_val(FILE *f, char *name) {

}

int handle_post(char *cookie) {

    readline(0);
    return 0;

}

int handle_get(char *cookie) {

    /*cookie_file();*/
    /*read_ini(USER_DIR + username);*/

    return 0;

}

int main(int argc, char **argv) {

    alarm(1);

    /*https://www.openroad.org/cgi-bin/cgienvdemo*/
    printf(rand_str(16));

    printf("\n%c", get_rand_alphanumberic());

    printf("\n");
    printf("%c", get_rand_alphanumberic());

    readline(0);
    exit(0);

    char *cookie = getenv("HTTP_COOKIE");
    char *request_method = getenv("REQUEST_METHOD");
    char *query_string = getenv("QUERY_STRING");
    /* Webserver name to this binary */
    char *script_name = getenv("SCRIPT_NAME");


    printf("Content-Type: text/html"NL);
    if (!cookie) {
        /* A new user, welcome! :) */
        cookie = rand_str(COOKIE_LEN);
    }
    printf("Set-Cookie: identity=%s"NL, cookie);

    /* header end */
    printf(NL);

    printf("%s %s %s", request_method, query_string, script_name);

    if (request_method && !strcmp(request_method, "GET")) {

        handle_get(cookie);

    } else if (request_method && !strcmp(request_method, "POST")) {

        handle_post(cookie);

    } else if (request_method && !strcmp(request_method, "TEST")) {

    } else {

        printf("Unknown method %s"NL, request_method);
        return -1;

    }

    printf("<html><body></body></html>");

    /*char *str = readline(0);
    //printf(str);
    //free(str);
    */

}
