/*#include "list.h"*/

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

#define KV_FOREACH(kv, block) do {              \
    int idx = 0;                                \
    char **cur = (kv);                          \
    char *key, *val;                            \
    while((key = cur[0]) && (val = cur[1])) {   \
        {block}                                 \
        idx++;                                  \
        cur += 2;                               \
    }                                           \
} while (0);

int assert(int condition) {
    if (!condition) {
        printf("Assert failed :/\n");
        exit(1);
    }
}

/* TODO: leave out param types for ptr/int types */

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

/* A new string with only alphanumeric chars.
   The others are stripped. */
char *dup_alphanumeric(char *str) {
    int i;
    int retpos = 0;
    char *ret = calloc(1, 1024);
    for (i = 0; str[i]; i++) {
        if (is_alphanumeric(str[i])) {
            ret[retpos++] = str[i];
        }
    }
    return ret;
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
    if(!((f && fgets(buf, sizeof(buf), f)) || gets(buf))) {
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
    return _NULL;
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
    return _NULL;
}

char **parse_query(char *str) {
    int i;
    char *contents = strdup(str);
    int content_len = strlen(contents);
    char **ret = calloc(1, content_len * 2);
    int parsing_key = 1;
    int current_len = 0;
    ret[0] = contents;
    int val_count = 0;
    for (i = 0; i < content_len; i++) {
        /* TODO: Use this in checker to fingerprint */
        if ((contents[i] == (parsing_key ? '=' : '&')) && current_len) {
            contents[i] = 0;
            ret[++val_count] = &contents[i + 1];
            parsing_key = !parsing_key;
            current_len = 0;
        } else {
            current_len++;
        }
    }
    return ret;
}

char **read_ini(char *filename) {
    char **ini = calloc(1, 256);
    int linec = 0;
    FILE *f = fopen(filename, "r+");
    if (!f) { PFATAL("Couldn't open ini"); }
    do {
        ini[linec++] = readline(f);
    } while (ini[linec - 1]);
    fclose(f);
    return ini;
}

int cookie_file(char *cookie) {
    char cookie_dir[1028];
    sprintf(cookie_dir, COOKIE_DIR"%s", cookie);
    int fc = fopen(cookie_dir, "w+");
    if (!fc) PFATAL("Cookie");
    return fc;
}

void write_ini_val(FILE *f, char *name) {

}

int write_sec_headers(char *nonce) {

    /* TODO: CSP Nonce */
    printf(
        "Content-Security-Policy: script-src 'self' 'unsafe-inline';"NL
        "X-Frame-Options: SAMEORIGIN"NL
        "X-Xss-Protection: 1; mode=block"NL
        "X-Content-Type-Options: nosniff"NL
        "Referrer-Policy: no-referrer-when-downgrade"NL
        "Feature-Policy "
            "geolocation 'self'; midi 'self'; sync-xhr 'self'; microphone 'self'; "
            "camera 'self'; magnetometer 'self'; gyroscope 'self'; speaker 'self'; "
            "fullscreen *; payment 'self';"NL
    );

    return 0;
}

/* run tests using
   make CFLAGS='-DTEST_RAND'
*/
#if defined(TEST_RAND)
int main() {

    assert(strlen(rand_str(16)) == 16);
    assert(is_alphanumeric(rand_str(1)[0]));
    printf("%s\n", rand_str(16));
    return 0;

}
#elif defined(TEST_QUERY_PARSER)
int main() {
    int i;
    char *parseme = "pool=side&fun=true&you're=beautiful!&&fun=";
    printf("parsing %s\n", parseme);
    char ** query = parse_query(parseme);
    KV_FOREACH(query, {
        printf("key: %s, val: %s\n", key, val);
    })
    assert(parseme[1] == query[0][1]);
    return 0;
}
#elif defined(TEST_ALPHA)
int main() {
    char *alpha = "FUN1";
    char *nonalpha1 = "%%!FUN1";
    char *nonalpha2 = "%%!";
    char *nonalpha3 = "%%!0";
    char *alpha1 = dup_alphanumeric(nonalpha1);
    printf("%s: %s", nonalpha1, alpha1);
    assert(!strncmp(alpha, alpha1));
    free(alpha1);
}
#else /* No TEST */

int main() {

#ifndef DEBUG
    alarm(15);
#endif

    /*https://www.openroad.org/cgi-bin/cgienvdemo*/
    char *cookie = getenv("HTTP_COOKIE");
    char *request_method = getenv("REQUEST_METHOD");
    char *query_string = getenv("QUERY_STRING");
    /* Webserver name to this binary */
    char *script_name = getenv("SCRIPT_NAME");

    char *nonce = rand_str(16);
    write_sec_headers(nonce);

    printf("Content-Type: text/html"NL);
    if (!cookie) {
        /* A new user, welcome! :) */
        cookie = rand_str(COOKIE_LEN);
    } else {
        cookie = dup_alphanumeric(cookie);
    }
    printf("Set-Cookie: identity=%s"NL, cookie);

    /* header end */
    printf(NL);

    /*printf("%s %s %s", request_method, query_string, script_name);*/

    if (request_method && !strcmp(request_method, "GET")) {

        handle_get(cookie);

    } else if (request_method && !strcmp(request_method, "POST")) {

        handle_post(cookie);

    } else if (request_method && !strcmp(request_method, "TEST")) {

        printf("TEST"NL);
        exit(0);

    } else {

        printf("Unsupported method %s"NL, request_method);
        return -1;

    }

    printf("<html><body></body></html>");

    /*char *str = readline(0);
    //printf(str);
    //free(str);
    */
   free(cookie);
   free(nonce);

}

#endif

/* The Webserver Methods */

int handle_get(char *cookie) {

    /*int cf = cookie_file(cookie);*/
    printf("test");
    /*read_ini(USER_DIR + username);*/

    return 0;

}

int handle_post(char *cookie) {

    char *line = readline(0);
    while (line && line[0]) {
        char **query = parse_query(line);

        KV_FOREACH(query, {

        });

        free(query[0]);
        free(query);
        free(line);
        line = readline(0);
    }
    return 0;

}

