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
#define KV_SPLIT ('&')
#define KV_START ('?')
#define NL "\r\n"

#define STORAGE_DIR "../../data/"

#define COOKIE_LEN (64)
#define COOKIE_DIR STORAGE_DIR"cookies/"
#define DATA_DIR STORAGE_DIR"data/"
#define USER_DIR DATA_DIR"user/"

#define KV_FOREACH(kv, block) do {              \
    int idx = 0;                                \
    char **cur = (kv);                          \
    char *key, *val;                            \
    while(cur[0] && cur[1]) {                   \
        key = cur[0];                           \
        val = cur[1];                           \
        {block}                                 \
        idx++;                                  \
        cur += 2;                               \
    }                                           \
} while (0);

#define TEMPLATE(x) #x


typedef struct state {

    char *cookie;
    char *nonce;
    char *user;
    char *route;
    char **queries[32];

} state_t;

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
    int content_len = strlen(str);
    char **ret = calloc(1, (content_len) * 4 + 8);
    char *contents = strdup(str);
    int parsing_key = 1;
    int current_len = 0;
    ret[0] = contents;
    int val_count = 0;
    for (i = 0; i < content_len; i++) {
        /* TODO: Use this in checker to fingerprint */
        if (!contents[i]) {
            ret[++val_count] = "";
            return ret;
        } else if ((contents[i] == (parsing_key ? DELIM : KV_SPLIT)) && current_len) {
            contents[i] = 0;
            ret[++val_count] = &contents[i + 1];
            parsing_key = !parsing_key;
            current_len = 0;
        } else {
            current_len++;
        }
    }
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

char *get_val(state_t *state, char *key_to_find) {
    int i;

    for(i = 0;;i++) {
        /*printf("p: %d %p"NL, i, state->queries[i]);*/
        if (!state->queries[i]) {
            state->queries[i] = parse_query(readline(0));
        }
        KV_FOREACH(state->queries[i], {
            /*printf("%s %s\n", key, key_to_find);*/
            if (!strcmp(key, key_to_find)) {
                return val;
            }
        });
    }
}

FILE *cookie_file(char *cookie) {
    char cookie_dir[1032];
    sprintf(cookie_dir, COOKIE_DIR"%s", cookie);
    int fc = fopen(cookie_dir, "r+");
    if (!fc) PFATAL("Cookie");
    return fc;
}

int write_headers(state_t *state) {

    printf(
        /* TODO: Use CSP Nonce */
        "Content-Security-Policy: script-src 'self' 'unsafe-inline';"NL
        "X-Frame-Options: SAMEORIGIN"NL
        "X-Xss-Protection: 1; mode=block"NL
        "X-Content-Type-Options: nosniff"NL
        "Referrer-Policy: no-referrer-when-downgrade"NL
        "Feature-Policy "
            "geolocation 'self'; midi 'self'; sync-xhr 'self'; microphone 'self'; "
            "camera 'self'; magnetometer 'self'; gyroscope 'self'; speaker 'self'; "
            "fullscreen *; payment 'self';"NL

        "Content-Type: text/html"NL

        "Set-Cookie: identity="
    );
    printf(state->cookie);
    printf(NL);

    return 0;
}

int write_head(state_t *state) {

    printf(
        "<head>"NL
        "   <title>&#127958; POOLSIDE</title>"NL
        "</head>"NL
    );

    return 0;
}

state_t *init_state(char *current_cookie, char *query_string) {
    int i;
    state_t *state = calloc(sizeof(state_t), 1);
    if (!current_cookie) {
        /* A new user, welcome! :) */
        state->cookie = rand_str(COOKIE_LEN);
    } else {
        state->cookie = dup_alphanumeric(current_cookie);
    }
    state->nonce = rand_str(16);
    state->queries[0] = parse_query(query_string);

    state->route = "";
    KV_FOREACH(state->queries[0], {
        if (!strcmp(key, "route")) {
            state->route = val;
        }
    })

    return state;
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
    assert(!strcmp(alpha, alpha1));
    free(alpha1);
    return 0;
}
#elif defined(TEST_VAL)
int main() {
    state_t *state = init_state(_NULL);
    printf("%s\n", get_val(state, "test"));
    printf("%s\n", get_val(state, "test2"));
}
#elif defined(TEST_READLINE)
int main() {
    printf("%s"NL, readline(0));
}
#elif defined(TEST_HASH)
int main() {
    printf("%s"NL, hash("test"));
}
#else /* No TEST */

int main() {

#ifndef DEBUG
    alarm(15);
#endif

    /*https://www.openroad.org/cgi-bin/cgienvdemo*/
    char *current_cookie = getenv("HTTP_COOKIE");
    char *request_method = getenv("REQUEST_METHOD");
    char *query_string = getenv("QUERY_STRING");
    /* Webserver name to this binary */
    char *script_name = getenv("SCRIPT_NAME");

    state_t *state = init_state(current_cookie, query_string);
    write_headers(state);

    /* header end */
    printf(NL);

    printf(
        "<!DOCTYPE html>"NL
        "<html>"NL
    );

    write_head(state);

    if (!request_method) {
        /* Debug Mode */
        request_method = "GET";
    }

    dprintf(2, "%s %s %s %s", request_method, state->route, query_string, script_name);

    if ((request_method && !strcmp(request_method, "GET"))
            || !strcmp(state->route, "")) {

        handle_get(state);

    } else if (request_method && !strcmp(request_method, "POST")) {

        handle_post(state);

    } else if (request_method && !strcmp(request_method, "TEST")) {

        printf("TEST"NL);
        exit(0);

    } else {

        printf("Unsupported method %s"NL, request_method);
        return -1;

    }

    printf(NL"</html>"NL);

    return 0;

}

#endif


/* The Webserver Methods */

int handle_get(state_t *state) {

    /*int cf = cookie_file(cookie);*/
    /*read_ini(USER_DIR + username);*/

    char *username = "Testuser";
    printf(
        #include "body_index.templ"
    );


    return 0;

}

int handle_post(state_t *state) {

    printf("%s", get_val(state, "route"));

}

int cookie_write(state_t *state, char *key, char *val) {

    int cf = cookie_file(state->cookie);

}

#define O_WRONLY	     01
#define O_CREAT	   0100	/* Not fcntl.  */
#define O_EXCL		   0200	/* Not fcntl.  */
#define S_IWUSR	0200	/* Write by owner.  */
#define	S_IRUSR	0400	/* Read by owner.  */

#define	EEXIST		17	/* File exists */

int user_create(char *name, char *pass_hash) {

    char user_file[1032];
    sprintf(user_file, USER_DIR"%s", name);

/*Should be reasonably atomic, see https://stackoverflow.com/questions/230062/whats-the-best-way-to-check-if-a-file-exists-in-c*/
    int fd = open(user_file, O_CREAT | O_WRONLY | O_EXCL, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        /* failure */
        /*if (errno == EEXIST) {
            /* the file probably already existed */
            return 0;
        /*}*/
    } else {
        fprintf(fd, "name=%s\npass_hash=%s\n", name, pass_hash);
    }
}

int handle_register(state_t *state) {
    char *name = dup_alphanumeric(get_val(state, "name"));
    cookie_write(state, "logged_in", "0");
    cookie_write(state, "name", name);
    char *pass_hash = get_val(state, "password");
    if (!user_create(name, pass_hash)) {
        printf("<h1>Sorry, username taken!</h1>");
        exit(1);
    }
    state->user = name;
    cookie_write(state, "logged_in", "1");
}


char *get_user_val(state_t *state, char *key) {
    /* TODO */
}

int cookie_remove(state) {
    /* todo */
}

int handle_login(state_t *state) {

    char *name = get_val(state, "name");
    cookie_write(state, "name", name);
    char **read_user_kv(name);
    char *login_pw_hash = hash(get_val(state, "password"));
    char *stored_pw_hash = get_user_val(state, "pass_hash");
    if (!strcmp(login_pw_hash, stored_pw_hash)) {
        cookie_write(state, "logged_in", "true");
    } else {
        cookie_remove(state);
    }
}

char *run(char *cmd, char *param) {

    param = dup_alphanumeric(param);
    char command[1024];

    sprintf(command, cmd, param);
    free(param);

    FILE *fp;
    char path[1035];

    /* Open the command for reading. */
    fp = popen(command, "r");
    if (fp == _NULL) {
        perror("Python hashing");
        exit(1);
    }

    char *ret = readline(fp);
    ret[strlen(ret)-2] = 0; /* strip newline */

    pclose(fp);

    return ret;

}

int hash(char *to_hash) {

    char *hash = run(
        "python3 -c 'print(__import__(\"hashlib\").sha256(b\"%s\").hexdigest())'",
        to_hash
    );

    return hash;

}
