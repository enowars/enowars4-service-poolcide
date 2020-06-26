/*#include "list.h"*/

#define RAND_LENGTH (16)
#define _NULL ((void *)0)
#define PFATAL(x)   \
  do {              \
                    \
    perror(x);      \
    fflush(stdout); \
    fflush(stderr); \
    abort();        \
                    \
  } while (0);

#define FATAL(x...) \
  do {              \
                    \
    LOG(x);         \
                    \
  }                 \
  fflush(stdout);   \
  fflush(stderr);   \
  abort();          \
                    \
  }                 \
  while (0)         \
    ;

#define LOG(x...)       \
  do {                  \
                        \
    dprintf(2, x); \
                        \
  } while (0);

#define FILE void
#define INI_LEN_MAX (256)
#define DELIM ('=')
#define KV_SPLIT ('&')
#define KV_START ('?')
#define COOKIE_NAME "poolcode"
#define NL "\r\n"
#define QUERY_COUNT (32)
#define COOKIE_LEN (64)

#define STORAGE_DIR "../../data/"
#define COOKIE_DIR STORAGE_DIR "cookies/"
#define DATA_DIR STORAGE_DIR "data/"
#define USER_DIR STORAGE_DIR "users/"
#define TOWEL_DIR STORAGE_DIR "towels/"
#define PRIORITY_TOWEL_DIR STORAGE_DIR "priority_towels/"

#define O_WRONLY 01
#define O_CREAT 0100                                         /* Not fcntl.  */
#define O_EXCL 0200                                          /* Not fcntl.  */
#define S_IWUSR 0200                                    /* Write by owner.  */
#define S_IRUSR 0400                                     /* Read by owner.  */

extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;

#define BODY() readline(0)
#define FILE_NEXT() readline(file)

#define KV_FOREACH(kv, block)              \
  do {                                     \
                                           \
    int    idx = 0;                        \
    int    key_idx = 0;                    \
    int    val_idx = 1;                    \
    char **cur = (kv);                     \
    char * key, *val;                      \
    while (cur[key_idx] && cur[val_idx]) { \
                                           \
      key = cur[key_idx];                  \
      val = cur[val_idx];                  \
      {block};                             \
      idx++;                               \
      key_idx += 2;                        \
      val_idx += 2;                        \
                                           \
    }                                      \
                                           \
  } while (0);

#define FILE_KV_FOREACH(filename, block)            \
  do {                                              \
                                                    \
    FILE *file = fopen(filename, "r");              \
    if (!file) { PFATAL("Couldn't open kv file"); } \
    do {                                            \
                                                    \
      char **query = parse_query(FILE_NEXT());      \
      if (!query) { break; }                        \
      KV_FOREACH(query, {block});                   \
                                                    \
    } while (1);                                    \
                                                    \
                                                    \
    fclose(file);                                   \
                                                    \
  } while (0);

/* 0-9A-Za-z */
#define IS_ALPHANUMERIC(c) (((c) >= '0' && (c) <= '9') || ((c) >= 'A' && c <= 'Z') || ((c) >= 'a' && (c) <= 'z'))

/* Templating in C is eas-C */
#define TEMPLATE(x) #x

typedef struct state {

  char *cookie;
  char *nonce;

  char *username;

  char *user_loc;
  char *cookie_loc;

  char *route;

  int logged_in;

  char **queries[QUERY_COUNT];

} state_t;

/* Sane sourcecode STARTS with main. Why would anybody read from bottom to top? */

/* run tests using
   make CFLAGS='-DTEST_RAND'
*/
#if defined(TEST_RAND)
int main() {

  printf("testing strlen of rand_str(16)\n");
  assert(strlen(rand_str(16)) == 16);
  printf("testing alphanumericity of rand_str(16)\n");
  char *rand = rand_str(1);
  assert(IS_ALPHANUMERIC(rand[0]));
  printf("%s\n", rand_str(16));
  return 0;

}
#elif defined(TEST_COOKIE_PARSER)
int main() {

  parse_cookie("cookie");
  printf(parse_cookie(COOKIE_NAME"=testcookie;"));
  assert(!strcmp(parse_cookie(COOKIE_NAME"=testcookie;"), "testcookie"));
  assert(!strcmp(parse_cookie(COOKIE_NAME"=testcookie; "), "testcookie"));
  assert(!strcmp(parse_cookie("test=fun; HTTPOnly; "COOKIE_NAME"=testcookie; "), "testcookie"));
  return 0;

}


#elif defined(TEST_QUERY_PARSER)
int main() {

  int   i;
  char *parseme = "pool=side&fun=true&you're=beautiful!&&fun=";
  printf("parsing %s\n", parseme);
  char **query = parse_query(parseme);
  KV_FOREACH(query, { printf("key: %s, val: %s\n", key, val); })
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

  system("mkdir -p " COOKIE_DIR);
  system("mkdir -p " USER_DIR);
  state_t *state = init_state(_NULL, _NULL);
  char *   testval = get_val(state, "test");
  if (!testval) {

    printf("No val read!");
    return 0;

  }

  printf("%s\n", testval);
  printf("%s\n", get_val(state, "test"));

}

#elif defined(TEST_READLINE)
int main() {

  char *body = BODY();
  if (body) {

    printf("%s\n" NL, body);

  } else {

    printf("No body read\n");

  }

  return 0;

}

#elif defined(TEST_HASH)
int main() {

  printf("%s" NL, hash("test"));
  return 0;

}

#elif defined(TEST_INI_FILES)
int main() {

  char *testfile = "testfile.tmp";
  char *key = "testkey";
  char *val = "testval";
  char *val2 = "testval2";
  file_delete(testfile);
  FILE *f = file_create_atomic(testfile);
  fclose(f);
  file_set_val(testfile, key, val);

  char *read_val = file_get_val(testfile, key, "");
  assert(!strcmp(val, read_val));

  file_set_val(testfile, "some", "value");
  file_set_val(testfile, key, val2);
  file_set_val(testfile, "someother", "value");
  system("cat testfile.tmp");
  read_val = file_get_val(testfile, key, "");
  assert(strcmp(val, read_val));
  assert(!strcmp(val2, read_val));

  file_delete(testfile);

  printf("testing empty ini. Query should be empty:\n");
  fflush(stdout);
  FILE *file = file_create_atomic(testfile);
  assert(file);
  debug_print_query(read_ini(testfile));
  assert(!file_get_val(testfile, "test", _NULL));
  remove(testfile);

  return 0;

}

#elif defined(TEST_ESCAPE)
int main() {

  assert(!strcmp(escape_4_html("AA"), "&#41;&#41;"));
  assert(!strcmp(escape_4_py("AA"), "\\x41\\x41"));
  return 0;

}
#elif defined(TEST_TOWEL_ENC)
int main() {
  
  printf(enc_towel_id("test"));
  assert(strlen(enc_towel_id("test")));
  return 0;
}

#else                                                            /* No TEST */

/* THE MAIN */

int main() {

  #ifdef RELEASE
  alarm(15);
  #endif

  /*https://www.openroad.org/cgi-bin/cgienvdemo*/
  char *current_cookies = getenv("HTTP_COOKIE");
  char *request_method = getenv("REQUEST_METHOD");
  char *query_string = getenv("QUERY_STRING");
  /* Webserver name to this binary */
  char *script_name = getenv("SCRIPT_NAME");

  char **cookie_kv = parse_query(current_cookies);

  state_t *state = init_state(current_cookies, query_string);
  write_headers(state);

  /* header end */
  printf(NL);

  write_head(state);

  if (!request_method) {

    /* Debug Mode */
    request_method = "GET";

  }

  LOG("%s %s - %s %s \n", request_method, state->route, query_string, script_name);

  if ((request_method && !strcmp(request_method, "GET")) ||
      !strcmp(state->route, "")) {

    handle_get(state);

  } else if (request_method && !strcmp(request_method, "POST")) {

    handle_post(state);

  } else if (request_method && !strcmp(request_method, "TEST")) {

    printf("TEST" NL);
    trigger_gc(0);
    exit(0);

  } else {

    printf("Unsupported method %s" NL, request_method);
    return -1;

  }

  printf(NL "</html>" NL);

  return 0;

}

#endif


void assert(int condition) {

  if (!condition) {

    LOG("Assert failed :/\n");
    fflush(stdout);
    trigger_gc(1);
    exit(1);

  }

}

/* Frees all memory we no longer need */
int trigger_gc(code) {

  exit(code);

}

/* The os will free our memory. */
const char *__asan_default_options() {

  /* The os will free our memory. */
  return "detect_leaks=0";

}

char *escape(char *replace, char *str) {

  int i;
  int len = strlen(str);
  int written = 0;
  /* all the right values for all the wrong reasons */
  int   replace_len = ((strlen(replace) + 2));
  char *ret = calloc(1, len * replace_len);
  /* printf("len %d, replen %d, rep %s, str %s, ptr %p\n", len, replace_len,
   * replace, str, ret); */
  for (i = 0; i < len; i++) {

    printf("%d %c %s\n", written, str[i], ret);
    fflush(stdout);
    written += sprintf(ret + written, replace, str[i]);
    /*sprintf(ret + (i * replace_len), replace, str[i]);*/

  }

  return ret;

}

/* char * */
#define E4(name, replace)            \
  int escape_4_##name(char *str) { \
                                     \
    return escape(replace, str);     \
                                     \
  }

E4(py, "\\x%2x")
E4(html, "&#%2x;")

/* FILE *(char *) */
int file_create_atomic(filename) {

  int fd = open(filename, O_CREAT | O_WRONLY | O_EXCL, S_IRUSR | S_IWUSR);
  if (fd < 0) {

    perror(filename);
    return _NULL;

  }
  fprintf(stderr, "Created file: %s\n", filename);

  return fdopen(fd, "w");

}

/* A random char in 0-9A-Za-z */
char get_rand_alphanumberic() {

  char ret = 0;
  if (!getrandom(&ret, 1, 0)) { PFATAL("Couldn't get random"); }
  if (IS_ALPHANUMERIC(ret)) { return ret; }
  return get_rand_alphanumberic();

}

/* A new string with only alphanumeric chars.
   The others are stripped. */
/* char * */
int dup_alphanumeric(char *str) {

  int i;
  int retpos = 0;
  if (!str) { return _NULL; }
  char *ret = calloc(1, 1024);
  for (i = 0; str[i]; i++) {

    if (IS_ALPHANUMERIC(str[i])) { ret[retpos++] = str[i]; }

  }

  return ret;

}

/* returns a random string with the given length */
/* char * */
int rand_str(len) {

  int   i;
  char *ret = calloc(2, len);
  if (!ret) { PFATAL("calloc") };
  for (i = 0; i < len; i++) {

    ret[i] = get_rand_alphanumberic();

  }

  return ret;

}

/* reads a line */
/* char *(FILE *) */
int readline(f) {

  char buf[1024];
  if (!(!f ? gets(buf) : fgets(buf, sizeof(buf), f))) {

    /* Looks like EOF to me */
    return _NULL;

  }

  char *ret = malloc(strlen(buf) + 1);
  strcpy(ret, buf);
  return ret;

}

/* char **(char *) */
int parse_query(str) {

  int i;

  if (!str) { return _NULL; }
  int content_len = strlen(str);
  if (!content_len) { 
    static char *empty[2] = {0};
    return empty; 
  }
  char **ret = calloc(1, (content_len)*4 + 8);
  char * contents = strdup(str);
  int    parsing_key = 1;
  int    current_len = 0;
  ret[0] = contents;
  int val_count = 0;

  /* Strip tailing newline */
  if (contents[content_len - 1] == '\n') {

    content_len = content_len - 1;
    contents[content_len] = '\0';

  }

  /* parse */
  for (i = 0; i < content_len; i++) {

    /* TODO: Use this in checker to fingerprint */
    if (!contents[i]) {

      ret[++val_count] = "";
      return ret;

    } else if ((contents[i] == (parsing_key ? DELIM : KV_SPLIT)) &&

               current_len) {

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

/* char ** */
int read_ini(char *filename) {

  int    i;
  int    ini_pos = 0;
  int    key_exists;
  char **ini = calloc(1, 256);
  char * keys[128] = {0};
  int    linec = 0;

  FILE_KV_FOREACH(filename, {

    key_exists = 0;
    for (i = 0; keys[i]; i++) {

      if (!strcmp(key, keys[i])) { key_exists = 1; }

    }

    if (!key_exists) {

      ini[ini_pos++] = key;
      ini[ini_pos++] = val;

    }

  });

  return ini;

}

void write_ini(char *filename, char **ini) {

  int   i;
  int   key_exists;
  char *keys[128] = {0};
  int   linec = 0;
  FILE *file = fopen(filename, "w");
  if (!file) { PFATAL("Couldn't open ini file"); }
  KV_FOREACH(ini, {

    key_exists = 0;
    for (i = 0; keys[i]; i++) {

      if (!strcmp(key, keys[i])) { key_exists = 1; }

    }

    if (!key_exists) {

      fprintf(stdout, "Outputting %s=%s\n", key, val);

      if (fprintf(file, "%s=%s\n", key, val) < 0) {

        perror("Writing ini");
        trigger_gc(1);
        exit(1);

      }

      keys[i] = key;

    }

  });

  fclose(file);

}

void debug_print_query(char **query) {

  fprintf(stderr, "---> Query:\n");
  KV_FOREACH(query, { fprintf(stderr, "%s=%s\n", key, val); });
  fprintf(stderr, "<--- EOQ\n");
  fflush(stderr);

}

#define LOC(name, DIR)                  \
  char *loc_##name(char *locname) {     \
                                        \
    char *loc = calloc(1, 1032);        \
    sprintf(loc, "%s%s", DIR, locname); \
    return loc;                         \
                                        \
  }

LOC(cookie, COOKIE_DIR)
LOC(user, USER_DIR)

/* char ** */
int file_set_val(char *filename, char *key_to_write, char *val_to_write) {

  char * keycpy = strdup(key_to_write);
  char * valcpy = strdup(val_to_write);
  char **ini = read_ini(filename);
  printf("Setting %s to %s, Read:\n", key_to_write, val_to_write);
  int wrote_val = 0;
  int last_idx = -1;
  KV_FOREACH(ini, {

    if (!strcmp(key, keycpy)) {

      ini[val_idx] = valcpy;
      wrote_val = 1;

    }

    last_idx = val_idx;

  });

  if (!wrote_val) {

    ini[last_idx + 1] = keycpy;
    ini[last_idx + 2] = valcpy;

  } else {

    free(keycpy);

  }

  write_ini(filename, ini);
  return 0;

}

/* char * */
int get_val(state_t *state, char *key_to_find) {

  int i;

  for (i = 0;; i++) {

    /*printf("p: %d %p"NL, i, state->queries[i]);*/
    if (!state->queries[i]) { state->queries[i] = parse_query(BODY()); }

    if (!state->queries[i]) { return _NULL; }
    KV_FOREACH(state->queries[i], {

      /*printf("%s %s\n", key, key_to_find);*/
      if (!strcmp(key, key_to_find)) { return val; }

    });

  }

  dprintf(2, "Getval without return should never be reached\n");
  assert(0);

}

/* char * */
int file_get_val(char *filename, char *key_to_find, char *default_val) {

  char **ini = read_ini(filename);
  KV_FOREACH(ini, {

    if (!strcmp(key, key_to_find)) { return val; }

  });

  return default_val;

}

int write_headers(state_t *state) {

  printf(
      /* TODO: Use CSP Nonce */
      "Content-Security-Policy: script-src 'nonce-%s'; style-src 'nonce-%s'" NL
      "X-Frame-Options: SAMEORIGIN" NL "X-Xss-Protection: 1; mode=block" NL
      "X-Content-Type-Options: nosniff" NL
      "Referrer-Policy: no-referrer-when-downgrade" NL
      "Feature-Policy "
      "geolocation 'self'; midi 'self'; sync-xhr 'self'; microphone 'self'; "
      "camera 'self'; magnetometer 'self'; gyroscope 'self'; speaker 'self'; "
      "fullscreen *; payment 'self';" NL

      "Content-Type: text/html" NL

      "Set-Cookie: "COOKIE_NAME"=%s; Secure; HttpOnly"NL,
      state->nonce, state->nonce, state->cookie);

  return 0;

}

int write_head(state_t *state) {

  printf(
#include <head.templ>
  );

  return 0;

}

/* state_t * */
int init_state(char *current_cookie, char *query_string) {

  int      i;
  state_t *state = calloc(sizeof(state_t), 1);
  char *   new_cookie = dup_alphanumeric(current_cookie);
  if (new_cookie && !new_cookie[0]) {

    free(new_cookie);
    new_cookie = _NULL;

  }

  if (!new_cookie) {

    /* A new browser, welcome! :) */
    new_cookie = rand_str(COOKIE_LEN);

  }

  state->cookie = new_cookie;
  state->cookie_loc = loc_cookie(state->cookie);

  FILE *file = file_create_atomic(state->cookie_loc);
  if (file) {

    fprintf(stderr, "Existing cookie %s\n", state->cookie);
    fclose(file);

  }

  state->username = cookie_get_val(state, "username", _NULL);
  if (state->username) {

    LOG("User %s is back!\n", state->username);
    state->user_loc = loc_user(state->username);

  } else {
    state->username = "New User";
  }

  state->logged_in = cookie_get_val(state, "logged_in", 0);
  LOG("User %s logged in.\n", state->logged_in ? "" : "not");

  state->nonce = rand_str(16);
  state->route = "index";

  if (query_string) {

    state->queries[0] = parse_query(query_string);
    KV_FOREACH(state->queries[0], {

      if (!strcmp(key, "route")) { state->route = val; }

    })

    if (state->route[0]) { LOG("Route: %s\n", state->route); }

  } else {

    query_string = "";

  }

  return state;

}

/* char * */
int parse_cookie(char *cookies) {

  int i;

  if (!cookies) {
    return _NULL;
  }
  int content_len = strlen(cookies);
  if (!content_len) { 
    return _NULL;
  }

  char *contents = strdup(cookies);
  int    parsing_key = 1;
  int    current_len = 0;
  char *current_key = contents;
  char *current_val = _NULL;
  int val_count = 0;

  /* Strip tailing newline */
  if (contents[content_len - 1] == '\n') {

    content_len = content_len - 1;
    contents[content_len] = '\0';

  }

  for (i = 0; i < content_len; i++) {
    if (contents[i] == ';') {
      contents[i] = '\0';
      if(parsing_key) {
        current_key = contents + i + 1;
        current_val = 0;
      } else {
        if (!strcmp(current_key, COOKIE_NAME)) {
          return dup_alphanumeric(current_val);
        }
        parsing_key = 1;
        current_key = contents + i + 1;
        current_val = _NULL;
      }
    } else if (parsing_key && contents[i] == ' ') {
      current_key = contents + i + 1;
    } else if (parsing_key && (contents[i] == DELIM || contents[i] == ' ')) {
      contents[i] = '\0';
      parsing_key = 0;
      current_val = contents + i + 1;
    }
  }
  if (!strcmp(current_key, COOKIE_NAME)) {
    return dup_alphanumeric(current_val);
  }
  return _NULL;

}

/* The Webserver Methods */

int handle_get(state_t *state) {

  /*int cf = cookie_file(cookie);*/
  /*read_ini(USER_DIR + username);*/

  char *username = state->username;
  printf(
#include "body_index.templ"
  );

  return 0;

}

int handle_post(state_t *state) {

  if (!strcmp(state->route, "dispense")) {
    handle_towel_dispenser(state);
  }

  /*TODO Handle post */
  return 0;

}

int cookie_get_val(state_t *state, char *key, char *default_val) {

  return file_get_val(state->cookie_loc, key, default_val);

}

void cookie_set_val(state_t *state, char *key, char *val) {

  file_set_val(state->cookie_loc, key, val);

}

void file_delete(char *filename) {

  remove(filename);

}

/* returns 0 on error / if :user exists */
int user_create(char *name, char *pass_hash) {

  char *user_loc = loc_user(name);
  FILE *file = file_create_atomic(user_loc);

  /*Should be reasonably atomic, see
   * https://stackoverflow.com/questions/230062/whats-the-best-way-to-check-if-a-file-exists-in-c*/
  if (!file) {

    /* failure */
    /*if (errno == EEXIST) {*/
    /* the file probably already existed */
    perror("Could not create user entry.");
    return 0;
    /*}*/

  } else {

    fprintf(file, "name=%s\npass_hash=%s\n", name, pass_hash);

  }

  fclose(file);
  return 1;

}

int handle_register(state_t *state) {

  char *username = dup_alphanumeric(get_val(state, "username"));
  if (!strlen(username)) { goto invalid_username; }
  cookie_set_val(state, "logged_in", "0");
  cookie_set_val(state, "username", username);
  char *pass_hash = get_val(state, "password");
  if (!user_create(username, pass_hash)) { goto invalid_username; }
  state->username = username;
  state->user_loc = loc_user(state->username);
  cookie_set_val(state, "logged_in", "1");
  return 0;
invalid_username:
  /* TODO Template? */
  printf("<h1>Sorry, username taken!</h1>");
  trigger_gc(1);
  exit(1);
  return -1;

}

char *get_user_val(state_t *state, char *key, char *default_val) {

  return file_get_val(state->user_loc, key, default_val);

}

int cookie_remove(state) {

  file_delete(((state_t *)state)->cookie_loc);

}

int handle_login(state_t *state) {

  cookie_set_val(state, "logged_in", 0);
  char *username = dup_alphanumeric(get_val(state, "username"));
  if (strlen(username) < 1) { goto user_not_found; }
  state->user_loc = loc_user(username);
  cookie_set_val(state, "username", username);
  char *login_pw_hash = hash(get_val(state, "password"));
  char *stored_pw_hash = get_user_val(state, "pass_hash", _NULL);
  if (!stored_pw_hash) { goto user_not_found; }
  if (!strcmp(login_pw_hash, stored_pw_hash)) {

    cookie_set_val(state, "logged_in", 1);
    prinf("success");
    return 0;

  }

user_not_found:
  printf(
#include "user_not_found.templ"
  );

error:
  cookie_remove(state);
  trigger_gc(1);
  exit(1);

}

char *run(char *cmd, char *param) {

  param = dup_alphanumeric(param);
  char command[1024];

  sprintf(command, cmd, param);
  free(param);

  LOG("Running %s\n", cmd);

  FILE *fp = popen(command, "r");
  if (fp == _NULL) {

    perror("run command");
    trigger_gc(1);
    exit(1);

  }

  char *ret = readline(fp);
  pclose(fp);

  int ret_len = strlen(ret);
  if (ret[ret_len -2] == '\n') {
    ret[ret_len - 2] = '\0';                                /* strip newline */
  }

  LOG("Response was %s\n", ret);

  return ret;

}

/* char *(char *) */
int hash(to_hash) {

  char *hash = run(
      "python3 -c 'print(__import__(\"hashlib\").sha256(b\"%s\").hexdigest())'",
      to_hash);

  return hash;

}

/* char *(char *) */
int enc_towel_id(towel_id) {
  return run(
    "echo '%s'"
    "| ./age -r age1mngxnym3sz9t8jtyfsl43szh4pg070g857khq6zpw3h9l37v3gdqs2nrlx -a"
    "| tr -d '\\n'", towel_id
  );
}

int handle_towel_dispenser(state_t *state) {
  char *towel_id = rand_str(16);
  char *towel_token = get_val(state, "towel_token");
  char *towel_color = get_val(state, "towel_color");

  char towel_space[1036];
  sprintf(towel_space, TOWEL_DIR"%s", dup_alphanumeric(towel_token));

  FILE *file = file_create_atomic(towel_space);
  if (!file) {
    perror(towel_space);
    char *error = "Sorry, towel dispensing failed. :(";
    printf(
      #include <error.templ>
    );
  }
  fclose(file);

  char *towel_id_enc = enc_towel_id(towel_id);
  printf(
    #include <towel_dispenser.templ>
  );

  char *towel_admin_id = get_val(state, "towel_admin_id");
  
  int id_len = strlen(towel_admin_id);
  if(!id_len) {
    LOG("Empty towl admin response received. In case you expected an admin to access this towl, there may be a proxy messing up adminness.\n");
    return -1;
  }
  if (!strcmp(towel_id, towel_admin_id)) {
    LOG("An admin entered the scene!\n");
    add_priority_towel_for(state->username);
  }
 
}

int add_priority_towel_for(char *username) {

  /*file_create_atomic();*/

}