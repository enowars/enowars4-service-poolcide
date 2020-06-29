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
    fprintf(stderr, x); \
    fflush(stderr);     \
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

#define ROUTE(method_name, route_name)        \
  if (!strcmp(state->method, #method_name) && \
      !strcmp(state->route, #route_name)) {   \
                                              \
    handle_##route_name(state);               \
    handled = 1;                              \
                                              \
  }

#define IS_GET (!strcmp(state->method, "GET"))
#define IS_POST (!strcmp(state->method, "POST"))

/* 0-9A-Za-z */
#define IS_ALPHANUMERIC(c)                                   \
  (((c) >= '0' && (c) <= '9') || ((c) >= 'A' && c <= 'Z') || \
   ((c) >= 'a' && (c) <= 'z'))

/* Templating in C is eas-C */
#define TEMPLATE(x) #x

char empty_list[2][2] = {0};

typedef struct state {

  char *cookie;
  char *nonce;

  char *username;

  char *user_loc;
  char *cookie_loc;

  char *method;
  char *route;

  int logged_in;

  char **queries[QUERY_COUNT];

} state_t;

/* Sane sourcecode STARTS with main. Why would anybody read from bottom to top?
 */

int main() {

/* run tests using
   make CFLAGS='-DTEST_RAND'
*/
#if defined(TEST_RAND)

  printf("testing strlen of rand_str(16)\n");
  assert(strlen(rand_str(16)) == 16);
  printf("testing alphanumericity of rand_str(16)\n");
  char *rand = rand_str(1);
  assert(IS_ALPHANUMERIC(rand[0]));
  printf("%s\n", rand_str(16));
  return 0;

#elif defined(TEST_COOKIE_PARSER)

  parse_cookie("cookie");
  printf(parse_cookie(COOKIE_NAME "=testcookie;"));
  assert(!strcmp(parse_cookie(COOKIE_NAME "=testcookie;"), "testcookie"));
  assert(!strcmp(parse_cookie(COOKIE_NAME "=testcookie; "), "testcookie"));
  assert(
      !strcmp(parse_cookie("test=fun; HTTPOnly; " COOKIE_NAME "=testcookie; "),
              "testcookie"));
  return 0;

#elif defined(TEST_QUERY_PARSER)

  int   i;
  char *parseme = "pool=side&fun=true&you're=beautiful!&&fun=";
  printf("parsing %s\n", parseme);
  char **query = parse_query(parseme);
  KV_FOREACH(query, { printf("key: %s, val: %s\n", key, val); })
  assert(parseme[1] == query[0][1]);
  return 0;

#elif defined(TEST_ALPHA)

  char *alpha = "FUN1";
  char *nonalpha1 = "%%!FUN1";
  char *nonalpha2 = "%%!";
  char *nonalpha3 = "%%!0";
  char *alpha1 = dup_alphanumeric(nonalpha1);
  printf("%s: %s", nonalpha1, alpha1);
  assert(!strcmp(alpha, alpha1));
  free(alpha1);
  return 0;

#elif defined(TEST_VAL)

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
  return 0;

#elif defined(TEST_READLINE)

  char *body = BODY();
  if (body) {

    printf("%s\n" NL, body);

  } else {

    printf("No body read\n");

  }

  return 0;

#elif defined(TEST_HASH)

  printf("%s" NL, hash("test"));
  return 0;

#elif defined(TEST_INI_FILES)

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

#elif defined(TEST_ESCAPE)

  assert(!strcmp(escape_4_html("AA"), "&#41;&#41;"));
  assert(!strcmp(escape_4_py("AA"), "\\x41\\x41"));
  return 0;

#elif defined(TEST_TOWEL_ENC)

  printf(enc_towel_id("test"));
  assert(strlen(enc_towel_id("test")));
  return 0;

#else                                                            /* No TEST */

  /* THE ACTUAL MAIN */

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

  char *cookie = "";
  KV_FOREACH(cookie_kv, {

    if (!strcmp(key, COOKIE_NAME)) {

      int i;
      cookie = val;
      for (i = 0; cookie[i]; i++) {

        if (cookie[i] == ';' || cookie[i] == ' ') {

          cookie[i] = '\0';
          break;

        }

      }

      LOG("Got cookie %s\n", cookie);

    }

  });

  state_t *state = init_state(request_method, cookie, query_string);

  write_headers(state);

  if IS_GET {                                         /* AJAX State of mind */
    write_head(state);

  }

  LOG("Started %s %s - %s %s \n", state->method, state->route, query_string,
      script_name);

  int handled = 0;

  ROUTE(GET, index);
  ROUTE(POST, login);
  ROUTE(POST, register);

  ROUTE(GET, dispense);
  ROUTE(GET, reserve);
  ROUTE(POST, reserve);

  ROUTE(GET, towel);
  ROUTE(POST, towel);
  ROUTE(PUT, towel);

  if (!handled) {

    LOG("Unknown route!\n");
    char *error = "Unsupported route or method!";
    printf(
  #include <error.templ>
    );

  }

  if IS_GET { printf(NL "</html>" NL); }

  LOG("Finished %s %s - %s %s \n", state->method, state->route, query_string,
      script_name);

  return 0;

#endif

}

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

    /*LOG("%d %c %s", written, str[i], ret);*/
    written += sprintf(ret + written, replace, (unsigned char)str[i]);
    /*sprintf(ret + (i * replace_len), replace, str[i]);*/

  }

  LOG("\n");

  return ret;

}

/* char * */
#define E4(name, replace)          \
  int escape_4_##name(char *str) { \
                                   \
    return escape(replace, str);   \
                                   \
  }

E4(py, "\\x%2x")
E4(html, "&#x%2x;")
E4(hash, "%2x")

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
  if (!content_len) { return empty_list; }

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

      LOG("Outputting %s=%s\n", key, val);

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
  LOG("Setting %s to %s, Read:\n", key_to_write, val_to_write);
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

    /*LOG("p: %d %p\n"NL, i, state->queries[i]);*/
    if (!state->queries[i]) { state->queries[i] = parse_query(BODY()); }

    if (!state->queries[i]) { return _NULL; }
    /*LOG("query: %s\n"NL, state->queries[i]);*/
    KV_FOREACH(state->queries[i], {

      /*LOG("tofind: %s - %s %s\n", key_to_find, key, val);*/
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
      "Content-Security-Policy: script-src 'nonce-%s'; style-src 'nonce-%s'"
      " https://fonts.googleapis.com/css2?family=Lobster&display=swap;" NL
      "X-Frame-Options: SAMEORIGIN" NL "X-Xss-Protection: 1; mode=block" NL
      "X-Content-Type-Options: nosniff" NL
      "Referrer-Policy: no-referrer-when-downgrade" NL
      "Feature-Policy "
      "geolocation 'self'; midi 'self'; sync-xhr 'self'; microphone 'self'; "
      "camera 'self'; magnetometer 'self'; gyroscope 'self'; speaker 'self'; "
      "fullscreen *; payment 'self';" NL "Content-Type: text/html" NL

      "Set-Cookie: " COOKIE_NAME "=%s; HttpOnly" NL NL,
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
int init_state(char *request_method, char *current_cookie, char *query_string) {

  int      i;
  state_t *state = calloc(sizeof(state_t), 1);

  if (!request_method || !request_method[0]) {

    LOG("No request method provided. Assuming GET\n");
    state->method = "GET";

  } else {

    state->method = request_method;

  }

  char *new_cookie = dup_alphanumeric(current_cookie);
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

  state->logged_in = !strcmp(cookie_get_val(state, "logged_in", "0"), "1");
  LOG("User is%s logged in.\n", state->logged_in ? "" : " not");

  if (state->logged_in) {

    state->username = cookie_get_val(state, "username", _NULL);

  }

  if (state->username) {

    LOG("User %s is back!\n", state->username);
    state->user_loc = loc_user(state->username);

  } else {

    state->username = "New User";

  }

  state->nonce = rand_str(16);

  maybe_prune(state, COOKIE_DIR);
  maybe_prune(state, USER_DIR);

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

  if (!cookies) { return _NULL; }
  int content_len = strlen(cookies);
  if (!content_len) { return _NULL; }

  char *contents = strdup(cookies);
  int   parsing_key = 1;
  int   current_len = 0;
  char *current_key = contents;
  char *current_val = _NULL;
  int   val_count = 0;

  /* Strip tailing newline */
  if (contents[content_len - 1] == '\n') {

    content_len = content_len - 1;
    contents[content_len] = '\0';

  }

  for (i = 0; i < content_len; i++) {

    if (contents[i] == ';') {

      contents[i] = '\0';
      if (parsing_key) {

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

int handle_index(state_t *state) {

  /*int cf = cookie_file(cookie);*/
  /*read_ini(USER_DIR + username);*/

  char *username = state->username;
  int   logged_in = state->logged_in;

  printf(
#include "body_index.templ"
  );

  return 0;

}

char **split(char *str, char splitter) {

  int i;

  if (!str) { return empty_list; }
  int len = strlen(str);
  if (!len) { return empty_list; }
  char **ret = calloc(sizeof(char *), len / 2);
  int    pos = 0;
  ret[pos] = str;
#define CURRENT_ITEM ret[pos]
  for (i = 0; str[i]; i++) {

    if (str[i] == splitter) {

      str[i] = '\0';
      if (strlen(ret[pos])) {

        /* LOG("Found element:: %s\n", CURRENT_ITEM); */
        pos++;

      }

      CURRENT_ITEM = str + i + 1;

    }

  }

#undef CURRENT_ITEM
  if (!strlen(ret[pos])) {

    ret[pos] = _NULL;
    pos--;

  }

  LOG("Split item count for %s: %d\n", str, pos);
  return ret;

}

char **own_towel_list(state_t *state) {

  int i;

  char *own_towels = get_user_val(state, "towels", "");
  LOG("User towels: %s\n", own_towels);
  return split(own_towels, '/');

}

int ls(state_t *state, char *dir) {

  int i;

  /* prune all 256 requests */
  maybe_prune(state, dir);
  /* using forward slash as divider = never a valid unix filename */
  char *list_str = run("ls '%s' | tr '\\n' '/'", dir);
  return split(list_str, '/');

}

int maybe_prune(state_t *state, char *dir) {

  if (state->nonce[0] == 'A') { prune(dir); }

}

int prune(char *dir) {

  LOG("Pruning all files in %s older than 15 minutes\n", dir);
  LOG(run("find '%s' -mmin +15 -type f -not -name .gitkeep -exec rm -fv {} \\;",
          dir));

}

int render_own_towels(state_t *state) {

  int i;

  char **towel_list = own_towel_list(state);
  if (!towel_list || !towel_list[0]) { return ""; }
  return render_towel_template(state, towel_list);

}

int render_all_towels(state_t *state) {

  int i;

  char **towel_list = ls(state, TOWEL_DIR);
  return render_towel_template(state, towel_list);

}

int render_towel_template(state_t *state, char **towel_list) {

  int    i;
  char **priority_towels = ls(state, PRIORITY_TOWEL_DIR);

  char *ret = calloc(1, 16384);
  int   retpos = 0;

#define CURRENT_TOWEL towel_list[i]
  for (i = 0; CURRENT_TOWEL && i < 1024; i++) {

    int   k;
    int   priority_towel = 0;
    char *towel_name = CURRENT_TOWEL;
    for (k = 0; priority_towels[k]; k++) {

      /*  LOG("Priority towel %s\n", priority_towels[k]); */

      if (!strcmp(towel_name, priority_towels[k])) {

        LOG("Towel %s is a priority towel\n", towel_name);
        priority_towel = 1;
        break;

      }

    }

    /* LOG("Current towelname: %s, ret: %s @%p-%p\n", towel_name, ret, ret, ret
     * + retpos); */

    retpos += sprintf(ret + retpos,
#include <towel.templ>
    );

  }

#undef CURRENT_TOWEL

  return ret;

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
int user_create(char *name, char *pass) {

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

    char *pass_hash = hash(pass);
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
  char *pass = get_val(state, "password");
  if (!user_create(username, pass)) { goto invalid_username; }
  state->username = username;
  state->user_loc = loc_user(state->username);
  cookie_set_val(state, "logged_in", "1");
  printf("success");
  return 0;
invalid_username:
  /* TODO Template? */
  printf("<h1>Sorry, username taken!</h1>");
  trigger_gc(1);
  exit(1);
  return -1;

}

/* char * */
int get_user_val(state_t *state, char *key, char *default_val) {

  return file_get_val(state->user_loc, key, default_val);

}

/* char * */
int set_user_val(state_t *state, char *key, char *val) {

  return file_set_val(state->user_loc, key, val);

}

int cookie_remove(state) {

  LOG("Removing cookie");
  file_delete(((state_t *)state)->cookie_loc);

}

int handle_login(state_t *state) {

  LOG("Logging in...\n");
  cookie_set_val(state, "logged_in", "0");
  char *username = dup_alphanumeric(get_val(state, "username"));
  LOG("Login started for user %s\n", username);
  if (strlen(username) < 1) { goto user_not_found; }
  state->user_loc = loc_user(username);
  cookie_set_val(state, "username", username);
  char *login_pw_hash = hash(get_val(state, "password"));
  LOG("Password hash: %s\n", login_pw_hash);
  char *stored_pw_hash = get_user_val(state, "pass_hash", _NULL);
  if (!stored_pw_hash) { goto user_not_found; }
  if (!strcmp(login_pw_hash, stored_pw_hash)) {

    LOG("Login successful for user %s", username);
    cookie_set_val(state, "logged_in", "1");
    printf("success");
    return 0;

  }

user_not_found:
  LOG("Login failed for user %s. Expected pw hash %s (len %d) but got (len %d)", username, stored_pw_hash, strlen(stored_pw_hash), strlen(login_pw_hash));
  printf(
#include "user_not_found.templ"
  );

error:
  cookie_remove(state);
  trigger_gc(1);
  exit(1);

}

/* char * */
int run(char *cmd, char *param) {

  int i;
  char command[1024];

  sprintf(command, cmd, param);

  LOG("Running %s\n", command);

  FILE *fp = popen(command, "r");
  if (fp == _NULL) {

    perror("run command");
    trigger_gc(1);
    exit(1);

  }

  char *ret = readline(fp);
  pclose(fp);

  if (!ret) {

    LOG("No Return\n");
    ret = "";

  } else {

    int ret_len = strlen(ret);
    if (ret_len) {
      for (i = ret_len - 1; ret[i] == '\n' && i >= 0; i--) {
        /* strip newline endings */
        ret[i] = '\0';
      }
    }

    LOG("Return was %s\n", ret);

  }

  return ret;

}

/* char *(char *) */
int hash(to_hash) {

  char *hash = run(
      "python3 -c 'print(__import__(\"hashlib\").sha256(b\"%s\").hexdigest())'",
      escape_4_hash(to_hash));

  return hash;

}

/* char *(char *) */
int enc_towel_id(towel_id) {

  return run(
      "echo '%s'"
      "| ./age -r "
      "age1mngxnym3sz9t8jtyfsl43szh4pg070g857khq6zpw3h9l37v3gdqs2nrlx -a"
      "| tr -d '\\n'",
      towel_id);

}

int handle_reserve(state_t *state) {

  char *towel_id = rand_str(16);
  char *towel_token = rand_str(10);
  char *color = get_val(state, "color");

  char towel_space[1036];
  sprintf(towel_space, TOWEL_DIR "%s", dup_alphanumeric(towel_token));

  FILE *file = file_create_atomic(towel_space);
  if (!file) {

    perror(towel_space);
    char *error = "Sorry, towel dispensing failed. :(";
    printf(
#include <error.templ>
    );
    return 0;

  }

  fprintf(file, "%s", color);
  fclose(file);

  char *user_towels_old = get_user_val(state, "towels", "");
  char *user_towels_new = calloc(1, strlen(user_towels_old) + 10 + 2);
  /* The towels list gets separated with slashes for serialization. */
  sprintf(user_towels_new, "%s/%s", user_towels_old, towel_token);
  set_user_val(state, "towels", user_towels_new);

  char *towel_id_enc = enc_towel_id(towel_id);
  char *own_towels = render_own_towels(state);
  char *towels = render_all_towels(state);

  printf(
#include <towel_dispenser.templ>
  );
  fflush(stdout);

  char *towel_admin_id = "";
  if IS_POST {

    char *towel_admin_id = get_val(state, "towel_admin_id");

    int id_len = strlen(towel_admin_id);
    if (!id_len) {

      LOG("Empty towel admin response received. In case you expected an admin "
          "to "
          "access this towel, there may be a proxy messing up adminness.\n");
      return -1;

    }

    if (!strcmp(towel_id, towel_admin_id)) {

      LOG("An admin entered the scene!\n");
      add_priority_towel_for(state->username, towel_token);
      printf("Admin at the pool!\n");

    }

  }

}

int handle_dispense(state_t *state) {

  char *towel_id = rand_str(16);
  char *towel_token = "";
  char *color = "";

  char *towel_id_enc = enc_towel_id(towel_id);
  char *own_towels = render_own_towels(state);
  char *towels = render_all_towels(state);

  printf(
#include <towel_dispenser.templ>
  );

}

int add_priority_towel_for(char *username, char *towel_token) {

  char priority_towel_space[1036];
  sprintf(priority_towel_space, PRIORITY_TOWEL_DIR "%s",
          dup_alphanumeric(towel_token));

  FILE *file = file_create_atomic(priority_towel_space);
  if (!file) {

    perror(priority_towel_space);

  } else {

    fclose(file);

  }

}

int handle_towel(state_t *state) {

  int    i;
  char **towels = own_towel_list(state);
  char * towel = get_val(state, "token");
  for (i = 0; towels[i]; i++) {

    if (!strcmp(towel, towels[i])) {

      char *username = state->username;
      char *color = escape_4_html(get_towel_color(towel));
      printf(
#include <towel_details.templ>
      );
      return 0;

    }

  }

  LOG("User %s does not posess towel %s\n", state->username, towel);
  char *error =
      "Don't steal somebody elses towel, please. We're on holidays!.\n";
  printf(
#include <error.templ>
  );

}

int get_towel_color(char *towel) {

  char  towelpath[1036];
  char *color = calloc(1, 4096);
  sprintf(towelpath, TOWEL_DIR "%s", towel);
  LOG("Reading color from towel at %s\n");
  FILE *file = fopen(towelpath, "r");
  fread(color, 1, 4096, file);
  fclose(file);
  return color;

}

