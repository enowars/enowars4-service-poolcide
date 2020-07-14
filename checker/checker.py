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
        random.shuffle(cookies)
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
        return secrets.choice(users) + hex(secrets.randbelow(256))[2:]

    def random_password(self) -> str:
        return self.random_string(16)

    def parse_cookie(self, response: Union[bytes, str]) -> str:
        response = ensure_unicode(response)
        try:
            cookie = (
                response.split("Set-Cookie:")[1].split("poolcode=")[1].split(";")[0]
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
        with self.connect() as t:
            http = build_http(
                method="POST",
                query_params={"route": route},
                cookies={"poolcode": cookie},
                body_params={"username": username, "password": password, "csrf": csrf},
            )
            self.debug(f"Sending request: {http}")
            t.write(http)
            resp = ensure_unicode(t.read_all())
            self.debug(f"Got response: {resp}")
            new_cookie = self.parse_cookie(resp)

            assert_equals(cookie, new_cookie)

            if "success" not in resp:
                self.error(f"No success response, instead got {resp}")
                raise BrokenServiceException("Login failed")
            self.info(f"Got cookie {cookie}")
            return resp, cookie, csrf

    def login(
        self, cookie: str, csrf: str, username: str, password: str
    ) -> Tuple[str, str, str]:
        return self.user_request("login", cookie, csrf, username, password)

    def register(
        self, cookie: str, csrf: str, username: str, password: str
    ) -> Tuple[str, str, str]:
        return self.user_request("register", cookie, csrf, username, password)

    def reserve(self, cookie: str, as_admin: bool) -> None:
        color_string = urllib.parse.quote(self.flag)
        with self.connect() as t:
            http = build_http(
                method="GET",
                query_params={"route": "dispense"},
                cookies={"poolcode": cookie},
            )
            self.debug(f"request for dispense: {http}")
            t.write(http)
            resp = ensure_unicode(t.read_all())
            self.debug(f"response for dispense was {resp}")

        try:
            csrf = resp.split('name="csrf" value="')[1].split('"')[0]
        except Exception as ex:
            self.warning(f"Could not read csrf token: {ex}")
            raise BrokenServiceException("No csrf token found in route=dispense")

        # POST has a special handling, waiting for the admin key in the body.
        method = "POST" if as_admin else "GET"
        with self.connect() as t:
            http = build_http(
                method=method,
                query_params={"route": "reserve"},
                params={"color": color_string, "csrf": csrf},
                cookies={"poolcode": cookie},
            )
            t.write(http)
            stuff = t.read_until("<code>")
            if b"admin" not in stuff:
                raise BrokenServiceException(f"No valid answer from reserve {method}")

            content = t.read_until("</body>")
            content = content.decode()[:-1]

            try:
                self.debug(f"reserve page content is {content}")
                towel_id = content.split("ID ")[1].split(" and")[0]
                self.info(f"Got towel id {towel_id}")
                # Storing towel_token
                self.team_db[self.flag + "_towel"] = towel_id
            except Exception as ex:
                self.warning(ex)
                raise BrokenServiceException("Could not get Towel ID")

            if not as_admin:
                return
            age_begin = "-----BEGIN AGE ENCRYPTED FILE-----"
            age_end = "-----END AGE ENCRYPTED FILE-----"
            age_line_len = 64
            try:
                line = content.split(age_begin)[1].split(age_end)[0]
            except Exception as ex:
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
            all = t.read_all()
            if not b"Admin at the pool" in all:
                self.warning(f"Didn't find admin info in {all}")
                raise BrokenServiceException(
                    "Could not Administer Towels at the Poolcide."
                )

    def get_towel(self, cookie: str, towel_token: str):
        with self.connect() as t:
            self.debug(
                f"Getting flag with towel_token {towel_token.strip()} and cookie {cookie}"
            )
            t.write(
                f"GET /cgi-bin/poolcide/poolcide?route=towel&token={towel_token.strip()}\r\nCookie: poolcode={cookie}\r\n\r\n"
            )
            resp = t.read_all()
            self.debug(f"Got return {resp}")
            return resp.decode()

    def putflag(self) -> None:
        user = self.random_user()
        password = self.random_password()
        self.team_db[self.flag] = {"user": user, "password": password}
        self.info(f"Random username: {user}, random password {password}")
        resp, cookie, csrf = self.request_index()
        self.info("trying to log in")
        resp, cookie, csrf = self.register(cookie, csrf, user, password)
        self.info(f"Logged in as {user}")

        self.reserve(cookie, as_admin=True)

    def getflag(self) -> None:
        try:
            user = self.team_db[self.flag]["user"]
            password = self.team_db[self.flag]["password"]
            towel_token = self.team_db[self.flag + "_towel"]
        except Exception as ex:
            self.error("Could not get user, password or towlid from db: {ex}")
            raise BrokenServiceException(
                "No stored credentials from putflag in getflag"
            )

        resp, cookie, csrf = self.request_index()

        resp, cookie, csrf = self.login(cookie, csrf, user, password)
        resp = self.get_towel(cookie, towel_token)
        try:
            escaped_flag = resp.split('<code id="color">')[1].split("</code>")[0]
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
        with self.connect() as sock:
            sock.write(req)
            indexresp = ensure_unicode(sock.read_all())
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
        resp, cookie, csrf = self.request_index()
        self.info("trying to log in")
        resp, cookie, csrf = self.register(cookie, csrf, user, password)
        self.info(f"Logged in as {user}")

        self.team_db[self.flag] = {"user": user, "password": password, "cookie": cookie}

        self.reserve(cookie, as_admin=False)

    def getnoise(self) -> None:
        try:
            user = self.team_db[self.flag]["user"]
            password = self.team_db[self.flag]["password"]
            cookie = self.team_db[self.flag]["cookie"]
            towel_token = self.team_db[self.flag + "_towel"]
        except Exception as ex:
            self.error("Could not get user, password or towlid from db: {ex}")
            raise BrokenServiceException(
                "No stored credentials from putflag in getflag"
            )

        if self.flag_idx % 2:
            cookies = {"poolcode": cookie}
            resp, cookie, csrf = self.request_index(cookies)
            assert_equals(cookie, cookies["poolcode"])
        else:
            # do a fresh login.
            resp, cookie, csrf = self.request_index()
            resp, cookie, csrf = self.login(cookie, csrf, user, password)
        resp = self.get_towel(cookie, towel_token)
        try:
            escaped_flag = resp.split('<code id="color">')[1].split("</code>")[0]
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

    def exploit(self) -> None:
        # Step 1: get all available admin ids
        user = self.random_user()
        password = self.random_password()
        self.info(f"Random username: {user}, random password {password}")
        resp, cookie, csrf = self.request_index()
        self.info("trying to log in")
        resp, cookie, csrf = self.register(cookie, csrf, user, password)
        self.info(f"Logged in as {user}")

        with self.connect() as t:
            http = build_http(
                method="GET",
                query_params={"route": "dispense"},
                cookies={"poolcode": cookie},
            )
            self.debug(f"request for dispense: {http}")
            t.write(http)
            resp = ensure_unicode(t.read_all())
            self.debug(f"response for dispense was {resp}")
            self.error("finish exploit...")


app = PoolcideChecker.service

if __name__ == "__main__":
    run(PoolcideChecker)
