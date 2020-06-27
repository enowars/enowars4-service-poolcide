#!/usr/bin/env python3
import secrets
import string
import subprocess
import html
import urllib.parse
from enochecker import BaseChecker, run, BrokenServiceException
from enochecker.utils import sha256ify

# created: 2020-06-25T23:34:03+02:00
AGE_PUBLIC_KEY = "age1mngxnym3sz9t8jtyfsl43szh4pg070g857khq6zpw3h9l37v3gdqs2nrlx"
AGE_SECRET_KEY = (
    "AGE-SECRET-KEY-1XCKQZWRQ6AH3MUZGHH29M37CF2CAC5U4TLZA9WRSTHNG9UH02LSS8FNDUY"
)

AGE_KEYFILE = "./age_key"


class PoolcideChecker(BaseChecker):
    port = 9001
    flag_count = 1
    noise_count = 1
    havoc_count = 1

    def random_string(self, len) -> str:
        return "".join(secrets.choice(string.ascii_letters) for x in range(len))

    def random_user(self) -> str:
        return self.random_string(8)

    def random_password(self) -> str:
        return self.random_string(16)

    def user_request(self, route: str, username: str, password: str) -> str:
        self.info(f"Executing {route} as user {username} with password {password}")
        with self.connect() as t:
            # TODO Change order, newlines, ...
            t.write(
                f"POST /cgi-bin/poolcide?route={route} HTTP/1.0\r\n\r\nusername={username}&password={password}\n"
            )
            resp = t.read_all()
            try:
                self.debug(resp)
                cookie = (
                    resp.split(b"Set-Cookie: ")[1].split(b"poolcode=")[1].split(b";")[0]
                )
            except Exception as ex:
                self.warning(ex)
                raise BrokenServiceException("Could not read cookie")
            if not b"success" in resp:
                self.error(f"No success response, instead got {resp}")
                raise BrokenServiceException("Login failed")
            cookie = cookie.decode()
            self.info(f"Got cookie {cookie}")
            return cookie

    def login(self, username: str, password: str) -> str:
        return self.user_request("login", username, password)

    def register(self, username: str, password: str) -> str:
        return self.user_request("register", username, password)

    def reserve_as_admin(self, cookie: str) -> None:
        # TODO
        with self.connect() as t:
            t.write(
                f"POST /cgi-bin/poolcide?route=reserve HTTP/1.0\r\nCookie: poolcode={cookie}\r\n\r\n"
                f"color={self.flag}\n"
            )
            stuff = t.read_until("<code>")
            # TODO expect more stuff
            if b"admin" not in stuff:
                raise BrokenServiceException("No valid answer from reserve POST")

            content = t.read_until("</body>")
            content = content.decode()[:-1]

            try:
                self.debug(f"reserve page content is {content}")
                towel_id = content.split("ID ")[1].split(" and")[0]
                self.info(f"Got towel id {towel_id}")
                self.team_db[self.flag + "_towel"] = towel_id
            except Exception as ex:
                self.warning(ex)
                raise BrokenServiceException("Could not get Towel ID")

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
                self.warning("Got {admin_id} (stderr {resp.stderr}) from ./age")
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
            t.write(f"GET /cgi-bin/poolcide/poolcide?route=towel&token={towel_token.strip()}\r\nCookie: poolcode={cookie}\r\n\r\n")
            resp = t.read_all()
            return resp.decode()

    def putflag(self) -> None:
        user = self.random_user()
        password = self.random_password()
        self.team_db[self.flag] = {"user": user, "password": password}
        # TODO: Check returns!
        resp = self.http_get()
        # print(resp.text)
        resp = self.http_get("/cgi-bin/poolcide?route=index")
        self.info("trying to log in")
        cookie = self.register(user, password)
        self.info("Got cookie: %s", cookie)
        self.reserve_as_admin(cookie)

    def getflag(self) -> None:
        try:
            user = self.team_db[self.flag]["user"]
            password = self.team_db[self.flag]["password"]
            towel_token = self.team_db[self.flag + "_towel"]
        except Exception as ex:
            self.error("Could not get user, password or towlid from db: {ex}")
            raise BrokenServiceException("No stored credentials from putflag in getflag")
        cookie = self.login(user, password)
        resp = self.get_towel(cookie, towel_token)
        try:
            escaped_flag = resp.split('<code id="color">')[1].split("</code>")[0]
            self.info(f"Escaped flag is {escaped_flag}")
            # Flags get url escaped on request by the browser - and html escaped by us.
            flag = urllib.parse.unquote(html.unescape(escaped_flag))
        except Exception as ex:
            # TODO: Fix?
            raise BrokenServiceException("Could not get back any flag")
        if flag != self.flag:
            self.error("Expected flag {self.flag} but got {flag}!")
            raise BrokenServiceException("Did not get back the valid flag.")

    def putnoise(self) -> None:
        self.logger.info("Starting putnoise")
        self.connect()

    def getnoise(self) -> None:
        self.logger.info("Starting getnoise")
        self.connect()

    def havoc(self) -> None:
        self.logger.info("Starting havoc")
        self.connect()

    def exploit(self) -> None:
        self.logger.warning("Blubb")
        pass


app = PoolcideChecker.service

if __name__ == "__main__":
    run(PoolcideChecker)
