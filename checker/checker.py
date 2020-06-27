#!/usr/bin/env python3
import secrets
import string
import subprocess
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

    def register(self, username: str, password: str) -> str:
        with self.connect() as t:
            # TODO Change order, newlines, ...
            t.write(
                f"POST /cgi-bin/poolcide?route=register HTTP/1.0\r\n\r\nusername=${username}&password=${password}\n"
            )
            resp = t.read_all()
            try:
                print(resp)
                cookie = resp.split(b"Set-Cookie: ")[1].split(b"poolcode=")[1].split(b";")[0]
            except Exception as ex:
                self.warning(ex)
                raise BrokenServiceException("Could not read cookie")
            if not b"success" in resp:
                raise BrokenServiceException("Login failed")
            cookie = cookie.decode()
            self.info(f"Got cookie {cookie}")
            return cookie

    def reserve_as_admin(self, cookie: str) -> None:
        # TODO
        with self.connect() as t:
            t.write(
                f"POST /cgi-bin/poolcide?route=reserve HTTP/1.0\r\nCookie: poolcode=${cookie}\r\n\r\n"
                f"color=${self.flag}\n"
            )
            stuff = t.read_until("<code>")
            #TODO expect more stuff
            if b"admin" not in stuff:
                raise BrokenServiceException("No valid answer from reserve POST")
            age_foo = t.read_until("<")
            age_foo = age_foo.decode()[:-1]
            age_begin = "-----BEGIN AGE ENCRYPTED FILE-----"
            age_end = "-----END AGE ENCRYPTED FILE-----"
            age_line_len = 64
            try:
                line = age_foo.split(age_begin)[1].split(age_end)[0]
            except Exception as ex:
                raise BrokenServiceException("Admin token not found")
            n = age_line_len
            age_lines = [line[i:i+n] for i in range(0, len(line), n)]
            age = age_begin + '\n' + '\n'.join(age_lines) + '\n' + age_end
            resp = subprocess.run(["./age", "-d", "-i", AGE_KEYFILE], input=age.encode(), capture_output=True)
            admin_id = resp.stdout.strip()
            if len(admin_id) != 16:
                self.warning("Got ${admin_id} (stderr ${resp.stderr}) from ./age")
                raise BrokenServiceException("No valid Admin ID could be found")
            t.write(b"towel_admin_id=")
            t.write(admin_id)
            t.write("\n")
            all = t.read_all()
            if not b"Admin at the pool" in all:
                self.warning(f"Didn't find admin info in ${all}")
                raise BrokenServiceException("Could not Administer Towels at the Poolcide.")

        self.warning("Putflag not done yet")
        pass

    def putflag(self) -> None:
        user = self.random_user()
        password = self.random_password()
        self.team_db[self.flag] = {"user": user, "password": password}
        # TODO: Check returns!
        resp = self.http_get()
        #print(resp.text)
        resp = self.http_get("/cgi-bin/poolcide?route=index")
        self.info("trying to log in")
        cookie = self.register(user, password)
        self.info("Got cookie: %s", cookie)
        self.reserve_as_admin(cookie)

    def getflag(self) -> None:
        self.connect()
        self.logger.warning("Getflag not implemented")

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
