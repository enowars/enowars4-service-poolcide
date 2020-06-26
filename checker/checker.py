from enochecker import BaseChecker, run
from enochecker.utils import sha256ify

# created: 2020-06-25T23:34:03+02:00
AGE_PUBLIC_KEY = "age1mngxnym3sz9t8jtyfsl43szh4pg070g857khq6zpw3h9l37v3gdqs2nrlx"
AGE_SECRET_KEY = "AGE-SECRET-KEY-1XCKQZWRQ6AH3MUZGHH29M37CF2CAC5U4TLZA9WRSTHNG9UH02LSS8FNDUY"

class PoolcideChecker(BaseChecker):
    port = 9001
    flag_count = 1
    noise_count = 1
    havoc_count = 1

    def putflag(self) -> None:
        self.connect()
        self.logger.warning("Putflag not implemented")

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
