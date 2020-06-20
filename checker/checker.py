from enochecker import BaseChecker, run
from enochecker.utils import sha256ify


class PoolsideChecker(BaseChecker):
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


app = PoolsideChecker.service

if __name__ == "__main__":
    run(PoolsideChecker)
