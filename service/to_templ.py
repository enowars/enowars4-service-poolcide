#!/usr/bin/env python3
import os
import sys


def compile_template(in_file, out_file):
    vars = []

    def handle_line(output: "IO", line: str):

        var_splits = line.split(b"{{")
        for i, var_split in enumerate(var_splits):
            if i == 0:
                remainder = var_split
            else:
                variable, remainder = var_split.split(b"}}")
                try:
                    name, printtype = variable.split(b"%")
                except ValueError as ex:
                    raise Exception(r"Variables need a type like {{varname%s}}", ex)
                vars.append(name)
                output.write(b"%")
                output.write(printtype)

            for char in remainder:
                if ord("0") <= char <= ord("9") or char in [ord(x) for x in "%()/"]:
                    output.write(b"\\")
                    output.write(hex(char)[1:].encode())
                else:
                    output.write(b"%c" % char)

    with open(in_file, "rb") as input:
        with open(out_file, "wb") as output:
            for line in input:
                if line.startswith(b"TEMPLATE("):
                    output.write(line)
                    continue
                if line.startswith(b")") and line.strip() == (b")"):
                    # Last element, closing the template.
                    output.write(line)
                    continue
                handle_line(output, line)
            for var in vars:
                output.write(b", ")
                output.write(var)


if __name__ == "__main__":
    # for file in os.listdir("."):
    # if file.endswith(".templ.html"):
    if len(sys.argv) < 2:
        print("Usage: to_templ.py <in_file> <out_file>")
    else:
        compile_template(sys.argv[1], sys.argv[2])
