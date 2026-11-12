import sys

def read_lines(path: str):
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if "sshd[" in line:
                yield line.rstrip("\n")

if __name__ == "__main__":
    for line in read_lines(sys.argv[1]):
        print(line)