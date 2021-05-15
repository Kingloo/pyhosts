import sys

def process():
    print("Hello, World!")

def main(args):
    try:
        process()
    except Exception as e:
        print(str(e))

if __name__ == "__main__":
    main(sys.argv[1:])
