from netscope.utils.command import run_command


def main():

    print("=" * 60)

    result = run_command(["hostname"])

    print(result)

    print("=" * 60)


if __name__ == "__main__":
    main()