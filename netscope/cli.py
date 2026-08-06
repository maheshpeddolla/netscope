import argparse

from netscope.collectors.system import collect_system
from netscope.collectors.connectivity import collect_connectivity
from netscope.reports.json import write_json


def main():

    parser = argparse.ArgumentParser(prog="netscope")

    subparsers = parser.add_subparsers(dest="command")

    collect_parser = subparsers.add_parser("collect")

    collect_parser.add_argument(
        "collector",
        choices=["system", "connectivity"]
    )

    args = parser.parse_args()

    if args.command == "collect":

        if args.collector == "system":

            data = collect_system()

            report = write_json("system.json", data)

            print(f"\nReport saved to {report}")

        elif args.collector == "connectivity":

            data = collect_connectivity()

            report = write_json("connectivity.json", data)

            print(f"\nReport saved to {report}")

    else:

        parser.print_help()


if __name__ == "__main__":
    main()