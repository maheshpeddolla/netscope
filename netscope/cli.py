import argparse

from netscope.monitors.packetdrop import monitor_packet_drops


def print_packetdrop_result(diagnosis):
    """Print a packet-drop diagnosis."""

    print()
    print("=" * 60)
    print("NetScope Packet Drop Monitor")
    print("=" * 60)

    print(f"Location   : {diagnosis.location}")
    print(f"Confidence : {diagnosis.confidence}%")
    print(f"Severity   : {diagnosis.severity}")

    print()
    print("Evidence:")

    for evidence in diagnosis.evidence:
        print(f"  - {evidence}")

    print()
    print("Recommendations:")

    for recommendation in diagnosis.recommendations:
        print(f"  - {recommendation}")

    print("=" * 60)


def run_packetdrop_monitor(interval, iterations):
    """Run the live packet-drop monitor."""

    print("Starting NetScope packet-drop monitor...")
    print(f"Observation interval: {interval} seconds")

    if iterations == 0:
        print("Mode: Continuous")
    else:
        print(f"Observations: {iterations}")

    print()
    print("Press Ctrl+C to stop.")
    print()

    try:

        monitor_packet_drops(
            interval=interval,
            iterations=iterations,
            callback=print_packetdrop_result,
        )

    except KeyboardInterrupt:

        print()
        print("NetScope packet-drop monitor stopped.")


def main():

    parser = argparse.ArgumentParser(
        description="NetScope Linux troubleshooting tool"
    )

    subparsers = parser.add_subparsers(
        dest="command"
    )

    # --------------------------------------------------
    # MONITOR
    # --------------------------------------------------

    monitor_parser = subparsers.add_parser(
        "monitor",
        help="Run live troubleshooting monitors",
    )

    monitor_subparsers = monitor_parser.add_subparsers(
        dest="monitor_type"
    )

    packetdrop_parser = monitor_subparsers.add_parser(
        "packetdrop",
        help="Monitor Linux packet drops",
    )

    packetdrop_parser.add_argument(
        "--interval",
        type=int,
        default=10,
        help="Observation interval in seconds (default: 10)",
    )

    packetdrop_parser.add_argument(
        "--iterations",
        type=int,
        default=3,
        help="Number of observations (default: 3, use 0 for continuous)",
    )

    args = parser.parse_args()

    # --------------------------------------------------
    # COMMAND DISPATCH
    # --------------------------------------------------

    if args.command == "monitor":

        if args.monitor_type == "packetdrop":

            run_packetdrop_monitor(
                interval=args.interval,
                iterations=args.iterations,
            )

            return

        monitor_parser.print_help()
        return

    parser.print_help()


if __name__ == "__main__":
    main()