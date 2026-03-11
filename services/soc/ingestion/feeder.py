import argparse
import csv
import subprocess
import time
import sys


def inject_line(line: str, container: str, logfile: str) -> bool:
    escaped = line.replace('"', '\\"')
    result = subprocess.run(
        [
            "docker", "exec", container,
            "bash", "-c",
            f'echo "{escaped}" >> {logfile}',
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"  [WARN] docker exec failed: {result.stderr.strip()}", file=sys.stderr)
        return False
    return True


def feed(
    input_file: str,
    limit: int,
    delay: float,
    container: str,
    logfile: str,
    category_filter: str | None,
    dry_run: bool,
) -> None:
    injected = 0
    skipped  = 0

    print("=" * 60)
    print("  Wazuh Log Feeder")
    print("=" * 60)
    print(f"  Source     : {input_file}")
    print(f"  Limit      : {limit if limit else 'all'}")
    print(f"  Delay      : {delay}s")
    print(f"  Container  : {container}")
    print(f"  Log file   : {logfile}")
    print(f"  Category   : {category_filter or 'all'}")
    print(f"  Dry run    : {dry_run}")
    print("=" * 60)

    with open(input_file, newline='', encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
            if limit and injected >= limit:
                break

            if category_filter and row.get("category") != category_filter:
                skipped += 1
                continue

            raw_log  = row.get("log", "")
            category = row.get("category", "unknown")

            if dry_run:
                print(f"  [DRY] [{category}] {raw_log[:100]}")
                injected += 1
                continue

            ok = inject_line(raw_log, container, logfile)
            if ok:
                injected += 1
                print(f"  [{injected:>6}] [{category}] {raw_log[:80]}")
            else:
                # Stop if Docker is unreachable — no point continuing
                print("Aborting: Docker injection failed.", file=sys.stderr)
                break

            if delay:
                time.sleep(delay)

    print("=" * 60)
    print(f"  Done. Injected: {injected}  Skipped: {skipped}")
    print("=" * 60)


def main() -> None:
    parser = argparse.ArgumentParser(description="Feed SIEVE CSV logs into Wazuh.")
    parser.add_argument("--input",     default="data/SIEVE_00_100K.csv")
    parser.add_argument("--limit",     type=int,   default=100,
                        help="Number of rows to inject (0 = all)")
    parser.add_argument("--delay",     type=float, default=0.05,
                        help="Seconds to wait between injections")
    parser.add_argument("--container", default="single-node-wazuh.manager-1")
    parser.add_argument("--logfile",   default="/var/ossec/logs/active-responses.log")
    parser.add_argument("--category",  default=None,
                        help="Only inject rows matching this category label")
    parser.add_argument("--dry-run",   action="store_true",
                        help="Print lines without injecting into Docker")
    args = parser.parse_args()

    feed(
        input_file=args.input,
        limit=args.limit,
        delay=args.delay,
        container=args.container,
        logfile=args.logfile,
        category_filter=args.category,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
