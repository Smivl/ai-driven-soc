"""
Inject "wrapped" logs into the Wazuh manager's analysisd queue socket so the
resulting alerts are attributed to a chosen agent — without running real agent
daemons.

A wrapped line has the format analysisd expects from wazuh-remoted:

    1:[<agent_id>] (<agent_name>) any-><location>:<raw log line>

Writing this as a datagram to /var/ossec/queue/sockets/queue inside the manager
container produces an alert with agent.id / agent.name set to the chosen agent.
"""

import subprocess
import sys

QUEUE_SOCKET = "/var/ossec/queue/sockets/queue"
DEFAULT_LOCATION = "/var/log/syslog"

# Runs inside the manager container: reads newline-delimited wrapped lines from
# stdin and sends each as a separate datagram to the analysisd queue socket.
# argv[1] is an optional per-line pacing delay in seconds (0 = as fast as possible).
_READER = (
    "import socket,sys,time\n"
    "pace=float(sys.argv[1]) if len(sys.argv)>1 else 0.0\n"
    "s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)\n"
    f"s.connect('{QUEUE_SOCKET}')\n"
    "n=0\n"
    "for line in sys.stdin.buffer:\n"
    "    line=line.rstrip(b'\\n')\n"
    "    if not line: continue\n"
    "    s.send(line); n+=1\n"
    "    if pace: time.sleep(pace)\n"
    "print(n)\n"
)


def wrap(agent_id: str, agent_name: str, log: str, location: str = DEFAULT_LOCATION) -> str:
    """Build the agent-attributed message analysisd expects for one raw log line."""
    # Strip newlines so each log stays a single datagram.
    log = log.replace("\n", " ").replace("\r", " ")
    return f"1:[{agent_id}] ({agent_name}) any->{location}:{log}"


def inject_batch(lines: list[str], container: str, pace_seconds: float = 0.0) -> int:
    """Send already-wrapped lines to the manager's queue socket in one docker exec.

    ``pace_seconds`` inserts a delay between datagrams. Use a small pace (~0.3s)
    when injecting a burst meant to trip a frequency/correlation rule, otherwise
    analysisd can process the batch too fast for its frequency counter to build.

    Returns the number of datagrams the in-container reader reported sending.
    """
    if not lines:
        return 0
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    result = subprocess.run(
        ["docker", "exec", "-i", container, "python3", "-c", _READER, str(pace_seconds)],
        input=payload,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"docker exec injection failed: {result.stderr.decode('utf-8', 'replace').strip()}"
        )
    try:
        return int(result.stdout.decode().strip() or 0)
    except ValueError:
        print(f"  [WARN] unexpected injector output: {result.stdout!r}", file=sys.stderr)
        return 0
