# ml_unimplemented

Experimental machine-learning modules brought over from a different branch. They
are not wired into the running pipeline and are kept here for future work, so you
can read them for direction but should not expect them to run as-is.

## Files

- **correlator.py** — would group related events into a single ongoing alert by
  matching on shared IPs, users, and MITRE techniques.
- **ml_category.py** — would predict which category a raw log belongs to.
- **ml_sequence.py** — would score sequences of events over sliding time windows
  to spot attack patterns rather than single events.
