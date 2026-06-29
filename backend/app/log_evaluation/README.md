# log_evaluation

Turning a raw alert into a scored, explained event. This is the middle of the
pipeline, between pulling an alert in and showing it on the dashboard.

## Files

- **socevent.py** — the event type that every stage reads and writes, plus the
  small labels for how dangerous it is and where it is in the pipeline.
- **normalizer.py** — pulls the useful fields (time, IPs, user, rule details) out
  of messy raw logs and builds a clean event.
- **severity_scoring.py** — gives the event a severity from 0 to 100 by adding up
  a few simple rules. No trained model is involved.
- **explanation.py** — asks a local LLM to explain the event in plain words and
  suggest a response, with a fixed fallback for when the LLM is not running.
