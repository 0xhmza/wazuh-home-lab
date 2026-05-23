# Real-world log datasets

Each subdirectory is a "dataset": a folder of real-world log lines that the
generator can replay through the `dataset_replay` scenario. When the lab
overlay starts, every `*.log` file in every subdirectory is loaded into memory,
the leading `<timestamp> <hostname>` is stripped from each line, and a fresh
`<timestamp> <agent-name> replay:` prefix is prepended at replay time so the
event appears to originate from the replaying endpoint.

## Bundled samples

| Folder                    | Source / inspiration                            | Category   |
|---------------------------|-------------------------------------------------|------------|
| `loghub-openssh/`         | LogHub OpenSSH dataset — SSH brute-force        | `auth`     |
| `loghub-linux/`           | LogHub Linux syslog                              | `noise`    |
| `loghub-apache/`          | LogHub Apache combined access log — web attacks  | `web`      |
| `cic-ids2017-suricata/`   | CIC-IDS2017 IDS sample — Suricata-style alerts  | `network`  |

The bundled files are intentionally small (a few hundred lines each) so the
repo stays light. They are based on the freely-redistributable patterns from
[LogHub](https://github.com/logpai/loghub) (MIT-licensed) and on
[CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) traffic patterns.

## Adding more data

Drop any text file (one log line per line) into a new subdirectory and re-run
`scripts/up.ps1`. The renderer mounts `datasets/` read-only into the generator
container, so the new lines will be picked up the next time the generator
starts.

```
datasets/
  my-custom/
    syslog.log        # one line per event
    meta.json         # optional: {"category": "auth"}
```

## Fetching a HuggingFace dataset

If you want to feed a much larger volume of real network/security telemetry
into the lab, use the bundled fetcher:

```powershell
# install once
python -m pip install datasets

# pull a dataset and write its 'text' / 'message' / 'log' column to .log files
python .\app\fetch_dataset.py `
  --dataset cybernative/Code_Vulnerability_Security_DPO `
  --column rejected `
  --output datasets\hf-cve-attempts `
  --max-lines 5000
```

The fetcher works with any HuggingFace dataset whose rows contain a string
column you can name with `--column`. It emits a single `data.log` plus a
`meta.json` describing the category. Restart the lab (`scripts/up.ps1`) to pick
up the new lines.
