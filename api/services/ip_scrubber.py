"""One-time utility to sanitize Zeek logs into demo-safe RFC5737 ranges."""
from __future__ import annotations

import argparse
import json
import random
import string
from pathlib import Path

from api.services.demo_data import sanitize_ip


def random_uid(length: int = 18) -> str:
    chars = string.ascii_letters + string.digits
    return "C" + "".join(random.choice(chars) for _ in range(length - 1))


def scrub_record(record: dict) -> dict:
    out = dict(record)
    for key in ("id.orig_h", "id.resp_h", "src", "dst"):
        value = out.get(key)
        if isinstance(value, str):
            out[key] = sanitize_ip(value)

    if "uid" in out:
        out["uid"] = random_uid()

    if "host" in out:
        out["host"] = None

    return out


def scrub_file(src: Path, dst: Path):
    dst.parent.mkdir(parents=True, exist_ok=True)
    with src.open("r", encoding="utf-8") as fin, dst.open("w", encoding="utf-8") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            fout.write(json.dumps(scrub_record(obj)) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Scrub Zeek logs for demo data")
    parser.add_argument("source", type=Path, help="Source directory")
    parser.add_argument("dest", type=Path, help="Destination directory")
    args = parser.parse_args()

    for filename in ("conn.log", "dns.log", "http.log", "notice.log"):
        src = args.source / filename
        if src.exists():
            scrub_file(src, args.dest / filename)
            print(f"scrubbed {filename}")


if __name__ == "__main__":
    main()
