#!/usr/bin/env python3
"""Pull full detail for every sub-product (repo/component) in a tenant.

Built for large tenants where `get_sub_product()` needs to be called once per
sub-product — there is no bulk "full detail for everything" endpoint, only a
lightweight id+name list (`get_sub_products()`) plus a per-id detail call.
For a tenant with tens of thousands of sub-products this can run for hours,
so the script is resumable and rate-limit safe by design:

* **Resumable** — each sub-product's detail is appended to a JSONL file as
  soon as it's fetched, and completed ids are checkpointed to a separate
  file periodically. A crash or Ctrl-C loses at most one checkpoint interval
  of progress; re-running the script skips everything already done instead
  of starting over.
* **Rate-limit safe** — relies entirely on the SDK's built-in
  `_ThrottledRetrySession` (proactive `min_request_interval` pacing plus
  reactive 429/5xx retry with exponential backoff honoring `Retry-After`),
  configured via `ArmorCodeClient(..., min_request_interval=, max_retries=)`.
  No retry logic is reimplemented here.
* **Non-fatal per-item failures** — if a single sub-product fetch fails even
  after the SDK's own retries are exhausted, its id is logged to a failures
  file and the run continues rather than aborting an hours-long pull over
  one bad id.

Examples::

    # full pull, default pacing (~20 req/s), writes into ./out/
    python pull_all_sub_products.py --env ../env

    # resume an interrupted run — already-done ids are skipped automatically
    python pull_all_sub_products.py --env ../env --out-dir ./out

    # slower pacing for a tenant with a tighter rate limit
    python pull_all_sub_products.py --env ../env --min-interval 0.2

    # quick smoke test against the first 50 sub-products only
    python pull_all_sub_products.py --env ../env --limit 50
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from armorcode import ArmorCodeClient  # noqa: E402


def log(log_path, msg):
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    print(line)
    with open(log_path, "a") as f:
        f.write(line + "\n")


def load_checkpoint(path):
    if path.exists():
        return set(json.loads(path.read_text()))
    return set()


def save_checkpoint(path, done_ids):
    path.write_text(json.dumps(sorted(done_ids)))


def main():
    p = argparse.ArgumentParser(
        description="Pull full detail for every sub-product in a tenant "
                     "(resumable, rate-limit safe).",
    )
    p.add_argument("--env", default="env", help="Path to env file (default: env)")
    p.add_argument("--out-dir", default="./sub_product_pull",
                   help="Directory for output/checkpoint/log files "
                        "(default: ./sub_product_pull)")
    p.add_argument("--min-interval", type=float, default=0.05,
                   help="Minimum seconds between requests, proactive "
                        "throttle (default: 0.05, ~20 req/s ceiling)")
    p.add_argument("--max-retries", type=int, default=8,
                   help="Max retries on 429/5xx with exponential backoff "
                        "(default: 8)")
    p.add_argument("--checkpoint-every", type=int, default=200,
                   help="Save checkpoint + print progress every N records "
                        "(default: 200)")
    p.add_argument("--limit", type=int, default=None,
                   help="Only process the first N sub-products (for testing)")
    args = p.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    detail_file = out_dir / "sub_product_details.jsonl"
    checkpoint_file = out_dir / "checkpoint_done_ids.json"
    failures_file = out_dir / "failed_ids.jsonl"
    progress_log = out_dir / "progress.log"

    client = ArmorCodeClient.from_env(
        args.env,
        min_request_interval=args.min_interval,
        max_retries=args.max_retries,
    )
    log(progress_log, f"tenant: {client.base_url}")

    log(progress_log, "Fetching full sub-product list (id + name)...")
    subs = client.get_sub_products()
    all_ids = [s["id"] for s in subs]
    if args.limit:
        all_ids = all_ids[:args.limit]
    log(progress_log, f"Total sub-products to process: {len(all_ids)}")

    done_ids = load_checkpoint(checkpoint_file)
    remaining = [sid for sid in all_ids if sid not in done_ids]
    log(progress_log,
        f"Already done (from checkpoint): {len(done_ids)}. "
        f"Remaining: {len(remaining)}")

    if not remaining:
        log(progress_log, "Nothing to do — all sub-products already pulled.")
        return 0

    detail_f = open(detail_file, "a")
    fail_f = open(failures_file, "a")

    start = time.time()
    since_checkpoint = 0

    try:
        for i, sid in enumerate(remaining, 1):
            try:
                detail = client.get_sub_product(sid)
                detail_f.write(json.dumps(detail, default=str) + "\n")
                detail_f.flush()
                done_ids.add(sid)
            except Exception as e:
                fail_f.write(json.dumps({"id": sid, "error": str(e)}) + "\n")
                fail_f.flush()
                log(progress_log, f"FAILED id={sid}: {e}")

            since_checkpoint += 1
            if since_checkpoint >= args.checkpoint_every:
                save_checkpoint(checkpoint_file, done_ids)
                since_checkpoint = 0
                elapsed = time.time() - start
                rate = i / elapsed if elapsed > 0 else 0
                eta_min = (len(remaining) - i) / rate / 60 if rate > 0 else float("inf")
                log(progress_log,
                    f"Progress: {i}/{len(remaining)} this run "
                    f"({len(done_ids)}/{len(all_ids)} total) "
                    f"rate={rate:.1f}/s ETA={eta_min:.1f}min")
    finally:
        # Always checkpoint on the way out, including Ctrl-C or an
        # unexpected exception, so a killed run loses minimal progress.
        save_checkpoint(checkpoint_file, done_ids)
        detail_f.close()
        fail_f.close()

    elapsed = time.time() - start
    log(progress_log,
        f"Done. {len(done_ids)}/{len(all_ids)} total complete. "
        f"This run took {elapsed/60:.1f} min.")
    return 1 if failures_file.stat().st_size > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
