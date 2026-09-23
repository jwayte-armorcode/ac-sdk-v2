# Rate Limiting

The ArmorCode API rate-limits sustained bulk traffic — most visibly on the
findings endpoints under heavy pagination, but any endpoint can return a
`429` under load, and transient `5xx` errors happen independently of rate
limiting. A script that pulls thousands of records (findings, sub-products,
runbooks, assets — anything paginated or fetched one-by-one in a loop) will
hit this if it runs long enough.

The Python SDK handles this for you automatically. This doc explains how,
so you can tune it for your own bulk scripts and understand what "handled"
actually means.

## The built-in protection: `_ThrottledRetrySession`

Every `ArmorCodeClient` wraps its HTTP session in `_ThrottledRetrySession`
(`armorcode/client.py`), which applies two protections **transparently** to
every `get`/`post`/`put`/`delete` call — no per-call-site changes needed:

1. **Proactive throttle** — enforces a minimum gap between requests
   (`min_request_interval` seconds), so a tight loop never bursts past the
   tenant's per-second budget in the first place.
2. **Reactive retry** — on `429` or `5xx`, waits and retries with
   exponential backoff, honoring the server's `Retry-After` header when
   present. Backoff starts at `backoff_base` seconds and doubles up to
   `backoff_cap`, for up to `max_retries` attempts. Any other status
   (including 4xx like 400/401/403) is returned immediately — those aren't
   rate-limit or transient-server problems, so retrying won't help and
   would just hide a real error from your code.

You opt in via two constructor kwargs:

```python
from armorcode import ArmorCodeClient

ac = ArmorCodeClient(
    "app.armorcode.com",
    token="<bearer-token>",
    min_request_interval=0.05,  # ~20 req/s ceiling, proactive pacing
    max_retries=8,               # retries on 429/5xx before giving up
)

# or via from_env — kwargs pass through the same way
ac = ArmorCodeClient.from_env("env", min_request_interval=0.05, max_retries=8)
```

Both default to "off": `min_request_interval=0.0` (no artificial pacing) and
`max_retries=8` (a reasonable retry budget even if you don't set pacing).
For a quick script hitting a handful of endpoints, the defaults are fine —
you generally only need to tune this for **bulk pulls**: loops that call
the API hundreds or thousands of times.

## Choosing `min_request_interval`

There's no published fixed rate limit to target — tenants and endpoints
vary — so the practical approach is empirical:

- Start conservative for a new bulk workload: `min_request_interval=0.05`
  (~20 req/s) is a safe default that has run cleanly against real tenant
  data without triggering sustained 429s.
- If you see repeated 429s in logs even with retry succeeding, raise the
  interval (e.g. `0.1`–`0.2`) to reduce how often you hit the limit in the
  first place — retrying past a 429 works, but it's slower and noisier than
  not tripping it.
- If a pull is comfortably under budget (no 429s ever observed), you can
  lower it for a faster run, but there's no reason to chase maximum
  throughput on a script that already finishes in an acceptable time.

`examples/pull_all_sub_products.py` exposes this as a `--min-interval` CLI
flag for exactly this kind of tuning without editing the script.

## Retry is not free — plan for it in your timing estimates

`max_retries` with exponential backoff means a script that starts tripping
429s doesn't crash, but it does get slower — each retry adds real wall-clock
time (backoff growing from `backoff_base` up to `backoff_cap` seconds per
attempt). When estimating how long a large bulk pull will take, budget for
retries as a normal part of the run, not an exceptional case. A sample of
10 calls with no load will systematically underestimate the real sustained
rate once a long-running loop is putting continuous pressure on the API —
time a longer sample (hundreds of calls) if you need an accurate ETA.

## Handling a run that gets interrupted

Retry handles *transient* failures inside a single call. It does not help
if the whole process gets killed — by you, by a crash, or (as happens on a
memory-constrained machine) by the OS reaping a long-running background
script. For anything that takes more than a few minutes, **build in
resumability** rather than relying on one unbroken run:

- Write results incrementally (e.g. one JSON object per line to a `.jsonl`
  file), flushed immediately — not buffered in memory until the end.
- Checkpoint which IDs are already done to a small separate file,
  periodically (e.g. every couple hundred records), and check it on startup
  to skip anything already fetched.
- Treat a single record's failure (after the SDK's own retries are
  exhausted) as non-fatal: log it and move on, rather than letting one bad
  ID abort a multi-hour run.

`examples/pull_all_sub_products.py` implements all three and is a good
reference for pointing this at your own bulk-pull scripts — see
[methods.md](methods.md#pulling-full-detail-for-every-sub-product-in-a-tenant)
for its usage and output files. It was validated against a live tenant with
~25,600 records; the run was killed and resumed three times by an
unrelated low-memory condition on the host machine, and finished with
correct, non-duplicated results and only a handful of failed IDs (mostly
transient network errors that a straightforward re-run would resolve).

## If you're writing your own loop instead of using an example script

You don't need to reimplement retry/backoff — just configure the client
and write a normal loop; the session handles the rest:

```python
ac = ArmorCodeClient.from_env("env", min_request_interval=0.05, max_retries=8)

results = []
for item_id in all_ids:
    try:
        results.append(ac.get_sub_product(item_id))  # any per-item GET works the same way
    except Exception as e:
        print(f"failed on {item_id}: {e}")  # log and continue, don't abort the whole loop
```

Avoid the older, manual pattern of sprinkling `time.sleep(...)` at call
sites — it paces requests but does nothing for a `429` that gets past it,
since there's no retry behind it. Prefer the constructor kwargs above; they
cover both proactive pacing and reactive retry in one place, for every call
the client makes. (`export_runbooks` used to do exactly this — a hardcoded
`time.sleep(0.15)` between calls — before being updated to rely on the
throttled session like everything else in the client.)

## Summary

| Need | How |
|------|-----|
| Avoid tripping rate limits during a bulk pull | `min_request_interval=0.05` (tune up if you still see 429s) |
| Survive a 429/5xx without writing retry code | Default behavior — `max_retries=8` out of the box |
| Survive the whole process getting killed | Build resumability into your script (see `pull_all_sub_products.py`) |
| Get an accurate time estimate for a large pull | Time a sample of hundreds of calls, not a handful — and budget for retries |
