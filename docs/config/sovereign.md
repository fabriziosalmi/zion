# Sovereign Edge Intelligence

Zion can classify the **origin** of every request by IP — Italian government,
Italian residential ISP, Italian datacenter, an EU-27 country baseline, and the
EU role equivalents — and expose that as a log field, a metric label, and
(optionally) a hard `403` deny. The classification data (CIDR → role) is
**baked into the binary** from authoritative sources, so lookups are a
lock-free binary search with no runtime dependency.

This is an **opt-in feature**: the classification tables are only compiled when
you build with a `geo-*` feature, and even then Zion only classifies when
`[sovereign] enabled = true`.

## Build

| Cargo feature | What it bakes in |
|---|---|
| `geo-ita` | Italian ASN-role table (`GovIta` / `ResidentialIta` / `DatacenterIta`). |
| `geo-eu`  | Everything in `geo-ita` **plus** the EU-27 hybrid table: a country-level `Eu` baseline for every EU-27 allocation, overridden by curated `GovEu` / `ResidentialEu` / `DatacenterEu` roles where known. |

```bash
cargo build --release --features geo-eu     # EU + Italy
cargo build --release --features geo-ita     # Italy only
```

### What each class means

| Class | An address gets it when |
|---|---|
| `gov_ita`, `residential_ita` | a curated Italian ASN of that role announces it |
| `datacenter_ita` | a curated hoster announces it **and** the block is registered in Italy (RIPE delegation with country `IT`) |
| `eu` | the block is registered in an EU-27 country and no curated EU ASN announces it |
| `gov_eu`, `residential_eu`, `datacenter_eu` | a curated EU ASN of that role announces it, wherever the block is registered |
| `unknown` | none of the above |

The Italian table is consulted first. `datacenter_ita` carries the second
condition because two of the curated hosters, OVH and Hetzner, are on the
Italian list as companies that operate in Italy, and they announce space
registered in France, Germany, the United States, Israel. Without the
condition 85 % of the IPv4 addresses called `datacenter_ita` were registered
outside Italy. The EU role classes have no such condition today: a block
that LeaseWeb announces and that is registered in the Seychelles is
`datacenter_eu`.

With neither feature, `classify()` always returns `Unknown` and the whole
subsystem is compiled out (zero cost).

## Configuration

```toml
[sovereign]
enabled            = true      # master switch (default: false)
region             = "eu"      # "ita" | "eu" — labelling hint; both tables are
                               # always searched when compiled in
log_classification = true      # add ip_class to structured request logs (default: true)

# Optional: turn classification from a pure signal into a hard gate.
[sovereign.enforce]
enabled = true
deny    = ["unknown"]          # IpClass labels denied with 403. On a geo-eu
                               # build, ["unknown"] denies every non-EU source
                               # while EU classes pass — an allowlist BY COMPLEMENT.
# mesh_score_deny_above = 0.9  # deny when the AIMP mesh reputation exceeds this
                               # (0.0 = off; requires --features sovereign-aimp)
```

## Overrides: your own word on an address

The tables are compiled in, and they say what registries and BGP say. When a
row is wrong for you (your office range, a partner's network, a block the
table has not caught up with), you do not need a rebuild:

```toml
[sovereign.overrides]
"203.0.113.0/24"  = "residential_ita"   # our branch offices
"203.0.113.64/26" = "datacenter_ita"    # ...except the server room
"2001:db8::/32"   = "unknown"           # take this range out of the tables
```

- Each key is a CIDR or a single address, IPv4 or IPv6. Each value is a class
  label (`gov_ita`, `residential_ita`, `datacenter_ita`, `unknown`, and on a
  `geo-eu` build `eu`, `gov_eu`, `residential_eu`, `datacenter_eu`).
- **Overrides are consulted before the tables, and the most specific prefix
  wins.** `unknown` is a class like the others: it takes a range out of
  whatever the tables say.
- **Read at boot and on reload.** Edit the file and the next request sees it.
  The boot and reload log says how many are in force.
- **A list with a mistake is refused whole**, at boot and on reload, with every
  problem named: a CIDR with bits set beyond its prefix (`203.0.113.7/24`: the
  message gives the network to write), a class that does not exist in this
  build, the same network twice. On reload the previous list stays in force.
  An override that did nothing in silence would be worse than none.

The class an override gives is what the logs, the metric and
`[sovereign.enforce]` then see. An override is how you correct one row today;
if the row is wrong for everyone, it is also worth an issue.

Classification is a **signal by default** — it only affects logs/metrics until
you enable `[sovereign.enforce]`. The class labels used in `deny` are the
snake-case `IpClass` names: `gov_ita`, `residential_ita`, `datacenter_ita`,
`eu`, `gov_eu`, `residential_eu`, `datacenter_eu`, `unknown`.

## Where the data comes from — and what keeps it honest

The tables are generated by `scripts/generate_sovereign_data.py` from two
feeds:

- **RIPE NCC delegated stats**: IP allocations by country (the EU-27 baseline).
- **IPtoASN** ([iptoasn.com](https://iptoasn.com)): which ASN originates which
  prefix in a BGP snapshot, for the curated ASN roles.

A weekly CI job (`.github/workflows/sovereign-data.yml`) downloads them once,
regenerates both tables from that one download and opens a refresh PR for each.
To regenerate by hand:

```bash
scripts/fetch_sovereign_sources.sh .sovereign-data
python3 scripts/generate_sovereign_data.py --region ita \
    --ripe .sovereign-data/delegated-ripencc-latest \
    --ripe-md5 .sovereign-data/delegated-ripencc-latest.md5 \
    --iptoasn .sovereign-data/ip2asn-v4.tsv \
    --iptoasn6 .sovereign-data/ip2asn-v6.tsv \
    --manifest .sovereign-data/SOURCES.tsv \
    --summary summary.md \
    --output src/sovereign/data_ita.rs
```

### What a refresh checks before it writes a table

**The files it is built from.** A download can go wrong quietly: a transfer cut
short, an error page saved as data, a mirror serving an old file. The generator
checks the files offline, before any lookup, and exits with status 4 and
`INPUT REFUSED` if one fails:

| File | Checked |
|---|---|
| RIPE delegated stats | the header is a version-2 `ripencc` one; the records of each type add up to the file's own summary lines and header total; the MD5 is the one RIPE publishes; the file's date is no more than 7 days old |
| IPtoASN, IPv4 and IPv6 | every row parses; rows are in order with no hole between them; the IPv4 table starts in `1.0.0.0/8` and reaches `223.0.0.0/8`, the IPv6 one runs from `::` to the last address; at least 300,000 / 100,000 rows and 60,000 / 25,000 origin ASNs |
| All three | size and SHA-256 are those recorded at download time (`SOURCES.tsv`); the server's `Last-Modified` is no more than 7 days old |

The download itself (`scripts/fetch_sovereign_sources.sh`) uses `curl --fail`
with retries and timeouts, and `gzip -t` on each archive.

Two things these checks do not see. An IPtoASN IPv4 file cut inside
`223.0.0.0/8` passes: what it loses is APNIC space that neither table uses. And
IPtoASN publishes no checksum, so a file that is whole in shape and wrong in
content is not detected here; the change budget below is what stands against it.

**How much it changes.** The new table is compared, address by address, with the
one it replaces:

| Change | Result |
|---|---|
| A class gains or loses more than 20 % of its addresses | refused (exit status 3), nothing written. It is the mark of a broken input or of an edit to the curated ASN list; after such an edit, regenerate by hand with `--allow-over-budget` |
| A class moves by more than 2 % | the PR opens as a **draft**, labelled `sovereign-review`, with the reason at the top |
| A block of /18 or more (IPv6: /32 or more) enters or leaves a role class (`gov_*`, `residential_*`, `datacenter_*`) | same: draft PR |
| A curated ASN originates no IPv4 range | same: draft PR |

The PR body is written by the generator (`--summary`): the sources and their
dates, what needs a look, the addresses each class holds before and after, and
the largest blocks that change class. Each block comes with the ASN that
announces it in this snapshot and the country RIPE has it registered in, so a
block that "leaves" a class because another ASN of the same operator now
announces it reads differently from one that is no longer announced at all.

The thresholds were set on the nine weekly tables from 2026-08-12 to
2026-10-05.

### The table follows the snapshots with a delay

One snapshot says what a curated ASN announced at one moment. Prefixes are
announced on and off, moved between the ASNs of one operator, lent for two
weeks. A table that copied each snapshot labelled real clients wrongly for a
week at a time: in nine weeks, 49 runs of addresses went from one class to
another and back.

So the published table is not the snapshot:

| A run of addresses | changes in the table |
|---|---|
| has no class and is observed in one | after **2** weekly snapshots that agree |
| has a class and is observed without it, or in another | after **3** |
| is observed back in its published class before that | never; the count starts again |

Two runs of the refresh count as two snapshots only when they are 5 days or
more apart, so running it again the same day does not hurry anything.

What has been observed and is not yet published is kept in
`src/sovereign/data_<region>.pending.json`, committed with the table. Each
refresh PR shows it in its diff, and its body lists the largest runs that are
waiting (`1 of 3`, `2 of 3`) and the ones that went back.

That memory advances only when a refresh PR is **merged**. One left open is a
week of sightings that was never recorded. The next refresh says so at the top
of its body, counts from what is on master, and closes the older PR of the
same region with a comment (`scripts/supersede_refresh_prs.sh`); branches are
left in place.

What this costs: a new allocation or a new announcement is classified one
week late, and a range that really left keeps its class for two more weeks.
With `[sovereign.enforce] deny = ["unknown"]` that is the safer direction (a
real client is not turned away because of one snapshot); with a deny list of
datacenter classes it means a range that stopped being a datacenter is denied
for two more weeks.

**Edits to the curated ASN list are not delayed.** When an ASN is removed from
the list, or given another role, the ranges it announces are re-labelled at
the next refresh: a removal is a correction, and making it wait three weeks
would keep a wrong label on purpose. An ASN that is added waits like any other
observation. The list each table was last built with is recorded in the same
`.pending.json`.

**Nor is a range outside the countries its class is confined to.** A published
`datacenter_ita` range that is not registered in Italy loses the class at the
next refresh: no snapshot can observe it in that class again, so there is
nothing to wait for. This is how the rule reached the table that was built
before it, and how the table follows a block that the registry moves to
another country.

To publish a snapshot as it is and clear the memory (after a change to the
generator's rules, by hand): `--no-hysteresis`.

On the nine historical weeks, replayed through this rule: the research
network's /13 that left `gov_eu` for one week, the /17 that was `datacenter_eu`
for two, and the three /18s of an Italian ISP that came and went are never
published.

### How old the data in a running binary is

The tables are compiled in. The repository refreshes them every week; a binary
keeps the ones it was built with. Each table carries the day of its last
snapshot, and the binary shows it in three places:

- the boot line: `Sovereign Edge active (region=eu, ..., address tables: ita
  2026-10-06, eu 2026-10-06)`;
- a `WARN` at boot when a table is more than 45 days old;
- `/metrics`: `zion_sovereign_data_snapshot_timestamp_seconds{region="..."}`
  (see [observability](../guide/observability.md)).

### What the tests hold the tables to

Each refresh PR runs, in CI, against the table it proposes:

- structure: rows sorted, not overlapping, ending at or after their start, and
  none in reserved space (`10/8`, `127/8`, `224/3`..., or outside `2000::/3`);
- **one pinned address per curated ASN**, IPv4 and IPv6 where the ASN has both,
  with the class it must have (82 addresses). An ASN that drops out of a
  table, or a lookup that breaks, fails by name. The test also checks the list
  itself: an ASN added to the generator without a pinned address fails;
- twelve addresses that must stay `unknown`: large networks in the US, Russia
  and China, and in the United Kingdom, Switzerland and Norway, which are in
  Europe and not in the EU-27;
- a floor on the addresses of each class, at about three quarters of today's.

A pinned address that really moved (the operator gave the block back) is
updated by hand. That is the point of pinning it.

### The holder-validation guarantee

The curated ASN sets in the generator are not bare numbers with a comment —
each ASN carries its **expected holder** as data, e.g. `3269: "Telecom Italia"`.
Before emitting anything, the generator fetches each ASN's **live holder** from
[RIPEstat](https://stat.ripe.net) and compares it (accent- and case-insensitive,
ignoring legal-form/noise words) to the expected name.

This closes a silent-wrongness hole: **RIPE reassigns ASNs.** When a curated ASN
moves to a different — even foreign — holder, the old pipeline would diligently
pull the *new* holder's ranges and re-label them with the Italian/EU role. The
generator now **fails closed** on any such drift and refuses to regenerate; the
weekly job's PR is blocked, not opened, and a human must either update the
expected holder (a legitimate reassignment still in scope) or remove the ASN
(reassigned out of national/EU sovereignty). `--allow-drift` overrides this for
a deliberate one-off. The generated file header records the snapshot date the
holders were validated on.

Two things were added to this check since. **The country.** A name alone lets
"Orange" in Mali pass for Orange in France, so each curated ASN must also be
registered where the list expects it: in Italy for the Italian list (OVH and
Hetzner are the two named exceptions, in France and Germany), in an EU-27
country for the EU list. The country comes from the BGP table itself, with no
lookup. **A lookup that fails is not a drift.** RIPEstat times out now and
then; each lookup is tried four times (after 2, 6 and 20 seconds), and if it
still fails the refresh stops with its own message and exit status (5): nothing
in the list needs fixing, run it again.

### What the curated list leaves out

A list goes stale without anyone touching it: an operator moves customers to a
second ASN, a new one grows. Every refresh PR ends with the share of the
region's announced IPv4 space that a curated ASN originates, and the eight
largest origins that are not on the list, for example:

```
Of the announced IPv4 addresses registered in the region, 84% are originated by a curated ASN (43,436,544 of 51,436,544).

| AS3302 AS-IRIDEOS (IT)  | 617,984 |
| AS24608 WINDTRE-AS (IT) | 549,888 |
```

Adding or removing an ASN stays a decision made by hand, in the generator.

The generator's tests live in `scripts/test_generate_sovereign_data.py`
(fixture-based, no network; they run in CI and at the start of every refresh)
and the pinned `golden_classify_*` tests in
`src/sovereign/mod.rs` are a regression net for the classification itself.

## What it guarantees

- **Correct-and-small over wrong-and-big.** An ASN that drifts to a foreign
  holder is removed rather than silently mislabelled — the classifier never
  claims a Russian or German range is Italian sovereign.
- **Zero runtime cost when off** (feature-gated tables, `enabled = false`).
- **Signal first, gate second** — enforcement is a separate, explicit opt-in.
