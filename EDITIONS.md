# EDITIONS — open source core vs pro

redveil ships as two editions over one architecture. The core repo you are
reading is the OSS edition's source; `redveil-pro` is a private wheel that
installs on top of it.

## The matrix

| capability | redveil (OSS) | redveil-pro |
|---|---|---|
| CLI, GUI, dashboard, SSE server mode | yes | yes |
| campaigns / targets / lures / serve / stager / reporting | yes | yes |
| technique catalog (clickfix surfaces) | yes | yes |
| category packs (colis, crypto, cloudflare, update, support, taxes) | yes | + premium packs (banking, brands, drains…) |
| generator engine (`cf/generator.py`, `generate` command) | yes | yes |
| delivery chains (MotW, one-click, search-ms) | yes | + exploit chains (CVE / 0day class) |
| collect + exfil snippets (`collect`, `exfil`) | yes | yes |
| payload factory (proxy/hpp, evasion chain) | — | yes |
| relay / extension C2 / aitm pivot | — | yes |
| sigma + csv export | — | yes |
| crypter / packer / evasion layer | — | yes |
| licensing tiers (demo/trial/pro/team) | — | yes |

## The mechanism

- The OSS wheel **omits** `cf/payload.py`, `cf/relay.py`, `cf/ext.py`,
  `cf/chain.py` and their command groups — the code is not shipped, not
  gated. Gating without source is theater; source without gating is free.
- `redveil-pro` is installed separately (`pip install redveil-pro` from the
  private index) and registers itself through two seams the core already
  implements:
  - `redveil_pro.data.categories/` — premium pack JSON files, discovered by
    `_pro_pack_dirs()` in `cf/generator.py`;
  - `redveil_pro.chains.CHAINS` — exploit chain dict, merged by `_chains()`
    with an id-collision check (collision fails closed at load).
- License checks (`require_feature`) live in the pro wheel and gate its own
  features per tier; the OSS core runs without any license file present.
- One codebase, two build profiles: `tools/strip_oss.py` prunes the pro
  modules from a checkout and emits the public tree; CI runs the full suite
  on the public tree with pro modules absent (seams return empty).

## Standing rules

- Packs are data, never code — a pack that needs code is a new engine
  feature, not a pack.
- `cf/stager.py` stays frozen in both editions.
- Every pack validates in the test suite: scenarios, surfaces, tags,
  collectors, exfil kinds, chain ids, placeholders ⊆ `CTX_KEYS`.
- Same seed = same bundle, OSS and pro alike.
