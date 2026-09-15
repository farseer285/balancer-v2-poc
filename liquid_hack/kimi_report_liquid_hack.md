# Elements rangeproof cache consensus failure — root cause analysis of the 2026-09-06 Liquid network split and 3,998.67 BTC peg-out theft

---

## 1. Executive summary

On 2026-09-06 at ~12:40 UTC the Liquid Network suffered a consensus split caused by
transaction `f24a4b17…183f` (mined in block 4050336, hash `e1d9a2aa…`) whose output #1
carries a rangeproof that is **cryptographically invalid** under its own (asset, script)
context. Part of the network accepted the block anyway; part rejected it and has not
accepted any block since. Within ~9 minutes the attacker laundered the created value into
two `sendtomainchain` peg-out outputs totalling **3,998.67 BTC**, and at 14:25 UTC the
Liquid functionaries — following the accepting side of the fork — paid both peg-outs from
the federation's Bitcoin wallet in batched mainnet tx `8db751a6…b140`. The attacker moved
the funds onwards within minutes.

The acceptance of a tx with an invalid rangeproof is explained by a **consensus bug in
Elements' rangeproof memoization cache** (`CachingRangeProofChecker`, `src/script/sigcache.cpp`)
— but there are **two** bugs in the same cache key, and the one exploited is not the
one that was being fixed:

- **Bug A — context omission (2019-03-19 → every release ≤ `elements-23.3.3`):** the
  cache key is derived only from the rangeproof bytes and the value commitment,
  omitting the **asset generator** and the **scriptPubKey** (both authenticated by
  `secp256k1_rangeproof_verify` as the generator argument and the `extra_commit`
  entropy input). A proof once verified in one (asset, script) context is thereafter
  treated as valid for *any* context on that node. Real, critical, shipped in 99
  release tags — **but not the exploited mechanism** (§2.4).
- **Bug B — ambiguous key encoding (introduced by the fix itself):** the fix
  ("Fix caching bug in rangeproof caching", `c26d719c29`, PR #1561 — authored
  **2026-08-03** per its git author date) computes the key as a salted hash over the
  **raw concatenation** `proof ‖ commitment ‖ asset-generator ‖ scriptPubKey` with
  **no length delimiters**. The proof and the script are both variable-length and sit
  at opposite ends of the stream, so the field boundary between them can be shifted:
  distinct `(proof, commitment, asset, script)` tuples hash to **byte-identical**
  streams. This is the exploited bug — reproduced byte-for-byte from the on-chain
  data in §2.4.

The fork-side attribution is therefore the *reverse* of the obvious reading: **the
accepting side — including the signing functionaries and Blockstream's own
infrastructure — was running the raced, unreleased fixed code** (23.3.4rc2-era builds)
with attacker-primed caches, while **the rejecting side ran pre-fix releases** whose
keying cannot collide for the attack tuple (§2.4) and which therefore ran the real —
failing — verification.

Timeline: the fix was merged to `master` on **2026-09-01**, cherry-picked to
`elements-23.x` (`6253d7e103`, 09-02) and prepared for `elements-23.3.x` as
`212c43f475` (09-03; backport PR #1599 opened 09-04 "in preparation for 23.3.4rc2") —
**2–5 days before the attack** — and deployed to the functionaries ahead of any
release. At the time of the attack (and still today) **no release tag contains the
fix** (verified: `git tag --contains` for all three commits is empty; latest tags
`elements-23.3.3`, `elements-23.4.0rc3`, `elements-29.4.1rc1` all predate it). The
23.3.x backport merged attack-day evening (`3b3f01eac9`, 19:20 +0200; §5.2). The
attacker reverse-engineered the public fix diff, found the boundary ambiguity the
fix had introduced, dry-ran the full mechanism on the functionaries' own mempools
~10 minutes before the attack (§4.6), and exploited it at ~12:40 UTC. **The deployed
fix does not close the exploited hole**: Bug B is unfixed in every branch as of this
writing (no delimiting follow-up exists), so any node running the current patch —
including the functionaries — is exploitable again today by re-priming (§6, §7).

---

## 2. Root cause: one cache, two key bugs

### 2.1 Bug A — context omission (pre-fix code, `c26d719c29~1:src/script/sigcache.cpp`)

```cpp
bool CachingRangeProofChecker::VerifyRangeProof(
    const std::vector<unsigned char>& vchRangeProof,
    const std::vector<unsigned char>& vchValueCommitment,
    const std::vector<unsigned char>& vchAssetCommitment,   // <-- NOT in the key
    const CScript& scriptPubKey,                             // <-- NOT in the key
    const secp256k1_context* ...) const
{
    uint256 entry;
    rangeProofCache.ComputeEntryRangeProof(entry, vchRangeProof, vchValueCommitment);

    if (rangeProofCache.Get(entry, !store)) {
        return true;                       // cache hit: ACCEPT without any verification
    }
    ...
    secp256k1_generator tag;
    secp256k1_generator_parse(..., &tag, &vchAssetCommitment[0]);
    if (!secp256k1_rangeproof_verify(..., &commit,
            vchRangeProof.data(), vchRangeProof.size(),
            scriptPubKey.size() ? &scriptPubKey.front() : nullptr,
            scriptPubKey.size(), &tag)) {
        return false;                      // real verification on miss
    }
    ...
    if (store) {
        rangeProofCache.Set(entry);        // only successes are cached
    }
    return true;
}
```

- `ComputeEntryRangeProof(entry, proof, value_commitment)` — salted SHA-256 over
  **proof + value commitment only**.
- `secp256k1_rangeproof_verify` binds the proof to three things: the **commitment**,
  the **generator** (asset), and the **extra commitment** (the output's scriptPubKey,
  hashed into the proof's message). Two of the three are missing from the cache key.
- `Set` is called only on successful verification (no negative caching), and
  `Get(entry, /*erase=*/!store)` removes the entry on read during block validation
  (`store == false`) but keeps it during mempool acceptance (`store == true`).
- The cache is a per-process in-memory `CuckooCache` (`SignatureCache`), salted per
  process: each node must be primed individually; entries do not survive restarts.


### 2.2 The raced fix — and Bug B, the ambiguous key encoding it shipped

The fix (`c26d719c29` on `master`, 09-01; `6253d7e103` on `elements-23.x`, 09-02;
`212c43f475` on `elements-23.3.x`, 09-03) threads the asset and script into the key —
a few lines in `src/script/sigcache.{cpp,h}`, touching only the rangeproof cache.
Verbatim post-fix key derivation:

```cpp
void ComputeEntryRangeProof(uint256& entry, ..., const std::vector<unsigned char>& proof,
    const std::vector<unsigned char>& commitment,
    const std::vector<unsigned char>& asset_commitment, const CScript& scriptPubKey) {
    CSHA256 hasher = m_salted_hasher_range_proof;                 // per-process salt
    hasher.Write(proof.data(), proof.size())                      // VARIABLE length
          .Write(commitment.data(), commitment.size())            // fixed 33 B
          .Write(asset_commitment.data(), asset_commitment.size())// fixed 33 B
          .Write(scriptPubKey.data(), scriptPubKey.size())        // VARIABLE length
          .Finalize(entry.begin());
}
```

What actually enters the third field (`src/confidential_validation.cpp:381-388`): for
outputs with an **explicit** asset, the caller runs
`secp256k1_generator_generate(&gen, assetID)` and passes the **33-byte serialized
generator**; for confidential assets it passes the 33-byte asset commitment. Either
way a fixed 33 bytes — but *which* 33 bytes is fully determined by the output's asset
field, which the attacker controls.

Two properties combine into Bug B:

1. **No length delimiters.** The key input is the raw concatenation
   `proof ‖ commitment ‖ generator ‖ script`; any partition of the same byte stream
   into these four fields yields the same key.
2. **The two variable-length fields sit at the ends.** The proof leads, the script
   trails, and the script can be anything — including a 69-byte OP_RETURN data push.
   A `k`-byte shift of the proof/script boundary collides iff

   ```
   P1 = P0 ‖ C0 ‖ A0 ‖ S0[:k]     C1 = (33 bytes at that offset inside S0)
   A1 = A0                         S1 = S0[k:]
   ```

   i.e. the attacker **relocates existing bytes across the boundary** rather than
   grinding any elliptic-curve values: the middle 66 bytes (`C ‖ A`) are kept
   byte-identical by *embedding the attack tuple's commitment `C1` and generator `X`
   inside the primer's script*. The per-process salt does not help: primer and attack
   keys are computed in the same process.

The surjection-proof cache was audited and is **not** affected: its key is
`salted(wtxid ‖ proof ‖ output_generator)` (`CachingSurjectionProofChecker`,
unchanged by the fix); the wtxid commits to every input/output asset commitment in
the transaction, and the variable-length proof is *interior* (fixed-width wtxid
ahead, fixed-width generator behind), so no end-to-end boundary shift exists.

### 2.3 Cache-era semantics (why priming works, and when)

- **Mempool:** `MemPoolAccept::PreChecks` → `Consensus::CheckTxInputs`
  (`src/consensus/tx_verify.cpp:250`, called from `validation.cpp:1100` with
  `cacheStore=true`): every successfully verified output rangeproof is **stored** and
  survives even if the tx is later evicted from the mempool; reads are
  `Get(entry, erase=false)` — hits do not consume.
- **Block validation:** `ConnectBlock` → `CheckTxInputs` (`validation.cpp:3041`,
  `fCacheResults = fJustCheck`, i.e. false when actually connecting): the cache is
  read with `Get(entry, /*erase=*/true)` — **a hit is consumed** — and nothing new is
  stored.

Consequences: (i) only mempool acceptance primes; (ii) a primed entry survives until
a block-connect read erases it, so the primer must be **mempool-live in the same
inter-block era** as the attack block's connection; (iii) after the accepting side
connected 4050336 the entry was consumed — those nodes cannot re-validate the very
block they accepted (reorg disconnect/reconnect, or startup `-checkblocks`
re-validation, fails), which explains part of the observed post-attack network
fragility; (iv) `testmempoolaccept` would also store entries but requires RPC auth;
no block-relay or orphan path stores.

### 2.4 The attacker's byte-level construction (reproduced from on-chain data)

All four alignment identities hold **byte-exactly** (`collision_test.py`, 2026-09-07):

```
X  = 0a ‖ 0a488de4899d0ae757f6cf8368663184d164106111ed9eaecf510e35282ddc6d
   = secp256k1_generator_generate(L-BTC asset id 6f0279e9…526d), byte-exact —
     independently reproduced via the Shallue–van de Woestijne map with the two
     tagged-hash candidates ("1st/2nd generation: ") → MATCH (gen_check.py)
S0 = 6a 43 ‖ C1 ‖ X ‖ 6a            (69 B = OP_RETURN + push opcode 0x43 + 67 B payload)
P1 = P0 ‖ C0 ‖ X ‖ 6a 43            (4,234 B = the 4,166 B dry-run proof + 68 B tail)
S1 = 6a                             (1 B, bare OP_RETURN)
```

- **Primer tuple** `(P0, C0, X, S0)` — the explicit-L-BTC OP_RETURN output of the
  dry-run txs (§4.6): `P0` verifies **VALID** against `(C0, X, S0)`
  (`prime_verify_test.py`: VALID, min/max `0/4503599627370495`), so ordinary
  verification stores `K = salted-hash(P0‖C0‖X‖S0)` on every fixed-code node that
  accepts the tx to its mempool.
- **Attack tuple** `(P1, C1, X, S1)` — attack tx out1: the fixed-key input streams are
  **byte-identical: 4,301 B, sha256 `82b0b8cc…9c01a` for both** (pre-salt) → cache hit,
  verification of the invalid `P1` skipped (`prime_verify_test.py`: `(P1, C1, X, S1)`
  → INVALID, as are both crossed contexts; the `min_value == 0 && !IsUnspendable()`
  check is likewise skipped — the bare-`6a` script is unspendable anyway).
  **Keying subtlety:** the key's asset field is the expanded 33-byte *generator* `X`,
  not the on-wire `01‖asset_id` (§2.2); keyed naively on the on-wire serialization
  the streams diverge (`collision_test.py` TEST 2b) — the attacker embedded exactly
  the generator the code computes.
- **Pre-fix keys cannot collide here:** `P0‖C0` (4,199 B) ≠ `P1‖C1` (4,267 B) — Bug A
  *cannot* accept this tuple. **The attack requires the fixed code.**
- The 69-byte script is the *minimum* that hides the 68-byte pivot inside a single
  push: 1 push-opcode byte + 67 payload bytes ≥ 2 + 33 + 33; the final `6a` carries the
  69th byte across the boundary to become `S1`.
- `P0` doubles as a parseable prefix for `P1` (same ring size; the 68-byte tail lands
  in this proof format's trailing message/padding field) — belt-and-braces, since `P1`
  is never parsed on the attack path at all.

---

## 3. The cryptographic primitive the bug exposes

A Pedersen value commitment `C = v·G + r·H` binds a value `v` to a specific asset
generator `G`; a rangeproof `P` for `(C, G, S)` additionally binds the output's
scriptPubKey `S` as message entropy. The attack tx's out1 commits (under the L-BTC
generator `X`) to a huge **negative** value — a rangeproof for it cannot exist. The
cache bug lets the attacker substitute the *verification result* of a genuinely valid
primer output `(P0, C0, X, S0)` for the forged one `(P1, C1, X, S1)`: under the fixed
key the two tuples hash identically (§2.4), so the second verification is never run.
The generator is the *same* in both contexts — no commitment/generator confusion is
required; the ambiguity lives purely in the cache-key encoding.

This turns a per-node performance cache into a network-splitting consensus oracle:
**primed nodes accept, unprimed nodes reject, and the difference is invisible in the
block data itself.**

---

## 4. The attack as observed on-chain

### 4.1 Actors / artifacts

| Item | Value |
|---|---|
| Crafted commitment `C1` | `086f5d67160fc4b477954fb09ef321e5b589d7a07740a1a6df494ed2335b1d01d8` |
| Crafted rangeproof `P1` | sha256 prefix `6619fa29…`, 4,234 bytes (= `P0 ‖ C0 ‖ X ‖ 6a 43`; §2.4) |
| Attack tx (mined) `V1` | `f24a4b179b5cc7e88b25a763911f7cbdf2bf45d1d1b5ab611e94461cef0a183f` @ block 4050336 |
| Double-spend variant `V2` | txid `a1669379f6204f066320974effeefcad2d758fa8ee408c35ae07bc8580c4abe9` (raw bytes recovered from the network; never mined) |
| Priming dry-run pair | `71c93d43…f411` and `27114710…7ec5` @ 4050335; identical explicit-L-BTC OP_RETURN outputs `(P0, C0, X, S0)`, `S0 = 6a 43 ‖ C1 ‖ X ‖ 6a`, `X` = L-BTC generator serialization (§2.4) |
| Laundering tx | `46f117c9…` @ 4050344 (peg-out 2.65138358 BTC) |
| Peg-out tx | `ce4caece413cd9d444ce7ed9f54e5b328b3da5e4af301aff59a3571f76e988f2` @ 4050349 (peg-out 3,996.01834922 BTC) |
| Federation mainnet payout | `8db751a650ae2f12006b7e8c69a75e4df360e8afd6b9e05ae0b9fa6458a7b140`, first seen 2026-09-06 14:25:13 UTC, confirmed BTC block 965783 (14:28:56 UTC), 83 in / 13 out, 4,019.44 BTC total — **verified via blockstream.info 2026-09-07**: out0 pays `bc1qgsl…wt7p` exactly 3,996.01834922 BTC, out1 pays `bc1qkxwv…h98my` exactly 2.65138358 BTC (both attack destinations, exact peg-out amounts); no OP_RETURN output |
| Attacker BTC destinations | `bc1qkxwva32eh7mgezq5kladncd3n5wtcjmslh98my` (2.65) / `bc1qgslsydz56d0ed6827hdemfmk5w2f6ldyc6wt7p` (3,996.02) — both received the exact peg-out amounts and were emptied within ~20 min |

### 4.2 Timeline (UTC)

- **08-03** fix authored (`c26d719c29`)
- **08-03** fix commit authored (`c26d719c29` git author date) — internal knowledge ~4 weeks pre-attack; **09-01** merged to `master`; **09-02** cherry-picked to `elements-23.x` (`6253d7e103`); **09-03/09-04** the `elements-23.3.x` cherry-pick (`212c43f475`) and its backport PR #1599 become public. **No release ever tags the fix.**
- **09-06 ~12:30–12:39** blocks 4050334–4050335 (valid on both future sides). `71c93d43…f411` and `27114710…7ec5` in 4050335 carry *identical* explicit-L-BTC OP_RETURN outputs `(P0, C0, X, S0)` — the primer tuple (§2.4): the first copy stores cache entry `K` on every fixed-code mempool that verifies it, and the duplicate reads `K` back — a live end-to-end dry run of the cache-hit path on the functionaries' own nodes, minutes before the attack.
- **~12:40** block 4050336 `e1d9a2aa…` mined with `f24a4b17…183f` (`V1`). **Fork.** Acceptance by the signing functionaries identifies their builds as **unreleased fixed code with primed caches** — pre-fix code cannot accept this tuple (§2.4, §4.5).
- **~12:44** `46f117c9…` @4050344: 2.65138358 BTC explicit `sendtomainchain` OP_RETURN.
- **~12:49** `ce4caece…f2` @4050349: 3,996.01834922 BTC explicit `sendtomainchain` OP_RETURN.
- **~13:11** invalid side still growing: `0b4505c7…` @4050367 (header nTime 14:24:10Z), ~31 blocks past the fork — independent node log (§4.5, §8).
- **14:25:13** functionaries' batched withdrawal `8db751a6…b140` first seen on Bitcoin mainnet (confirmed block 965783, 14:28:56 UTC) — pays both destinations (consistent with the ~102-block peg-out maturity counted on the *accepting* chain).
- **14:25:49 / 14:41:35** attacker forwards the proceeds (`85d2ca15…`, `22c6afb0…`); the 3,996 BTC is split 3,995.99999857 + 0.01834922 to fresh addresses.
- **09-07** accepting chain (blockstream.info) at 4050420+; rejecting side (liquid.network's backend) still stuck at tip 4050335 ≈ 26 h later. mempool.space's Liquid instance diverged/unreachable during the incident.

*Note on times:* the timeline above is wall clock; Liquid header nTimes run ~73 min
**ahead** of wall clock (signer clock skew, within the +2 h consensus bound — an
independent node log records headers 4050335 = 13:52:10Z, 4050336 = 13:53:10Z,
4050367 = 14:24:10Z). The wall-clock anchor is the federation's Bitcoin payout at
14:25:13Z, which requires the peg-outs to be ~100+ accepting-side blocks deep,
placing the real attack time at ≈ 12:40Z.

### 4.3 Anatomy of `V1` (f24a4b17…183f), from raw bytes

| out | asset | value | scriptPubKey | proof |
|---|---|---|---|---|
| 0 | explicit L-BTC | committed `08360f95…` (the **huge positive** ≈ 4.18e18 sats; valid proof) | p2wpkh `f590…` (attacker) | 4,174 B, VALID |
| 1 | explicit L-BTC | committed **`086f5d67…` = C1** (the **crafted negative** ≈ −4.18e18) | **`6a` (OP_RETURN)** | 4,234 B, **INVALID** — never verified on the attack path (cache hit, §2.4) |
| 2 | committed asset `0b0957be4c…` | committed `08dc50cf…` | p2wpkh `f590…` | 4,174 B, VALID |
| 3 | explicit L-BTC | **58 sats** | empty (fee) | – |

Balance: input `0fbde521:2` (legit, pre-fork) vs `C_out0 + C_out1 + C_out2 + 58·H_L`.
`C_out0` commits to a huge **in-range** positive value — its rangeproof is honestly
generated and *valid* (rangeproofs prove `0 ≤ v < 2^64`, nothing about inputs). `C1`
commits to the corresponding huge **negative** value — its proof cannot exist, and it is
the one that rides the cache. The invalid output is deliberately `OP_RETURN`
(unspendable), which also exempts it from the `min_value == 0 && !IsUnspendable()`
rule; the positive side of the forgery sits in the spendable, validly-proven out0.

`V2` (unmined variant `a1669379…`) is byte-identical except the fee output carries
**4,179,340,454,199,820,288 sats = `0x3a00000000000000`** instead of out0 hiding the
value. `V2` is unmineable on *any* version: `HasValidFee` (`MoneyRange(fee)`,
`MAX_MONEY = 21e6 BTC`) has rejected such fees since 2016 — which is presumably why the
attacker switched to the `V1` design (value hidden in a *confidential* output, where no
explicit-value range check applies). The reused magnitude `0x3a00000000000000` matches
the crafted negative commitment in both variants.

Empirical verification (local libsecp256k1-zkp via ctypes): `P1`/`C1` verifies
**INVALID** under its true context (L-BTC generator `X`, script `6a`) and 20+ plausible
alternates — and it is never verified on the attack path at all: the priming side is
now **fully demonstrated**. `P0` verifies **VALID** against `(C0, X, S0)`; the primer
and attack fixed-key input streams are byte-identical (4,301 B, sha256
`82b0b8cc…9c01a`; `collision_test.py`, §2.4) while the pre-fix keys differ. The live
primer never needed to be mined: it only had to be mempool-live on the accepting
nodes in the ~60 s era before 4050336 connected (§2.3, §4.5, §6).


### 4.4 Why `HasValidFee` / `MoneyRange` don't save the network

- The fee check only constrains *explicit fee outputs*; `V1`'s fee is 58 sats.
- `CheckTransaction`'s per-output `MoneyRange` applies to *explicit* values; the forged
  amounts live entirely inside *commitments*, which no sanity check can range-check —
  that is precisely the rangeproof's job, and it was cache-bypassed.
- The huge explicit values only appear *after* laundering, in `sendtomainchain`
  OP_RETURN peg-out outputs: 2.65 BTC and 3,996 BTC — both `< MAX_MONEY`, so even those
  pass.

### 4.5 Node-level behavior matrix (why the split persisted)

| node software / state | on `V1` in mempool | on block 4050336 |
|---|---|---|
| pre-fix release (≤ 23.3.3), any cache state | reject (real verify fails — pre-fix keys provably differ, §2.4) | **reject block** |
| fixed code (post-`c26d719c29` build), cold cache | reject (miss → real verify fails) | **reject block** |
| fixed code, primer entry `K` live in cache | accept (hit, no erase) | **accept** (hit, entry erased) |

The fork sides therefore identify the running software *inversely* to the first-reading
assumption: the **accepting** side (the signing functionaries, blockstream.info's
backend) ran **unreleased fixed code with primed caches**; the **rejecting** side is
every node without the live entry — all pre-fix releases, plus any fixed build that
never saw the primer. Rejecting nodes never see a valid heavier chain (the
functionaries kept building on the invalid chain — their own nodes were primed), so
their tip freezes at 4050335: exactly what liquid.network's backend shows a day later.

Era mechanics (§2.3): the dry-run entries from 4050335 were erased when that block
connected, so the attack required a live primer in the accepting mempools in the
~60 s before 4050336 connected. The other five non-coinbase transactions in 4050336
were fetched from the accepting-side explorer and parsed (`09016269…`, `c652a104…`,
`efa5e6e6…`, `5707d0ce…`, `2817e839…`): **none carries the primer tuple** — the live
primer was never mined and is identifiable only in accepting nodes' mempool
acceptance logs. On pre-fix nodes the same primer is a harmless, valid tx.

Consistent confirmation of this partition: a published node log from a fresh-sync
node running `elements-23.3.4rc1` (tagged 2026-07-01 — **pre-fix code**) shows
`ConnectTip: ConnectBlock e1d9a2aa… failed, block-validation-failed` at height
4050336, its tip frozen at `aad24e4f…`@4050335, and the invalid side observed at
`0b4505c7…`@4050367 — "~6 blocks longer than our best chain" (artifact
`coldsync_2334rc1_rejection.png`; the log's `date=` fields are header nTimes, which
run ~73 min ahead of wall clock — see §4.2 note). Under the corrected mechanism this
is the *required* behavior of pre-fix code; a cold-synced fixed build would reject
identically (no live entry). Acceptance is a property of (fixed code ∧ live primed
entry) — cf. §5.2 item 8.

### 4.6 Pre-fork dry run

`71c93d43…f411` and `27114710…7ec5` (both @4050335) contain *identical* explicit-L-BTC
OP_RETURN outputs: same 4,166-byte proof `P0`, same commitment `C0` = `09d6c615…83f5`,
explicit L-BTC asset (→ generator `X` in the fixed key), same 69-byte script
`S0 = 6a 43 ‖ C1 ‖ X ‖ 6a`. The output genuinely verifies (VALID, min=0, max=2^52−1,
re-verified 2026-09-07) — so on fixed-code nodes the first copy **stores** cache entry
`K`, and the duplicate in the sibling tx **reads `K` back** (identical key, no
re-verification): a live end-to-end dry run of the cache-hit path on the
functionaries' own mempools, in the last block before the attack. The "34-byte blob"
that resisted decoding in the first analysis is now fully identified: it is `X ‖ 6a` —
the **L-BTC generator serialization** (byte-exact reproduction via the
Shallue–van de Woestijne map, §2.4) plus the script's final opcode — planted as inert
script data so it re-enters the key stream at exactly the offsets where the attack
tuple places its commitment and generator fields. Byte forensics (`prooflen_test.py`,
`collision_test.py`): the attack's crafted proof is exactly `P0 ‖ C0 ‖ X ‖ 6a 43`
(§2.4). Liquid uses the original Borromean-style CT rangeproofs (kilobyte-scale; size
varies with encoding parameters and message), so the 4,166/4,174/4,234-byte sizes are
all legitimate, and verification is exact-length — truncating or extending `P0` by
even one byte makes it INVALID (relevant to the dry run's own validity; `P1` is never
parsed on the attack path).

---

## 5. Affected versions

- **Every released Elements version carries Bug A** (context-omitting key, 2019 →
  `elements-23.3.3`): the fix exists only on the `master`, `elements-23.x`,
  `elements-23.3.x` branches (merged 2026-09-01..03). Verified:
  `git tag --contains {c26d719c29,6253d7e103,212c43f475}` → no release tags.
  Latest releases (`elements-23.3.3`, `23.3.4rc1`, `23.4.0rc3`, `29.4.1rc1`) predate it.
- **Every build of the fix carries Bug B** (ambiguous key encoding, §2.2) — the bug
  actually exploited — and **no branch contains a delimiting follow-up** (verified
  2026-09-07: `git log --all -- src/script/sigcache.cpp` shows the three fix variants
  as the only changes since 2024; the ambiguous raw-concat key is present in all).
  Any node running the patch — including the functionaries' 23.3.4rc2-era builds — is
  exploitable again today by re-priming.
- Any sidechain based on Elements with confidential assets enabled is consensus-affected
  the same way; both bugs are in shared consensus code, not Liquid-specific config.
- **Severity: critical (×2).** Remote, unauthenticated, splits the network
  deterministically per-node-cache-state, and on Liquid enabled direct theft of
  federation BTC via peg-outs.


### 5.1 Adjacent-code audit (2026-09-07): no other critical bugs found

A targeted audit of the surrounding consensus code (master `c7e856fab1` and
`c26d719c29~1`) found **no additional unfixed vulnerability of the same class**.
(Candidly: this audit compared pre- and post-fix code for additional *distinct* issues
and did not itself spot the key-encoding ambiguity the fix introduced — Bug B, §2.2 —
which was identified by an independent researcher; see §5.2 items 7–8.):

- **Only two proof caches exist** (rangeproof, surjection). The surjection cache key
  was always safe (wtxid-bound, see §2.2). The ECDSA/Schnorr `SignatureCache` uses
  upstream Bitcoin keying — sighash commits to all relevant context.
- **Single priming vector confirmed:** `VerifyAmounts` is called only from
  `Consensus::CheckTxInputs` (tx_verify.cpp:250) — mempool acceptance
  (`cacheStore=true`) and `ConnectBlock` (`cacheStore=false`). `testmempoolaccept`
  would also store cache entries but requires RPC auth; `CTxMemPool::check` is a
  local sanity routine. No block-relay or orphan path stores entries.
- **`HasValidFee`** (confidential_validation.cpp:33): per-fee-output `fee > 0` and
  `MoneyRange`, plus cumulative per-asset `MoneyRange` — no overflow possible
  (output count is weight-bounded). Note: consensus does **not** restrict the fee
  *asset* (fees may be paid in any asset; only mempool policy requires the policy
  asset). By design, but worth documenting.
- **Explicit values:** `CheckTransaction` enforces per-output `< MAX_MONEY` *and* a
  cumulative `MoneyRange` over all explicit outputs (CVE-2010-5139 lineage).
  Explicit issuance amounts must be `> 0`, and `MoneyRange` is enforced when the
  issued asset is the pegged asset (`VerifyIssuanceAmount`). Confidential issuance
  amounts use rangeproofs that went through the same (formerly buggy) checker —
  covered by the same fix.
- **Consequence landmine (not a separate vuln, and *not* addressed by the fix):** the
  erase-on-read semantics (`Get(entry, /*erase=*/!store)`) mean a node that accepted
  the invalid block *consumed* its cache entry. On reorg disconnect/reconnect, or on
  the startup `-checkblocks` re-validation of recent blocks (which re-runs
  `ConnectBlock`), such a node **fails to re-validate the very block it accepted**
  and errors out (forcing a reindex onto the honest chain). Restarting also wipes
  the cache. This explains part of the observed post-attack network behavior and
  means accepting-side infrastructure is fragile until patched and reindexed.

### 5.2 Adjudication of alternative root-cause theories (rev. 2, 2026-09-07)

Because the completeness of `c26d719c29` determines which nodes were (and remain)
exploitable, every candidate residual gap and every public alternative theory was
tested. Rev. 2 corrects two verdicts of the first revision: the concatenation-
ambiguity mechanism (item 7) is **exploitable**, and the third-party "the fix
introduced the exploited bug" claim (item 8) is **confirmed**; both corrections
follow from the byte-level reproduction in §2.4.

1. **Degenerate key component from the caller?** No. For outputs with *explicit* assets,
   `VerifyAmounts` serializes a generator derived from the asset ID
   (`confidential_validation.cpp:380-384`); for committed assets it passes the parsed
   generator bytes. The new key component is unique per asset in both cases, so the
   post-fix key is context-complete for tx outputs (and for issuances, which pass the
   serialized generator and an empty script — also the complete verification context).
2. **Partial cherry-picks?** No. The `elements-23.x` (`6253d7e103`) and
   `elements-23.3.x` (`212c43f475`) cherry-picks change exactly the same lines as master.
3. **Surjection cache still context-confusable?** No. It has been keyed on
   `salted(wtxid ‖ proof ‖ output_generator)` since 2018 (`4815bc62cd`), and that code
   is present in `elements-23.3.3`; the wtxid transitively binds the input-tag set.
4. **Deployed libsecp256k1-zkp verifies the crafted proof differently?** No. The tree
   pinned by `elements-23.3.3` (`443b7094…`) differs from master's (`d0854d8b…`) inside
   the rangeproof module, but the diff is a behavior-preserving refactor (`hash_ctx`
   threading, serialization helpers, memclear hardening). The 23.3.3-pinned library was
   built from the vendored tree (`/tmp/secp2333/`) and the verification harness re-run
   (`verify_2333lib.py`): `P1`/`C1` under (`H_L`, `6a`) is still **INVALID**, and all
   legitimate control proofs in the same txs verify VALID — byte-identical conclusions
   to the master build.
5. **Priming a patched node through an identical key?** *Possible* — this is exactly
   Bug B. Post-fix, equal cache keys no longer imply equal verification contexts,
   because the key encoding is ambiguous (item 7): the attacker's two tuples have
   different contexts but identical key byte streams (§2.4). What remains true: a
   restart wipes the cache (per-process salt), so a primed entry cannot survive a
   restart; and priming requires mempool acceptance in the same inter-block era
   (§2.3).
6. **The August 2026 secp256k1-zkp update is the "real" fix / the split cause?** No.
   The subtree bump `95b983597a..a2b001cc20` (merged 2026-08-14, `9bc77876a3`;
   deployed to 23.3.x/23.x/29.x on 2026-08-21 via #1585/#1586/#1587) hardens
   surjection-proof *generation* against s-value (nonce) reuse — its own code
   comments state the goal is preventing distinct proof inputs from reusing any
   s-value — plus memclear/serialization hardening and a module sync. Verification
   code is untouched except behavior-preserving `hash_ctx` threading
   (`surjectionproof_verify` and `rangeproof_verify` both merely pass the context's
   hash state into the unchanged message-generation and shared Borromean-verify
   path). Master's vendored tree is byte-identical to `a2b001cc20`
   (`git diff 644c14d263 master -- src/secp256k1` = ∅), so the deployed-lib
   equivalence test (item 4) already covers this update end-to-end: the attack
   proof stays INVALID and every control proof VALID. Generation-side nonce
   hardening cannot mint value and cannot split consensus.

7. **Cache-key concatenation ambiguity via field-boundary shift?** **Confirmed —
   this is the exploited mechanism.** Rev. 1 of this report dismissed it ("the fields
   adjacent to the variable-length proof are fixed at 33 bytes … pinning the split
   point"), which was wrong: it considered only the proof↔commitment boundary. The
   fixed key is `proof ‖ commitment(33) ‖ generator(33) ‖ script`, and the *second*
   variable-length field — the scriptPubKey — sits at the opposite end, so the
   proof↔script boundary is **not** pinned: shifting `k` bytes from the script's head
   to the proof's tail preserves the entire byte stream, while the two fixed middle
   fields are kept byte-identical by embedding the attack's `C1` and the generator
   `X` inside the primer's script (§2.2, §2.4). No elliptic-curve grinding is
   required — the construction relocates existing bytes, so rev. 1's objection that
   "commitments/generators cannot be ground to forced byte patterns" is moot, and the
   per-process salt is irrelevant (both keys are computed in the victim's process).
   Rev. 1's empirics remain true but inapplicable: verification is indeed
   exact-length (`prooflen_test.py`), but the colliding proof `P1` is never verified
   on the attack path; and "the attack pair shares no key stream with the dry-run
   pair" measured the *pre-fix* streams — under the fixed key the streams are
   byte-identical (`collision_test.py`: 4,301 B both, sha256 `82b0b8cc…9c01a`).
8. **Did `c26d719c29` introduce the exploited vulnerability? (independent
   researcher's claim, 2026-09-07)** **Yes — confirmed and reproduced.** The
   third-party analysis argued: the *fixed* key is a raw, undelimited concatenation
   `proof‖commitment‖asset‖script`; the attacker stretched the proof and shrank the
   script so the exploit tuple and a dry-run primer tuple hash to identical bytes;
   therefore the accepting side ran the fixed code and the fork attribution is
   inverted. Every element checks out byte-for-byte (§2.4): the fixed-key streams
   are identical (4,301 B, sha256 `82b0b8cc…9c01a`), the pre-fix keys are not, and
   the planted generator `X` is byte-exactly `secp256k1_generator_generate(L-BTC)`
   (`gen_check.py`). The attribution correction stands: the accepting side —
   functionaries included — ran unreleased fixed code with primed caches; the
   rejecting side ran pre-fix releases or unprimed fixed builds. This report's
   rev.-1 rebuttal ("under the fixed key the primed entry is unreachable") was
   wrong because it assumed the attacker replayed the `(P, C)` pair verbatim; the
   actual construction shifts the proof/script boundary, which rev.-1 item 7 had
   dismissed. Two details of the third-party account need correction: (a) the
   key's "asset" field is the 33-byte *generator serialization*
   (`confidential_validation.cpp:381-388`), not the raw asset id — immaterial to
   the mechanism, material to reproducing it; (b) an earlier claim from the same
   source that release `23.3.3` *accepted* the attack block is inconsistent with
   pre-fix code (the pre-fix keys provably differ and the real verification
   fails, §2.4/§4.3) and is superseded by the same author's later fresh-sync
   `23.3.4rc1` rejection log (§4.5), which is exactly what the corrected
   mechanism predicts. The pre-fix Bug A (context omission, `0b5066143d`,
   2019-03-19, 99 release tags) remains real and unfixed in every release — but
   it is not what was exploited on 2026-09-06.

Corroborating timeline: the `elements-23.3.x` backport of exactly this fix was
queued **pre-attack** as PR #1599 (opened 09-04 by psgreco: "All clean cherry picks
from 23.x branch, in preparation for 23.3.4rc2"; 12 cherry-picks, the cache fix
`212c43f475` first; ACKs tomt1664 09-05, delta1 09-06) and merged attack-day evening
(`3b3f01eac9`, 2026-09-06 19:20:55 +0200, merge-script) — the only attack-day commit
activity on public branches (as of 2026-09-07). The vendor's conduct is consistent
with having treated Bug A as a low-severity cache-correctness issue, having raced
the fix onto its own infrastructure ahead of release (dogfooding — precisely what
made the functionaries exploitable via Bug B), and not having recognized the
key-encoding ambiguity: post-attack the fix was neither reverted nor hardened, and
as of this writing **no delimiting follow-up exists in any branch**
(`git log --all -- src/script/sigcache.cpp`).

**Residual operational exposure:** Bug A is live in every released version; Bug B is
live in every build of the fix; and the patch leaves the fragile cache-as-consensus
design in place (erase-on-read footgun, §2.3) rather than removing the rangeproof
cache from the consensus path. Until a delimiting fix (or cache removal) ships, the
network is one primed mempool away from a repeat — against *whichever* keying the
victim runs. Rev. 1's "residual gap" caveat (accepting nodes possibly running fixed
builds) is no longer hypothetical: it is the established mechanism (§2.4), and the
remaining unknowns are which exact builds the functionaries ran and what their
mempool logs show (§6).


---

## 6. Open items / limitations

1. **Live priming transaction mempool-only — now the expected shape, not a gap.**
   Cache-era mechanics (§2.3) require the primer to be mempool-live on the accepting
   nodes in the ~60 s before 4050336 connected; it never needed to be mined.
   Consistent with that: the **1,500-block (~25 h) pre-fork scan** on the valid chain
   (`scan_back.py`, `DONE found=[]`) found no `C1` and no blob bytes except the
   4050335 dry-run pair, and **all five other non-coinbase txs of 4050336** were
   fetched and parsed (§4.5) — none carries the primer tuple. Only the accepting
   nodes' mempool acceptance logs / `debug.log` can identify the live primer.
2. Which exact builds the accepting functionaries/explorers ran — established to be
   **post-fix, unreleased** (23.3.4rc2-era; §2.4, §4.5), but the precise commit set
   and deployment date can only be confirmed by the vendor.
3. Whether `V2` was ever broadcast on the P2P network or only seen by one explorer
   backend; its purpose is inferred (first-generation design, killed by `HasValidFee`).
4. mempool.space's Liquid backend was unreachable during analysis; its fork position
   could not be re-confirmed today.
5. ~~The cryptographic demonstration is one-sided~~ **Resolved (rev. 2):** the
   priming context is demonstrated — `P0` verifies VALID against `(C0, X, S0)` and
   `(P1, C1, X, S1)` verifies INVALID (`prime_verify_test.py`), the fixed-key streams
   of the primer and attack tuples are byte-identical, and the pre-fix streams
   differ (`collision_test.py`, §2.4).

---

## 7. Recommendations

1. **Do not ship the current patch as-is — it does not close the exploited hole.**
   Emergency release of all maintained branches with a *corrected* fix: serialize the
   rangeproof-cache key with unambiguous field boundaries (length-prefix each field,
   or hash each field separately and hash the concatenation of the digests) — or
   remove the rangeproof result cache from the consensus path entirely. Until then
   **both** keyings are exploitable (Bug A in every release, Bug B in every patched
   build) and the attack is repeatable by re-priming with fresh tuples (§2.4).
2. **Node operators:** restarting clears the primed cache but does not by itself resolve
   the split; accepting-side nodes must `invalidateblock e1d9a2aa…` (and everything on
   top) after upgrading to rejoin the valid chain. Caveat for **functionaries**:
   Liquid's blocksigners remember prior signing state and refuse reorgs deeper than
   one block, so abandoning the invalid chain on the signing side additionally
   requires an authorized override of that signer protection — `invalidateblock`
   alone does not move the federation.
3. **Functionaries / watchmen:** halt peg-out processing while the network is split;
   the 14:25 payout shows watchmen maturing peg-outs on a chain that honest unprimed
   nodes reject. Consider requiring N-of-M oracle agreement on best chain before
   signing withdrawals.
4. **Defense in depth (code):**
   - The context-in-key direction is right but insufficient on its own; add consensus
     regression tests: (i) two tuples related by a shifted proof/script boundary must
     never share a cache key; (ii) same `(proof, commitment)` under a different asset
     and script must fail.
   - `CachingSurjectionProofChecker` was audited and is safe (key includes the wtxid,
     which commits to all generator context); a dedicated regression test is still
     worthwhile to lock that property in.
   - Consider skipping the rangeproof-result cache during block validation entirely
     (verification is cheap relative to Liquid's 1-minute blocks).
   - **Length-delimit the rangeproof-cache key fields (or hash each field
     separately) — required, not optional.** The undelimited encoding is the
     exploited bug (§2.2, §5.2 item 7): with variable-length fields at both ends
     of the stream, no fixed-width interior field can pin the boundary.
   - Consider `MoneyRange`-style caps for *peg-out* OP_RETURN explicit values
     (per-output and per-block) — that alone would have stopped the 3,996 BTC output
     even with the cache bypassed.
5. **Disclosure process:** the fix was authored 2026-08-03 and sat unmerged for ~4
   weeks, then was public, clearly titled, and easily diffable for 3–5 days
   pre-attack ("Fix caching bug in rangeproof caching") — effectively a published
   exploit recipe. For consensus-critical crypto/cache fixes, consider
   embargoed or low-visibility landing (merge at release time), as practiced for
   Bitcoin Core CVEs. A second process failure compounded the first: the patch was
   **deployed to the signing functionaries before any release and before
   adversarial review of the patch itself** — and it was the deployment, not just
   the publication, that enabled the attack (pre-fix nodes could never have
   accepted the crafted tuple, §2.4). Rushing consensus-touching patches onto the
   signing set ahead of release converts every latent bug *in the patch* into a
   federation-level incident.

