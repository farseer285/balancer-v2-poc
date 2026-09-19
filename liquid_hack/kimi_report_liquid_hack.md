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
- `Set` is called only on successful verification (no negative caching). `Get(entry,
  /*erase=*/!store)` *requests* erase during block validation (`store == false`) and
  keeps the entry during mempool acceptance (`store == true`) — but CuckooCache's erase
  is **lazy** (§2.3), so even the block-validation read does **not** actually remove the
  entry; it only marks the slot reusable for a later insert.
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
  read with `Get(entry, /*erase=*/true)` and nothing new is stored (`store == false`).
  The `erase=true` does **not** consume the hit: CuckooCache's erase is **lazy** —
  `contains(key, /*erase=*/true)` calls `allow_erase(loc)`, which only sets a
  `collection_flags` bit and *still returns the hit*; the element physically stays in
  `table[loc]` and keeps matching until a **future `insert` reuses that slot**
  (`cuckoocache.h:28` "Elements are lazily erased on the next insert"; `:152`
  "`allow_erase` … the real discard happens later"). So a block-connect read leaves the
  entry in place.

Consequences (corrected for lazy erase; an earlier revision assumed eager
erase-on-connect, which the source refutes): (i) only mempool acceptance primes
(`ConnectBlock` runs `store == false` and never inserts); (ii) once planted, `K`
**persists across its own block-connect and across many later blocks** — until some
`insert` happens to overwrite that slot, rare on low-volume Liquid — so there is **no
"same inter-block era" constraint** and the exploit's block-timing window is **wide**: a
forged `V1` in block N+1, N+2 or N+k all still hit `K`. This is the article's plain
memoization model and matches the on-chain data; (iii) because the entry is not
consumed, a node **can** re-validate the block it accepted (a reorg disconnect/reconnect
*without a restart* still finds `K`); the residual fragility is that the cache is
per-process and **wiped on restart** (§5.2), not that reads consume entries. The real
driver of the persistent split is therefore **which nodes ever mempool-accepted the
primer** (→ `K` inserted), not any erase timing; (iv) `testmempoolaccept` would also
store entries but requires RPC auth; no block-relay or orphan path stores.

### 2.4 The attacker's byte-level construction (reproduced from on-chain data)

All four alignment identities hold **byte-exactly** (`collision_test.py`, 2026-09-07):

```
X  = 0a ‖ 0a488de4899d0ae757f6cf8368663184d164106111ed9eaecf510e35282ddc6d
   = secp256k1_generator_generate(L-BTC asset id 6f0279e9…526d), byte-exact —
     independently reproduced via the Shallue–van de Woestijne map with the two
     tagged-hash candidates ("1st/2nd generation: ") → MATCH (gen_check.py)
S0 = 6a 43 ‖ C1 ‖ X ‖ 6a            (69 B = OP_RETURN + push opcode 0x43 + 67 B payload)
P1 = P0 ‖ C0 ‖ X ‖ 6a 43            (4,234 B = the 4,166 B primer proof + 68 B tail)
S1 = 6a                             (1 B, bare OP_RETURN)
```

- **Primer tuple** `(P0, C0, X, S0)` — the explicit-L-BTC OP_RETURN output of the
  primer txs (§4.6): `P0` verifies **VALID** against `(C0, X, S0)`
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
| Primer pair | `71c93d43…f411` and `27114710…7ec5` @ 4050335; identical explicit-L-BTC OP_RETURN outputs `(P0, C0, X, S0)`, `S0 = 6a 43 ‖ C1 ‖ X ‖ 6a`, `X` = L-BTC generator serialization (§2.4) |
| Laundering tx | `46f117c9…` @ 4050344 (peg-out 2.65138358 BTC) |
| Peg-out tx | `ce4caece413cd9d444ce7ed9f54e5b328b3da5e4af301aff59a3571f76e988f2` @ 4050349 (peg-out 3,996.01834922 BTC) |
| Federation mainnet payout | `8db751a650ae2f12006b7e8c69a75e4df360e8afd6b9e05ae0b9fa6458a7b140`, first seen 2026-09-06 14:25:13 UTC, confirmed BTC block 965783 (14:28:56 UTC), 83 in / 13 out, 4,019.44 BTC total — **verified via blockstream.info 2026-09-07**: out0 pays `bc1qgsl…wt7p` exactly 3,996.01834922 BTC, out1 pays `bc1qkxwv…h98my` exactly 2.65138358 BTC (both attack destinations, exact peg-out amounts); no OP_RETURN output |
| Attacker BTC destinations | `bc1qkxwva32eh7mgezq5kladncd3n5wtcjmslh98my` (2.65) / `bc1qgslsydz56d0ed6827hdemfmk5w2f6ldyc6wt7p` (3,996.02) — both received the exact peg-out amounts and were emptied within ~20 min |

### 4.2 Timeline (UTC)

- **08-03** fix authored (`c26d719c29`)
- **08-03** fix commit authored (`c26d719c29` git author date) — internal knowledge ~4 weeks pre-attack; **09-01** merged to `master`; **09-02** cherry-picked to `elements-23.x` (`6253d7e103`); **09-03/09-04** the `elements-23.3.x` cherry-pick (`212c43f475`) and its backport PR #1599 become public. **No release ever tags the fix.**
- **09-06 ~12:30–12:39** blocks 4050334–4050335 (valid on both future sides). `71c93d43…f411` and `27114710…7ec5` in 4050335 carry *identical* explicit-L-BTC OP_RETURN outputs `(P0, C0, X, S0)` — the primer tuple (§2.4): the first copy stores cache entry `K` on every fixed-code mempool that verifies it, and the duplicate independently re-plants the same `K` (hitting it on its own mempool acceptance) — **redundancy / insurance** so at least one primer propagates, not a rehearsal (§4.6), minutes before the attack.
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
`82b0b8cc…9c01a`; `collision_test.py`, §2.4) while the pre-fix keys differ. Priming
only needs the primer to be **mempool-accepted** on the fixed-code nodes (that is what
inserts `K`); because the erase is lazy the entry then persists across blocks (§2.3), so
the exploit window is wide rather than a single ~60 s era (§4.5, §6).


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
| fixed code, primer entry `K` live in cache | accept (hit, no erase) | **accept** (hit; entry **not** consumed — lazy erase) |

The fork sides therefore identify the running software *inversely* to the first-reading
assumption: the **accepting** side (the signing functionaries, blockstream.info's
backend) ran **unreleased fixed code with primed caches**; the **rejecting** side is
every node without the live entry — all pre-fix releases, plus any fixed build that
never saw the primer. Rejecting nodes never see a valid heavier chain (the
functionaries kept building on the invalid chain — their own nodes were primed), so
their tip freezes at 4050335: exactly what liquid.network's backend shows a day later.

Cache persistence (§2.3): because CuckooCache's erase is lazy, the `K` planted when the
4050335 primers were **mempool-accepted** was **not** consumed when 4050335 connected —
it persisted into the ~60 s window before 4050336, where the forged `V1` reused it. No
separate, later live primer was needed. Consistent with this, the other five
non-coinbase transactions in 4050336 were fetched from the accepting-side explorer and
parsed (`09016269…`, `c652a104…`, `efa5e6e6…`, `5707d0ce…`, `2817e839…`): **none carries
the primer tuple** — the key-planting happened at the 4050335 primers' mempool
acceptance, not in 4050336. On pre-fix nodes the same primer is a harmless, valid tx.

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

### 4.6 The pre-fork primer pair (redundancy, not a rehearsal)

`71c93d43…f411` and `27114710…7ec5` (both @4050335) contain *identical* explicit-L-BTC
OP_RETURN outputs: same 4,166-byte proof `P0`, same commitment `C0` = `09d6c615…83f5`,
explicit L-BTC asset (→ generator `X` in the fixed key), same 69-byte script
`S0 = 6a 43 ‖ C1 ‖ X ‖ 6a`. The output genuinely verifies (VALID, min=0, max=2^52−1,
re-verified 2026-09-07) — so on fixed-code nodes the first copy **stores** cache entry
`K`, and the duplicate in the sibling tx, sharing the identical key, **hits `K`** on its
own mempool acceptance (no re-verification). Two independent plantings of the same `K`
are **redundancy / insurance** — the article notes "just one transaction would have
sufficed" and the second "is presumably insurance" — **not a rehearsal or a
discriminating test**: because both proofs are genuinely valid, each is accepted on every
node via a real re-verify even on a cache miss, so nothing about the pair exercises the
cache-hit path in a way an outside observer could distinguish (observability caveat (b)
below). This was the last block before the attack. The "34-byte blob"
that resisted decoding in the first analysis is now fully identified: it is `X ‖ 6a` —
the **L-BTC generator serialization** (byte-exact reproduction via the
Shallue–van de Woestijne map, §2.4) plus the script's final opcode — planted as inert
script data so it re-enters the key stream at exactly the offsets where the attack
tuple places its commitment and generator fields. Byte forensics (`prooflen_test.py`,
`collision_test.py`): the attack's crafted proof is exactly `P0 ‖ C0 ‖ X ‖ 6a 43`
(§2.4). Liquid uses the original Borromean-style CT rangeproofs (kilobyte-scale; size
varies with encoding parameters and message), so the 4,166/4,174/4,234-byte sizes are
all legitimate, and verification is exact-length — truncating or extending `P0` by
even one byte makes it INVALID (relevant to the primer's own validity; `P1` is never
parsed on the attack path).

**Observability — why on-chain confirmation is the go-signal, and what it does *not*
prove.** The event the attacker actually needs — the functionaries' nodes writing `K`
on the `cacheStore=true` mempool-acceptance path (§2.3) — is **not directly
observable**: no p2p or RPC method reports another node's mempool contents or cache
state, and the attacker's own node accepting the primer proves only that *its own*
cache is primed. The single network-wide, publicly observable proxy is **whether the
primer got mined into a block the network accepted** — strong evidence that it
propagated through the p2p mempool layer and was therefore accepted (and primed) by the
well-connected functionary nodes en route. This is the natural trigger for firing `V1`,
and it plausibly explains why primer-tuple outputs sit in 4050335 at all rather than
only in an unmined mempool tx: they double as an on-chain propagation receipt. Three
caveats keep this a *probabilistic proxy*, not a proof:

- **On-chain ≠ primed.** Priming happens only on the mempool-acceptance path
  (`cacheStore=true`); `ConnectBlock` runs `cacheStore=false` and stores nothing (§2.3).
  A node that first sees the primer *inside the block* (never via mempool relay) is
  therefore **not** primed. Confirmation evidences the *cause* (propagation) that
  primes, not the priming event itself.
- **Non-discriminating.** `P0` verifies VALID against `(C0,X,S0)`, so a mined primer is
  accepted on **every** node — fixed-code (cache hit) and pre-fix (real re-verify)
  alike. On-chain data cannot separate "cache-hit path exercised" from "ordinary
  verification," so the twin 4050335 copies read better as **redundancy / insurance**
  (maximize the chance the key is planted and propagated) than as a discriminating
  rehearsal; the only tx whose acceptance actually discriminates the mechanism is the
  forged `V1`, and broadcasting it *is* the attack.
- **Sound only if `K` outlives the confirming block.** Gating on "primer confirmed in
  block N → fire `V1` into N+1" is viable only if the planted entry survives past N's
  connection. Were the erase eager it would not. But CuckooCache's erase is **lazy**
  (§2.3) — `contains(key, /*erase=*/true)` calls `allow_erase`, which only *marks* the
  slot reusable and leaves the element findable until a later `insert` overwrites it — so
  `K` in fact persists across the connect and the window is wide, not a single
  "inter-block era." Under that lazy-erase behavior the on-chain go-signal is
  straightforwardly usable.

**Manual on-chain check — `waitfornewblock` as trigger + `gettransaction` as probe.**
First, a naming correction: **`waitnextblock` is not an RPC** (absent from `src/rpc/*` —
verified against the `elements` tree). The real block-wait calls are the *hidden* RPCs
`waitfornewblock [timeout_ms]`, `waitforblock <blockhash> [timeout_ms]` and
`waitforblockheight <height> [timeout_ms]` (`src/rpc/blockchain.cpp`); each blocks until
the tip changes and returns only `{ hash, height }` — **none takes a txid**, so a
block-wait alone never confirms the primer. The confirmation itself needs a tx-scoped
call. The natural pairing is therefore **`waitfornewblock` (block-arrival trigger) +
`gettransaction <primer_txid>` (confirmation probe)**, and that combination is valid and
sensible, subject to two conditions:

- **`gettransaction` is wallet-scoped — and on-chain the txs are wallet-shaped, so it
  applies.** *(Verified on blockstream.info, 2026-09-18.)* Both primers (`271147…`,
  `71c93d…`) and the exploit (`f24a4b…`) are **self-funded**: each is a single-input tx
  spending one output (`:0`/`:1`/`:2`) of a common funding tx
  `0fbde521636bd2c3…` (block 4050333, two blocks before the primers), whose 7 inputs and
  3 fan-out outputs are all the attacker's own P2WPKH address
  `ex1q7kgx4ptje7px48tn0nsmc6se5pngdp3smpqa2w`; change on every attack tx returns to that
  same address; fees are 58 sats in L-BTC; only the OP_RETURN payloads (primer `scriptPubKey`
  = 69 B `S0`, exploit = 1 B bare `6a`) are exotic. That is textbook wallet coin-control (a
  deliberate 3-UTXO pre-stage). So if the `ex1q7kg…` key sits in the node's `elementsd`
  wallet, `gettransaction` reports each tx's `confirmations`/`blockhash` with **no
  `-txindex`**. The only thing on-chain data cannot settle is key custody — node wallet vs.
  an external signer + raw assembly; only in the latter case does `gettransaction` return
  "Invalid or non-wallet transaction id", and you fall back to `getrawtransaction <txid>
  true` +txindex, `gettxout`/`scantxoutset`, a `getblock <hash> 2` scan, or an explorer.
  *(Corrects an earlier draft that claimed the byte-level construction made these non-wallet
  txs — the actual on-chain shape is plainly wallet-funded.)*
- **Loop with a confirmation gate, not one-shot.** `waitfornewblock` fires on *any* new
  block, which may not contain the primer:
  `gettransaction` once; then `while conf < REQUIRED_CONF: waitfornewblock;
  gettransaction`. On Liquid (reorgs ≤ 1 block, `gettransaction` confirmations are
  active-chain-fresh) `REQUIRED_CONF=1` suffices, `2` is the safe choice.

This pattern is exactly the **event-driven form of this repo's default wallet method**:
`broadcast-then-broadcast.sh` polls with `sleep POLL_INTERVAL` + `gettransaction`
(`CONFIRM_METHOD=wallet`); swapping the sleep for a `waitfornewblock` trigger is the
middle rung; `broadcast-then-broadcast-zmq.py` (ZMQ `hashblock`) is the fully
event-driven rung. All three answer the same question — *did the primer propagate and
confirm* (the network-wide go-signal) — and none of them, by construction, proves the
functionaries wrote `K` (that lives in their mempool-acceptance path and is
unobservable; see the caveats above).

**Block-inclusion timing — the adjacency (`f24a4b17…` @4050336, one block after the
4050335 primers `71c93d43…`/`27114710…`) is neither guaranteed by the confirmation
method nor required by the exploit.** A `waitfornewblock`+`gettransaction` gate is purely
*reactive*: it fires `V1` only *after* observing the primer confirmed in block N, then
races the ~60 s Liquid block cadence to land `V1` in N+1. That is a *high-probability*
outcome (a freshly observed N leaves nearly the full ~60 s until N+1) but **not a
guarantee**:

- **Inclusion is the signer's choice, not the broadcaster's.** Which block a tx enters is
  decided by the N+1 proposer's template selection; a broadcaster can bias the odds (fee,
  timing, connectivity) but cannot pin a target block. Detection lag, or a template
  already cut, pushes `V1` to N+2+.
- **`V1`'s propagation is partition-limited to the primed fixed-code subgraph.** `V1` is
  *invalid* on any node without `K` (all pre-fix nodes, and cold-cache fixed nodes) — they
  reject and **do not relay** it. But the primer, being valid, floods everywhere and plants
  `K` on every fixed-code node it reaches, *paving a road*: `V1` can then travel exactly
  that primed fixed-code subgraph. So a plain local `sendrawtransaction` + P2P **does**
  carry `V1` to the signer — *provided the attacker's node is connected into that subgraph*
  (peered with a functionary / Blockstream-infra fixed node); point-to-point delivery
  straight to the signer is only the most reliable form of that, not a hard requirement.
  (Correcting an earlier overstatement that `V1` "must be submitted directly to the
  specific signer".) Either way, `V1` cannot ride the general (mostly pre-fix) network, so
  reaching the *specific* N+1 signer before it cuts its template is topology- and
  latency-dependent — not controllable — which removes "next block" from any broadcast
  method's guarantees.
- **Adjacency is not required.** Because the CuckooCache erase is lazy (`K` persists
  across connects — §2.3 correction above), a `V1` landing several blocks later still hits
  `K`; the observed N→N+1 adjacency is the natural result of prompt/direct submission into
  a 60 s window, not something the gate enforces. Conversely, under an eager-erase model
  reading adjacency *would* be mandatory — and a reactive gate provably cannot guarantee
  it — so the attack's success is itself evidence for the wide-window (lazy-erase) model.
- **Confirmation-gating is stricter than the mechanism needs.** Priming happens at the
  primer's *mempool acceptance*, not its confirmation; to maximize the chance of catching
  a chosen next block one would keep the primer mempool-live (re-broadcasting) and time /
  directly submit `V1`, rather than wait for a confirmation that only arrives later.

**Did the real attacker use the manual `waitfornewblock`+`gettransaction` flow? —
Judgment: possible, but unlikely the actual method.** On-chain data fixes the *sequence*
(primers @4050335 → exploit @4050336) and the adjacency, but not the operator's tooling.
The manual CLI flow is a faithful, working *reconstruction* of that observable sequence,
and `gettransaction` on the attacker's own wallet tx is the simplest confirmation probe
(no `-txindex`). But four features of this operation point away from a hand-typed check
and toward an automated, directly-fed pipeline:

1. **Sophistication + value + a ~60 s window.** Reverse-engineering an unreleased patch, a
   byte-level cache-key collision, ~4,000 BTC at stake, and a one-minute cadence make a
   hand-driven "watch the output, then paste `sendrawtransaction`" flow needlessly
   fragile; such an operator scripts the broadcast-then-broadcast sequence (ZMQ
   `hashblock` / `waitfornewblock` in code — the `.py`/`.sh` rungs above), not eyeballs it.
2. **`V1` can only ride the primed fixed-code subgraph** (partition-limited relay, above),
   so the attacker's node had to be deliberately **connected into that subgraph** (peered
   with a functionary / Blockstream-infra fixed node) — engineered network positioning, not
   a broadcast to random public peers. A plain local `sendrawtransaction` + P2P then
   suffices once the node is so positioned (point-to-point delivery to the signer is only
   the strongest form); either way it is not a generic public broadcast.
3. **The redundant twin primers** read as fire-and-forget robustness (plant `K` on as many
   mempools as possible), a mindset more consistent with an automated, resilient pipeline
   than with careful manual per-step verification.

*(An earlier draft listed a fourth point — that the byte-level tx construction might make
these non-wallet txs, so `gettransaction` would not apply. The on-chain data
**retracts** it: the cluster is plainly wallet-funded and self-financed from one P2WPKH
address, used wallet-style coin-control, and only the OP_RETURN payloads were
hand-crafted — so `gettransaction`-based confirmation is fully viable, and this point no
longer argues either way.)*

On balance: the wallet-shaped self-funding makes the `waitfornewblock`+`gettransaction`
manual flow **entirely viable** and consistent with the data, so it cannot be ruled out.
The two things that still tilt toward a **scripted, well-positioned** run are non-wallet
facts: the ~60 s window against a byte-crafted `V1`, and `V1`'s partition-limited relay
(invalid on unprimed nodes → rides only the primed fixed-code subgraph, so the attacker's
node had to be **positioned inside that subgraph** — via peering or direct submission —
not a generic public broadcast). So: manual confirmation is plausible; a local
`sendrawtransaction`+P2P submission of `V1` is also plausible *if* the node was so
positioned; what is ruled out is `V1` reaching the signer via the general public network.
Tooling and topology are not recoverable from on-chain data — this is inference from
operational constraints, not a forensic fact.

### 4.7 Operator procedure — reconstruction, footprint-identical alternatives, and OPSEC

On-chain data fixes the *sequence* (primers @4050335 → exploit @4050336) and the
one-block adjacency, but not the operator's tooling, network position, or confirmation
method. This section reconstructs the most-likely procedure, shows that several distinct
methods all leave an **identical** on-chain footprint (so none can be proven from the
chain), and reads the OPSEC. Everything here is inference from operational constraints
and verified client behavior, **not** forensic fact; the repo's
`broadcast-then-broadcast.sh` / `-zmq.py` are the *user's* POC tooling, not recovered
attacker artifacts.

**Verified Elements block-wait RPC / CLI facts** (against local official source
`../elements`). The three block-wait calls — `waitfornewblock`
(`src/rpc/blockchain.cpp:347`), `waitforblock <hash>` (`:389`), `waitforblockheight <N>`
(`:443`) — are all registered under the **`"hidden"`** category (`:3797`–`:3799`, so
`help` never lists them). Each blocks on `miner.waitTipChanged` and returns only
`{ hash, height }` of the **tip**; **none takes a txid**, so a block-wait alone can never
confirm a specific primer — a tx-scoped call (`gettransaction` / `getrawtransaction` / a
block scan) is always required. Their `timeout` argument is in **milliseconds** (`0` =
block indefinitely). Separately, `elements-cli`'s own `-rpcclienttimeout` is a
**client-side HTTP timeout in seconds** (`src/bitcoin-cli.cpp:99`, default
`DEFAULT_HTTP_CLIENT_TIMEOUT = 900` = 15 min; `=0` is implemented as ~5 years because
libevent cannot express true-infinite, `:858`–`:866`). A blocking `waitfor*` therefore
needs **both** timeouts set (server-side ms `0` *and* client-side `-rpcclienttimeout=0`),
or the CLI disconnects at 900 s before the block arrives.

**Reconstructed most-likely manual flow.** The article documents none of the operator
procedure, so this is an informed reconstruction of the observed sequence:

- **Phase 0 — offline prep:** construct and sign both primers and the exploit; keep the
  raw hex ready; own `elementsd` synced to the Liquid tip; an Esplora explorer open as a
  visual second-eye. (Byte-crafting the 4,234 B forged proof is the bulk of the work and
  is never done in the live window.)
- **Phase 1 — broadcast primers:** `sendrawtransaction` both (`271147…`, `71c93d…`). Two
  copies are redundancy / insurance (maximize the chance `K` is planted and propagated),
  **not** a rehearsal (§4.6).
- **Phase 2 — the confirm gate (core action):** a **level-triggered, check-first** loop —
  probe the tx *first*, wait only if not yet confirmed, repeat. The authoritative probe
  is a tx-level RPC (`getrawtransaction <txid> true`, or `gettransaction`, which works
  without `-txindex` because the txs are wallet-shaped and self-funded, §4.6) or an
  explorer refresh. A block-wait / sleep is at most an optional early-wake *between*
  probes, and only with a finite timeout. The criterion is coarse: seeing one primer in a
  block is enough.
- **Phase 3 — fire:** immediately `sendrawtransaction <exploit_hex>`; the pre-built hex
  lands in the next block (4050336), well within the ~60 s cadence.
- **Phase 4 — (optional) confirm** the exploit tx / that the funds moved.

**Why a `waitfornewblock`-first gate is the wrong primitive (and why the repo scripts
avoid it).** `waitfornewblock` is both **edge-triggered** (it snapshots the current tip,
then blocks for the *next* change — it never level-checks current state, verified
`blockchain.cpp:347`) and **block-level** (no txid). That yields two independent
footguns: (a) if the primer already confirmed *before* the call, the wait ignores it and
blocks ~60 s for the block *after* — late notice; (b) the block it returns is merely "the
next block after call-time," which may not contain the primer, so "wait returns → assume
primer in it → fire" can fire on a false premise. A human naturally reads *current* state
(refresh the explorer, or run `getrawtransaction` on their own node), so a hand-driven
check is inherently level-triggered and dodges both. The repo scripts are correct to use
`waitfornewblock` **nowhere**: `broadcast-then-broadcast.sh` is a check-first
fixed-interval poll (absolute / idempotent, `TIMEOUT`-bounded, never hangs), and
`broadcast-then-broadcast-zmq.py` uses ZMQ `hashblock` only as a *wake*, with the
authoritative confirm still a tx-level RPC plus a 60 s fallback poll. ZMQ `hashblock` and
`waitfornewblock` are in fact the **same class of signal** — both fire from the same
chainstate tip-update (`zmq/zmqnotificationinterface.cpp:150`–`156`;
`node/interfaces.cpp:1000`–`1006` ← `node/kernel_notifications.cpp:51`–`57`), both
edge-triggered and block-level — differing only in transport (async buffered pub/sub vs.
a blocking RPC condition-variable wait). So if event-driven is wanted, ZMQ is the right
primitive; a bare blocking `waitfornewblock` (server timeout 0) additionally risks
hanging forever across a chain halt.

**Footprint-identical alternatives — the go-signal need not be a confirmation at all.**
Because `K` persists (wide window, §2.3), even a **blind fixed-60 s timer** works:
broadcast a primer at `t0`, wait exactly one block interval, broadcast the exploit, with
*no* confirmation probe. Phase-preservation argument: let `T_next` be the first block
boundary after `t0` (so `T_next ∈ (t0, t0+60]`); if the primer's lead margin
`m = T_next − t0` sufficed to land it in block N, then the exploit fired at `t0+60` has
margin `(T_next+60) − (t0+60) = m` into N+1 — the **same** margin. A fixed 60 s wait thus
*preserves the phase* relative to the block boundary and naturally yields N/N+1. Its only
genuinely fatal mode is broadcasting the primer too close to a boundary, so it slips to a
later block and the exploit fires **before** the primer is mempool-accepted (hitting a
`K`-less node → rejected as invalid); mere block-time jitter only causes an off-by-one to
N+2/N+3, which the wide window forgives. So **poll-then-fire, ZMQ-event and blind-timer
all leave the identical footprint** (primer @N, exploit @N+1); poll-vs-event,
manual-vs-scripted and timer-vs-gate are equally chain-unrecoverable. (A mild lean toward
a confirm-gate over a blind timer: the txs sit in *adjacent* rather than the *same*
block — the natural output of "see primer in N, then fire," since a near-simultaneous
mempool dump would tend to co-locate both in one block, the exploit needing only `K`
already present, not the primer mined. Not dispositive.)

**Manual confirmation cadence (if hand-driven).** A human re-issuing `gettransaction`
would type at ~10–20 s per attempt during an active watch burst, not starting until
~30–60 s post-broadcast (the first block is tens of seconds away and `confirmations` can
change only once per 60 s, so sub-10 s polling is pointless). The N+1 requirement pins a
*lower* bound — effective discovery latency ≤ ~30 s to reliably make N+1 — which trims the
minute-scale tail but does **not** push toward sub-second / high-frequency polling. Net
shape: idle ~45 s → 10–20 s bursts near the expected block → fire on first sight of a
primer in a block. The exact in-band cadence is chain-unrecoverable.

**Does hand-polling load the RPC node? No — negligible.** The human is the rate limiter
(~0.05–0.1 req/s at a 10–20 s cadence); `gettransaction` is a read-only, sub-ms
`mapWallet` lookup that touches neither mempool acceptance nor block validation nor
consensus; and a serial "next call only after the previous returns" loop keeps ≤ 1
request in flight, so it structurally cannot overflow `-rpcworkqueue` (default 16) or
starve `-rpcthreads` (default 4) — those need *concurrent* flooding. Even a machine
busy-loop stays a few % of one core server-side; a human is 2–3 orders of magnitude
slower. (This mirrors the `POLL_INTERVAL` note: a 1 s poll does ~5× the calls of the 5 s
default for identical information — waste, not a stability risk.)

**OPSEC reads.**

- **Trace *location*, not density, is the axis that matters.** Hand-confirming against
  one's own `elementsd` over `127.0.0.1` leaves traces only on the attacker's own box
  (shell history; `debug.log` only if `-debug=rpc`, off by default) with **no network
  egress** — invisible to ISP, explorer and the Liquid network; forensics reaches them
  only by seizing / imaging the machine, at which point RPC-log *density* is trivia next
  to the wallet keys, exploit hex and reused address already on disk. By contrast a
  third-party **explorer** query plants the txid + timing on someone else's server,
  subpoena-able without ever touching the attacker — that is the real leak, and it is what
  makes own-node querying beat explorer-refresh. Poll frequency is OPSEC-neutral.
  ("Local ⇒ unreachable" is not absolute: machine seizure / arrest, VPS / cloud imaging or
  remote syslog, and non-loopback RPC over LAN / SSH each move the trace onto hardware the
  attacker does not fully control.)
- **Address reuse is the one OPSEC-unclean point.** All three attack txs *and* the funding
  tx return change to the same P2WPKH `ex1q7kg…` (§4.6). On a permanent public ledger this
  is explicit clustering: it hands analysts the change-address heuristic for free, extends
  linkage beyond the already-unhideable primer↔exploit relation to bind the **funding
  source** and change trail into one identity anchor, and creates a single point of
  de-anonymization — if that address ever touches an identifiable event (KYC, IP leak,
  reuse elsewhere) the whole campaign collapses to it in one step. Clean OPSEC would use a
  fresh address per output and unlinkable (e.g. coinjoined) funding. That the attacker did
  not suggests anonymity was deprioritized in favor of simple 3-UTXO coin-control, or that
  the far end of the funds path was already considered clean. (Consistent with the
  "conservative prep, coarse confirmation" character of the operation.)

**Bottom line.** The wallet-shaped self-funding makes a manual
`getrawtransaction` / `gettransaction` confirm-then-fire flow entirely viable and
data-consistent, so it cannot be ruled out; a local `sendrawtransaction` + P2P submission
of `V1` is likewise viable **if** the node was positioned inside the primed fixed-code
subgraph (§4.6). What is ruled out is `V1` reaching the signer over the general public
network. The features that tilt toward a scripted, well-positioned run — the ~60 s window
against a byte-crafted `V1`, and `V1`'s partition-limited relay — are non-wallet facts;
tooling and topology are simply not recoverable from on-chain data.

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
  rangeproof cache is per-process, in-memory and **wiped on restart** (per-process
  salt). The entry itself is *not* consumed on read — the erase is lazy (§2.3) — so a
  node that accepted the invalid block re-validates it fine on a reorg
  disconnect/reconnect **without** a restart. But once the process restarts, or on a
  startup `-checkblocks` re-validation that runs after the cache is already empty, `K`
  is gone and such a node **fails to re-validate the very block it accepted**, erroring
  out (forcing a reindex onto the honest chain). This explains part of the observed
  post-attack network behavior and means accepting-side infrastructure is fragile until
  patched and reindexed. *(An earlier revision blamed erase-on-read for consuming the
  entry; the source shows the erase is lazy, so the real fragility is the restart-wipe.)*

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
   restart; and priming requires mempool acceptance to plant `K`, which then persists
   across blocks (lazy erase, §2.3) — with no same-inter-block-era constraint.
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
   script so the exploit tuple and a primer tuple hash to identical bytes;
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
design in place (a valid-proof memoization on the consensus path that a forged
key-collision can hit, §2.3) rather than removing the rangeproof
cache from the consensus path. Until a delimiting fix (or cache removal) ships, the
network is one primed mempool away from a repeat — against *whichever* keying the
victim runs. Rev. 1's "residual gap" caveat (accepting nodes possibly running fixed
builds) is no longer hypothetical: it is the established mechanism (§2.4), and the
remaining unknowns are which exact builds the functionaries ran and what their
mempool logs show (§6).


---

## 6. Open items / limitations

1. **`K` came from the 4050335 primers' mempool acceptance — not a hidden mempool-only
   primer.** Priming needs the primer **mempool-accepted** on the accepting nodes (that
   inserts `K`); because the erase is lazy, `K` then persists across blocks (§2.3), so
   the two primers mined into 4050335 suffice and no separate, later primer is required.
   Consistent with that: the **1,500-block (~25 h) pre-fork scan** on the valid chain
   (`scan_back.py`, `DONE found=[]`) found no `C1` and no blob bytes except the
   4050335 primer pair, and **all five other non-coinbase txs of 4050336** were
   fetched and parsed (§4.5) — none carries the primer tuple. The only thing not on
   chain is the exact mempool-acceptance timing, visible only in the accepting nodes'
   `debug.log` / mempool logs.
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

