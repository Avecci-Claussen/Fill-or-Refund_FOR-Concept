# Twin-chain Fill-or-Refund

**A Taproot adaptor RFQ for Bitcoin ↔ Fractal Bitcoin**

Technical note · NexumBit · 22 September 2026  
Authors: *(NexumBit — names TBA)*  
Status: **sound with patches.** Spec and unit script-invariants only. Not consensus-tested. `FOR_ENABLED` remains off.

---

## Abstract

Twin-chain Fill-or-Refund (FOR) is a two-output Taproot construction for a short-lived RFQ between Bitcoin (chain A) and Fractal Bitcoin (chain B). A maker advertises an **unfunded** quote: *X* sats of A for *Y* sats of B. After exclusive reservation, both traders lock. The taker is paid *X* on A if and only if the maker can take *Y* on B. Coins that are not filled refund to their funder after a CLTV.

Atomicity is the existing BIP-340 adaptor in this repository (`backend/services/adaptor_signature.py`): the maker holds scalar *t*, publishes point *T* = *t*·G. Completing **Claim_B** publishes a Schnorr signature from which anyone extracts *t* and completes **Take_A**, which pays the **taker**. The coordinator never holds *t* or claim keys. This is not protocol v1, where *T* was treated as a coordinator CHECKSIG key.

A brief that used a **single-key TAKE_A** leaf (`<maker> CHECKSIG`, the v2 swap claim leaf) is **unsound**. The adaptor is not in script; after (or without) claiming B, the maker can naked-sign a self-send of Offer_A. The patched tree is: unspendable NUMS internal key; **party 2-of-2 of the two traders** on TAKE_A and CLAIM_B; **funder-only CLTV** refund leaves. *T* is metadata, never a script key.

Clocks are wall-clock remaining time via `hours_to_blocks`, never a raw height compare. *T*_pay unlocks before *T*_offer. `REFUND_GRACE_HOURS` (24 h) is reused from v2 because BTC ~10 min vs FB ~30 s makes minute-scale slack invert after a hashrate burst. Do not bind Pay_B until Offer_A has *k* confirms; do not broadcast Take_A until Claim_B has *k* confirms. Offer_A on the stronger chain (BTC) is the reorg-safer default.

The residual is **maker free option** after `both_locked`: the maker can refuse Claim_B, wait out the windows, and both refund. That cannot be eliminated on today’s Bitcoin without a covenant such as CTV; this note does not invent one. Price it in the spread and keep the Pay_B window short. FOR layers a reverse book, RFQ, *N* independent fills (distinct *T*), and later a PTLC-style B-leg **in principle**. It does **not** layer perps, leverage, oracle CETs, or repricing of locked coins.

**Audience.** A trader can stop after §§1–2, 8–9, and 11. A cryptographer wants §§3–7 and 10. The talk track at the end is the walkthrough, not a second document.

---

## Contents

1. [Problem](#1-problem)
2. [Threat model](#2-threat-model)
3. [Construction](#3-construction)
4. [Adaptor complete and extract](#4-adaptor-complete-and-extract)
5. [Clocks](#5-clocks)
6. [Reservation and the RFQ book](#6-reservation-and-the-rfq-book)
7. [Privacy](#7-privacy)
8. [Security arguments](#8-security-arguments)
9. [Residual optionality](#9-residual-optionality)
10. [Comparison](#10-comparison)
11. [What this note will not claim](#11-what-this-note-will-not-claim)
12. [Implementation status](#12-implementation-status)
13. [References](#13-references)
14. [Talk track](#14-talk-track)

Notation matches `backend/services/for_protocol.py`, `for_script.py`, `for_clocks.py`, `for_book.py`, `for_watch.py`, and protocol v2 in [`PROTOCOL.md`](../PROTOCOL.md).

---

## 1. Problem

Three ways to run a BTC↔FB book collide with different failure modes.

**Ghost intents (today’s v2 matching).** A party posts `WAITING_FOR_MATCH` without locking coins. The book looks deep; fills fail when the intent cannot fund. The coordinator can require confirmed balance at create (`REQUIRE_CONFIRMED_BALANCE_AT_CREATE`) — that is solvency theatre at post time, not a lock. Capital stays in the wallet until match, which makers want; the counterparty still faces a no-show.

**Lock-before-match.** The maker funds a long-lived Offer_A onto the book. Inventory is real. It is also hostage: every minute on the book is a CLTV clock, a fee, and a reorg window on the slower chain. A maker quoting many sizes cannot park *N* funded A-outputs for a 24 h intent TTL.

**RFQ with Fill-or-Refund.** Advertise *X*, *Y*, *T* with a **short TTL** and **no funding**. On reserve, freeze *X*, *Y*, build both locks, presign, then fund. If nobody takes, nothing was locked. If somebody takes and the fill completes, adaptor atomicity binds the two spends. If it aborts, each funder refunds unilaterally.

FOR is that third shape. It is not a replacement for `/v1/swap` v2 clients. It is a different matching primitive: quote is an advertisement; the contract is the reserved session (frozen *X*, *Y*, timeouts, destinations, presigs). A UI “hint” (ticker, indicative FX) is **not** in the sighash.

Default pair in code: chain A = Bitcoin, chain B = Fractal Bitcoin (`for_api.py` rejects anything else). That assignment is the reorg default, not a law of the scripts.

---

## 2. Threat model

**In scope.** Two traders, an untrusted coordinator/relay, public mempools, reorgs within the configured confirmation targets, fee spikes, and a malicious counterparty who signs only what the protocol asks and then deviates.

**Operator grief ≠ steal.** The operator can: hide or expire quotes; grant an exclusive reserve to a friend; refuse to relay presigs; delete the in-memory book; stall a watcher. The operator **cannot**: complete TAKE_A or CLAIM_B (those are 2-of-2 of the traders); spend a refund leaf (funder key only); learn *t* before Claim_B is on chain; invent a Take_A that pays anyone but the bound destination. Worst case on coordinator compromise is the v2 swap case: DoS and lying about public data that clients must verify before locking.

**What “steal” would mean here.** Maker ends with *Y* and still holds *X*; or taker ends with *X* without *Y* having been paid to the maker; or a third party (including the operator) takes either lock. The patched scripts are meant to rule those out under the usual Schnorr / Taproot assumptions, **except** the maker’s refusal to claim B after both locks confirm — that is optionality, not theft. Theft via **clock inversion** (claim-then-refund across heterogeneous block times) is in scope and is why wall-clock remaining time and `REFUND_GRACE_HOURS` are mandatory.

**Out of scope as “the protocol failed.”** Users who leak *t* or keys. Wallets that adaptor-presign the wrong sighash. Explorers that lie about confirms (clients should check their own node). Covenants Bitcoin does not have.

---

## 3. Construction

Maker (Alice) sells A, wants B, samples *t* and publishes *T* = *t*·G. Taker (Bob) pays B, wants A. One offer, one *T*, one taker.

### 3.1 Transaction graph

```
  Maker wallet                    Taker wallet
       │                               │
       │  Offer_A (X sats, chain A)    │  Pay_B (Y sats, chain B)
       ▼                               ▼
  ┌─────────────┐                 ┌─────────────┐
  │  Offer_A    │                 │   Pay_B     │
  │  P2TR NUMS  │                 │  P2TR NUMS  │
  └──────┬──────┘                 └──────┬──────┘
         │                               │
    TAKE_A │  REFUND_A              CLAIM_B │  REFUND_B
         │                               │
         ▼                               ▼
   pays taker                      pays maker
   (needs t)                       (reveals t)
```

Happy path:

1. Maker advertises quote (*X*, *Y*, *T*, maker x-only, receive-B, refund-A, TTL).
2. Taker reserves (taker x-only, receive-A, refund-B). Book proposes clocks, builds both descriptors. *X*, *Y* freeze.
3. Both sides adaptor-presign / Schnorr-sign the **exact** Take_A and Claim_B transactions (destinations and miner fees bound in BIP-341 sighash), plus refund templates. Relay verifies before any lock is treated as bound (`store_and_verify_presigs`).
4. Maker funds Offer_A. Watcher accepts Pay_B only after Offer_A has *k*_A confirms.
5. Taker funds Pay_B. State `both_locked` after *k*_B confirms.
6. Maker completes Claim_B with *t* (taker’s adaptor + maker’s regular sig). Claim_B pays **maker**.
7. After Claim_B has *k*_B confirms, anyone extracts *t* and completes Take_A. Take_A pays **taker**.
8. If the fill never happens, refund leaves unlock: maker alone after *T*_offer; taker alone after *T*_pay.

Do not broadcast Take_A before Claim_B is deep enough. A reorg that undoes Claim_B after Take_A confirms is the cross-chain theft the confirm gate exists to make expensive.

### 3.2 Taproot trees

Internal key: the same unspendable NUMS construction as v2 (`dlc_v2.derive_unspendable_internal_key`). BIP-341 NUMS *x*-coordinate `50929b74…803ac0`, tweaked with `TaggedHash("NexumDLCv2/internal", coop_leaf || refund_leaf)`. Key-path spend is not a protocol path.

*T* is **not** in either script. Putting *T* in script is how v1 pretended to be an adaptor (coordinator key).

```
Offer_A = tr(NUMS_internal, { TAKE_A, REFUND_A })
Pay_B   = tr(NUMS_internal, { CLAIM_B, REFUND_B })
```

| Lock | Success leaf | Refund leaf |
|------|----------------|-------------|
| Offer_A | TAKE_A: `<taker> CHECKSIGVERIFY <maker> CHECKSIG` | `<T_offer> CLTV DROP <maker> CHECKSIG` |
| Pay_B | CLAIM_B: `<maker> CHECKSIGVERIFY <taker> CHECKSIG` | `<T_pay> CLTV DROP <taker> CHECKSIG` |

Witness for a coop spend is `[second_sig, first_sig, script, control_block]` (`finalize_coop_tx`). First key is the CHECKSIGVERIFY key (top of stack when the script starts).

| Spend | first (CSV) | second (CS) | Who adaptor-presigns | Regular sig | Completed with *t* pays |
|-------|-------------|-------------|----------------------|-------------|-------------------------|
| Take_A | taker | maker | **maker** (65-byte adaptor) | taker Schnorr | **taker** (`taker_recv_a`) |
| Claim_B | maker | taker | **taker** (65-byte adaptor) | maker Schnorr | **maker** (`maker_recv_b`) |

Maker adaptor-presigns Take_A paying the taker. After Claim_B leaks *t*, anyone (taker, maker, watcher, a third party with the public presigs) can complete the maker half. Taker adaptor-presigns Claim_B paying the maker. Only the maker, who created *t*, can complete it — until they do, *t* is not public.

Refund: same leaf as v2 (`build_dlc_refund_script`). Funder only. Not a Take_A destination. `nLockTime` ≥ timeout; sequence is RBF (`0xFFFFFFFD`) so CLTV is enforced.

### 3.3 Who knows *t*

```
  before Claim_B                 after Claim_B confirms
  ──────────────                 ──────────────────────
  maker          : t, T          maker, taker, watcher,
  taker          : T             chain observers     : t
  coordinator    : T, presigs    coordinator still
                   (never t)       must not store t
```

Relay fields that are safe: `adaptor_point`, both adaptor presigs, both regular coop sigs, both refund sigs, addresses, timeouts. Recovery JSON sets `"t": null` and says to extract from Claim_B plus `claim_b_taker_adaptor` (`for_watch.py`).

### 3.4 Fee bumping

Take_A’s miner fee is inside the adaptor sighash. RBF of Take_A would need a new maker adaptor presig; the watcher **refuses** that rewrite (`refuse_take_a_rbf`). Bump with **CPFP** on the Take_A (or Claim_B) output.

---

## 4. Adaptor complete and extract

No new scalar recipe. FOR calls the v2 module:

```
Presign(d, m, T) → (R', s')     # 65-byte compressed(R') || s'
Verify(P, m, presig, T)
Complete(presig, t) → (r, s)    # 64-byte BIP-340
Extract(presig, sig, T) → t     # t ≡ s − s' (mod n), check T = t·G
```

Parity rule is already in that module: *R*_adapted = *R*' + *T* must have even *Y* so the completed signature is a BIP-340 signature. FOR does not re-derive it.

On Claim_B, the published taker signature is the completed adaptor. `extract_t_from_claim_b` is `adaptor_extract` on that witness and the stored taker presig. `complete_take_a_maker_sig` is `adaptor_complete` on the maker’s Take_A presig.

Verification rejects a **naked Schnorr** in the adaptor slot (`verify_take_a_presigs`: 65 bytes, `adaptor_verify`, and `schnorr_verify` of the same bytes must fail). A 64-byte maker signature on Take_A would let the taker take A without *t* ever appearing — that is a fill without a pay.

The sighash is BIP-341 script-path, `SIGHASH_DEFAULT` (0x00), bound to funding outpoint, value, and **exact destination**. A maker adaptor on “pay taker” does not verify on “pay maker”; the 2-of-2 still needs the taker’s signature on that dest, which the taker never gave.

---

## 5. Clocks

BTC ~600 s/block, FB ~30 s/block. A height compare of *T*_pay vs *T*_offer **inverts**: FB’s tip plus six hours of blocks is a larger integer than BTC’s tip plus the offer window, even when the offer is later in wall-clock. v2 already learned this (`determine_first_claimed_leg`, `tests/test_first_claimed_leg_clock.py`). FOR reuses that function and **requires** the earlier refund to be Pay_B.

```
remaining(unlock, tip, bt) = max(0, unlock − tip) × bt

T_pay   = tip_B + hours_to_blocks(pay_hours, B)
T_offer = tip_A + hours_to_blocks(pay_hours + (Δ_A + Δ_B + grace)/3600, A)

need:  remaining(T_pay)  <  remaining(T_offer)
       remaining(T_offer) ≥ remaining(T_pay) + Δ_A + Δ_B + grace
       first-claimed leg by wall-clock = B
```

Δ_C = *k*_C × block_time_C (confirmation target from settings: BTC *k*=3, FB *k*=10 → ~30 min + ~5 min). Confirmation Δ alone is ~35 minutes. BTC Poisson σ over a 6 h window is on the order of an hour. Minute-scale slack therefore inverts *T*_pay < *T*_offer after funding. Grace is `REFUND_GRACE_HOURS` = 24 h, the same claim-then-refund defence as v2.

Default `FOR_PAY_HOURS` = 6. Offer window is then about 6 h + 24 h + Δ ≈ 30.6 h of A-blocks. Raw heights may satisfy `t_pay > t_offer`; wall-clock remaining must still have Pay_B first (`test_for_clocks_keep_pay_first_with_v2_grace_against_height_inversion`).

On bind, `recompute_or_reject` re-checks the **frozen** heights against live tips. If the inequality has already failed, abort; do not rewrite *X*, *Y* or the scripts.

---

## 6. Reservation and the RFQ book

Quotes are advertisements. Coins stay in wallets until both sides fund after reserve. Defaults (`settings.py`): `FOR_QUOTE_TTL_SECONDS` = 30, `FOR_RESERVE_SLOT_SECONDS` = 90, `FOR_PAY_HOURS` = 6.

| Rule | Why |
|------|-----|
| One offer, one *T*, one taker | Adaptor reuse across sessions would leak *t* or collide extracts |
| Short quote TTL | Do not fund long-lived A onto the book |
| Exclusive reserve | Second `reserve` fails while the slot is live |
| Reserve expiry returns the quote | Availability grief is temporary |
| Replace = new id, new *T*, new *X*,*Y* | Cannot mutate a live reserve |
| *X*,*Y* frozen at reserve | No reprice, no last-look on locked terms |
| Hint is UI | `"indicative — not the contract"`; not in sighash |
| Confirmed balance at advertise/reserve | Same ghost-intent gate as swap create; not a lock |

State the book actually uses: `reserved` → `presigned` → `offer_locked` → `both_locked` → (`claim_b`) → `taken`, plus `expired` / `refunded` / `aborted`.

*N* independent fills: *N* quotes, *N* distinct *T*, *N* sessions. Not one UTXO sliced by a covenant. A reverse book (sell B, want A) is the same scripts with roles flipped; the HTTP API does not enable it yet, and flipping would move Offer onto FB unless the reorg default is redesigned.

**Presign-before-fund.** Invariant 11 in `for_watch.store_and_verify_presigs`: intended funding outpoints are passed in so sighashes bind **before** locks are broadcast. Funding txs that do not hit those outpoints are a different contract; the watcher will not complete them.

---

## 7. Privacy

**On-chain.** Two P2TR outputs. Scripts are ordinary 2-of-2 CHECKSIGVERIFY/CHECKSIG plus a CLTV refund — they do not mention *T*, pair, or *X*/*Y* FX. A chain observer sees coop spends or funder refunds. Take_A and Claim_B destinations are the traders’ receive addresses (bound at reserve). This is **discretion**, not anonymity: amounts, timing, and address reuse still link.

**Operator database.** The book sees maker/taker ids, addresses, *T*, *X*, *Y*, clocks, presigs, funding txids. That is more than the chain. Treat the operator as an RFQ dealer’s blotter, not as a mixer. Deleting the blotter after lock does not brick a fill: recovery material is public, and *t* is extracted from Claim_B when it exists (`test_operator_deleted_after_lock_recovery_kit_has_no_t`).

**Mempool.** Adaptor presigs are public at the relay. They are useless without *t*. Broadcasting Claim_B is the reveal.

---

## 8. Security arguments

These are arguments over the patched tree and the existing adaptor code, not a machine-checked proof, and not a tapscript VM run.

### 8.1 The single-key TAKE_A attempt (unsound)

The brief’s TAPROOT tree as written used the v2 claim leaf on Offer_A: `<maker> CHECKSIG`. Atomicity was supposed to come from an adaptor presig on “pay taker.”

The adaptor is not in script. Any BIP-340 signature under the maker key spends the leaf. After claiming B (or at any time), the maker `schnorr_sign`s a transaction that pays themselves. The adaptor presig still verifies only on the taker destination; it does not constrain the UTXO. `test_brief_single_key_take_leaf_does_not_bind_destination` is the counterexample.

A single-key TAKE_A under the **taker** key is the other rug: the taker takes A without paying B.

### 8.2 Why 2-of-2 patches it

TAKE_A requires **both** traders. The maker can still naked-sign a self-send sighash (`test_maker_cannot_redirect_offer_without_taker_sig`); they cannot assemble a valid witness without a taker signature on that dest. The taker signed only Take_A paying `taker_recv_a`. Completing the maker adaptor with *t* yields a signature on that same sighash, not on the fake dest (`test_claim_b_extract_completes_take_a_to_taker_not_maker`).

CLAIM_B is symmetric: taker adaptor + maker regular. Completing it is what leaks *t*. The maker cannot take B with a naked signature alone.

### 8.3 Not v1 fake-adaptor

v1 (`build_dlc_success_script`): `<adaptor_xonly> CHECKSIGVERIFY <receiver> CHECKSIG` with the coordinator holding the adaptor scalar as an ordinary key. Atomicity was coordinator-enforced. PROTOCOL.md deprecates it.

FOR 2-of-2 keys are **the two traders**. *T* is an off-chain adaptor point for `adaptor_presign` / `complete` / `extract`. The coordinator has no CHECKSIG key in either tree.

### 8.4 Refunds are not a second take

Refund leaf: CLTV + funder. Taker cannot refund Offer_A; maker cannot refund Pay_B. A refund sighash is a different leaf hash than the coop spend. After timeout, the funder can send the coins anywhere they can sign; that is a refund, not a fill.

### 8.5 Confirm gates and Offer_A on BTC

| Gate | If skipped |
|------|------------|
| Pay_B accepted before Offer_A has *k*_A | Taker locks *Y*; a shallow Offer_A can reorg; maker may never have bound *X* |
| Take_A broadcast before Claim_B has *k*_B | Taker is paid *X*; Claim_B reorgs; maker lost B and A |
| Raw height clocks | Pay_B refunds after Offer_A on wall-clock — claim-then-refund |

Offer_A on BTC (harder reorg, slower blocks) is the default because the taker’s claim of A is the **second** spend and must survive after *t* is public. Putting the first lock on the weaker chain is possible in the scripts and unwise in the watcher.

### 8.6 Abort table (unit-level)

| Condition | Outcome |
|-----------|---------|
| Quote TTL, no reserve | Off the book; nothing locked |
| Second reserve while slot live | Rejected |
| Reserve expires, still unfunded | Quote listed again |
| Reuse *T* | Rejected |
| *X*,*Y* mutation | Rejected |
| Naked Schnorr in adaptor slot | Rejected |
| Offer funded, Pay_B never | Maker refunds after *T*_offer |
| Both locked, maker never Claim_B | Both refund after their CLTVs (optionality, §9) |
| Claim_B *k*-conf | Extract *t*, complete Take_A to taker |
| Operator DB gone after lock | Public recovery; *t* from chain if Claim_B exists |

### 8.7 What the arguments do not cover

They do not replace `bitcoind` script verification, mempool policy, or a reorg simulator. They do not remove maker optionality. They assume traders verify addresses and sighashes in their own wallets, not by trusting the HTML.

---

## 9. Residual optionality

After `both_locked`, the maker may refuse to complete Claim_B. *t* never appears. At *T*_pay the taker refunds *Y*; at *T*_offer the maker refunds *X*. No theft. The taker has **sold a free American option** on the pair for the length of the Pay_B window: if the market runs in the maker’s favour, the maker fills; if not, the maker walks.

This is inherent in “maker holds *t* and Claim_B is not a covenant.” Eliminating it on Bitcoin today means a covenant that **forces** a Claim_B-shaped spend (CTV/APO-class). This protocol **does not** add CTV, does not pretend a presig is a covenant, and does not wait on a soft fork.

**Mitigations that are in-protocol:** short `FOR_PAY_HOURS`; spread that pays for the option; RFQ so the maker is not sitting on a funded book for a day; reputation is operator policy, not a script. **Not a mitigation:** asking the coordinator to “make them claim” — the coordinator has no key.

Traders should see the option in the quote, not discover it in a post-mortem.

---

## 10. Comparison

| | Custody | Atomicity | Matching | Optionality / honesty |
|---|---------|-----------|----------|------------------------|
| CEX | Full | Ledger | Order book | Last-look, freeze, haircut |
| HTLC atomic swap | None after lock | Hash preimage | Usually lock-then-find | Timeout grief; hash reuse; lock-before inventory |
| Event-DLC (oracle CETs) | None after lock | Oracle attestation | Not a two-chain RFQ | Oracle; no fill-or-refund book |
| NexumBit v2 matching | None after fund | BIP-340 adaptor, single-key claim leaves | Intent pool; fund after match | Ghost intents; both sides can fail to fund |
| **FOR (this note)** | None after fund | BIP-340 adaptor on **2-of-2** leaves | Unfunded RFQ, exclusive slot, frozen *X*,*Y* | Maker free option after both_locked; operator grief ≠ steal |

v2 matching remains the live product (`FOR_ENABLED` off). FOR is the construction to present when the question is “can the book be real without parking BTC on a quote for hours?”

**Layering (in principle, not specified here).** Reverse book (roles flipped). *N* fills = *N* *T*. A later B-leg that is a PTLC rather than 2-of-2+adaptor. None of that is a perpetual, a leverage tape, or an oracle CET on the locked coins.

---

## 11. What this note will not claim

- **Perps, leverage, oracle CETs, or repricing locked coins.** Frozen *X*,*Y*. Hint is not the contract.
- **“Trustless fees.”** FOR spends deduct a miner fee bound in sighash. There is no on-chain protocol take in `for_protocol.py`. Venue fees, if any, are operator policy. (v2 swap’s 2.4% take is a different product; only that take is an extra funding output, and even there filler/integrator shares are ledger-settled.)
- **“No optionality.”** §9 is load-bearing.
- **“The operator cannot grief.”** They can. They cannot steal under the patched scripts if clients verify.
- **Production readiness.** Not consensus-tested. Flag off.
- **Compatibility with a single-key TAKE leaf.** That brief is unsound; do not “simplify back.”
- **CTV.** Not used, not invented.

---

## 12. Implementation status

**Verdict from script review: sound with patches** (the 2-of-2 trees, wall-clock clocks, confirm gates, presig-before-fund). The unsound single-key TAKE_A is refused in tests and in `for_script.py` commentary.

| Piece | Where | Proven how |
|-------|--------|------------|
| Leaves, NUMS, sighash, complete/extract | `for_script.py`, `for_protocol.py` + `adaptor_signature.py` | pytest invariants, no bitcoind |
| Clocks | `for_clocks.py` | wall-clock vs height inversion tests |
| RFQ book | `for_book.py` | in-memory unit tests |
| Confirm / Take_A / CPFP hook | `for_watch.py` | unit tests; no live watcher loop |
| HTTP | `api/for_api.py` under `/v1/for` | 404 unless `FOR_ENABLED` |
| Limits advertisement | `/v1/limits` → `for_protocol` | flag still false |

`FOR_ENABLED` defaults **false**. `.env.example` says to leave it off until 2-of-2 + grace clocks are **regtest-proven**. This paper is the spec to present; it is not a ship checklist.

What has **not** been done: `bitcoind` / Fractal regtest, mempool policy, reorg tests, fee-market CPFP on mainnet, persistent book, production auth on `/v1/for`, UI beyond whatever experimental files exist, any enabling of the flag.

---

## 13. References

1. W. Wuille, J. Nick, T. Ruffing. BIP-340: Schnorr Signatures for secp256k1.  
2. P. Wuille, J. Nick, A. Towns. BIP-341: Taproot: SegWit version 1 spending rules.  
3. P. Wuille, J. Nick, A. Towns. BIP-342: Validation of Taproot Scripts.  
4. A. Poelstra. *Scriptless Scripts* / adaptor signatures. Bitcoin-dev and related notes.  
5. L. Aumayr, O. Ersoy, A. Erwig, S. Faust, K. Hostáková, M. Maffei, P. Moreno-Sanchez, S. Riahi. *Bitcoin-Compatible Virtual Channels* / adaptor and PTLC lines. IEEE S&P / related.  
6. T. Dryja. Discreet Log Contracts.  
7. NexumBit. [`PROTOCOL.md`](../PROTOCOL.md) — protocol v2: NUMS internal key, BIP-340 adaptor, `REFUND_GRACE_HOURS`, deprecated v1 coordinator key.  
8. NexumBit. `backend/services/adaptor_signature.py` — canonical Presign / Verify / Complete / Extract used by FOR.  
9. NexumBit. `docs/MATCHING_SYSTEM.md` — v2 intent pool (ghost-intent baseline).  

---

## 14. Talk track

Eight beats. This is the walkthrough if you have a whiteboard and the PDF; it is not a slogan deck.

**1. Title (30 s).** Twin-chain Fill-or-Refund: unfunded RFQ, then two Taproot locks, then adaptor atomicity. Status: sound with patches; not on. Date 22 Sep 2026.

**2. Why a third primitive (2 min).** Ghost intents look like a book and then fail to fund. Lock-before-match makes the book honest and parks BTC on a quote. FOR: advertise *X*,*Y*,*T* for seconds; lock only after reserve. Hint is not the contract.

**3. The failed leaf (3 min).** Draw `<maker> CHECKSIG` on Offer_A. Adaptor presig on “pay taker.” Ask: can the maker sign “pay maker”? Yes — adaptor is not in script. That brief is unsound. Do not ship it.

**4. Patched tree (4 min).** NUMS internal. TAKE_A = taker CSV, maker CS (maker adaptor). CLAIM_B = maker CSV, taker CS (taker adaptor). Refund = funder + CLTV. *T* not in script. Coordinator has no key. Witness `[second, first, script, control]`. Who holds *t*: maker, until Claim_B.

**5. Graphs and gates (3 min).** Offer_A on BTC first, *k* confirms, then Pay_B. Claim_B *k* confirms, then Take_A. CPFP, not RBF, on Take_A. Extract *t* from taker’s on-chain sig + public presig — same module as v2, no new equations.

**6. Clocks (2 min).** Never compare heights. FB 30 s vs BTC 10 min inverts. *T*_pay before *T*_offer in remaining seconds. 24 h grace because 35 min of confirmation Δ is less than BTC Poisson over six hours.

**7. Threats and the option (3 min).** Operator grief ≠ steal. After both locked, maker can walk; taker sold a free option. Price it; shorten the window; no CTV in this paper. Abort table: unused quote never locked; both refund if no Claim_B.

**8. Status and non-claims (2 min).** Unit invariants only. `FOR_ENABLED=false`. Will not claim perps, trustless fees, no optionality, or production. Questions: reverse book, *N* fills (distinct *T*), later PTLC-B — layering, not this tree.

---

*NexumBit · Twin-chain Fill-or-Refund · spec 22 September 2026 · `FOR_ENABLED` off*
