# Phase 2 · H3 — binary entity-representation decoders: **run results & assessment**

*The follow-up to [target B](phase2-targetB-agent-parse-results.md). Target B left one named gap:
the `REPRESENTATION_IN_BINARY` decoders (`OBJK_*_Binary` / `*_QosBinary`) were never reached. This
run closes it — and corrects why it existed. Outcome: **no memory-safety violation** in the binary
entity-representation decoders at a documented coverage plateau.*

> **Status: COMPLETE — negative result (binary entity representation).**
> Run date **2026-11-11**, WSL Ubuntu. Harness: [`agent_fuzz/`](agent_fuzz/) (extended, same CI target).

> **Scope, safety & ethics.** UNCLASSIFIED, open-source (eProsima Micro-XRCE-DDS-Agent / Fast-CDR,
> Apache-2.0). **DEFENSIVE and OFFLINE:** the harness parses attacker-controlled **bytes in-process**
> — no network, no Agent process, no DDS domain, no vehicle. No committed blobs/corpora.

## 1. Outcome in one line

With the harness extended to mirror the Agent's second decode pass and seeded with 32
serialize-generated messages, **~240 million** coverage-guided executions under **ASan + UBSan**
reached a plateau of **755 edges** (up from 535 for the target-B corpus on the same binary) with
**zero crashes, OOMs, timeouts, or leaks**. All 13 binary-representation decoders are exercised.

## 2. Correction to target B §6 — why the gap existed

Target B attributed the gap to the byte mutator being unable to synthesize "XCDRv2 PL-CDR
member-header structures". Reading the Agent source shows that was wrong on both counts:

1. **The decoders are not on the `InputMessage` parse path.** `CREATE_Payload` deserializes a binary
   representation as an opaque `std::vector<uint8_t>`. The Agent decodes that blob in a **second**
   Fast-CDR pass inside `<Entity>::create()` — `Participant.cpp`, `Topic.cpp`, `Publisher.cpp`,
   `Subscriber.cpp`, `DataWriter.cpp`, `DataReader.cpp`, `Requester.cpp`, `Replier.cpp` — over a
   fresh `FastBuffer`/`Cdr` whose endianness comes from the `CREATE` submessage flags
   (`Processor::process_create_submessage`). The target-B harness stopped at the first pass, so
   **no input could have reached them**. It was a harness-reach gap, not a seed problem.
2. **The structures are simple.** They are XCDRv1 with flag-prefixed optional members
   (`bool present; if (present) value`), not PL-CDR member headers.

The lesson for the method: an uncovered function in `-print_coverage` needs a call-graph check
before it is called "reachable but not reached".

## 3. What changed in the harness

[`agent_fuzz.cpp`](agent_fuzz/agent_fuzz.cpp):

- **`decode_binary_rep()`** — after a `CREATE` payload parses, stamps the submessage endianness on
  the representation and, for each of the 8 entity kinds, repeats the Agent's stage-2 decode:
  copy the representation, wrap the octets in a new `FastBuffer`/`Cdr` (XCDRv1), call the
  `OBJK_*_Binary::deserialize`, catching **only** Fast-CDR exceptions as the Agent does. Any other
  exception aborts the harness and is recorded as a crash.
- **`--gen-seeds <dir>`** (standalone build) — writes 32 valid messages: 8 entity kinds ×
  {no optionals, all optionals} × {little, big endian}, built with the Agent's own `serialize()`
  so octet-sequence lengths, optional flags and alignment are exact.
- **Self-test as positive control** — `--selftest` now fails unless every generated seed is handed
  to its stage-2 decoder **and** decodes cleanly, so a harness that silently stops at the opaque
  blob cannot pass.

The entity must have a session, and every kind except the participant also needs its parent
entity to exist, before the Agent reaches this code; a peer can satisfy both with ordinary
`CREATE_CLIENT` / `CREATE` messages. The harness skips those preconditions and decodes directly.

## 4. Run record

| Field | Value |
|-------|-------|
| Run date / host / OS | 2026-11-11 · WSL Ubuntu · x86-64 |
| Source under test | Agent **v3.0.2** `a88c712…` · Fast-CDR **v2.3.1** `c931bde…` (unchanged from target B) |
| Compiler / engine | clang 21.1.8, **libFuzzer** (fork=14), `-max_len=4096`, `xrce.dict` |
| Sanitizers | ASan + UBSan on Fast-CDR, the XRCE type objects and the harness |
| Corpus | target-B corpus (685 units) + 32 generated binary-representation seeds; bytes git-ignored |
| Baseline (target-B corpus, new binary, `-runs=0`) | **535 edges** / 3141 ft |
| + 32 generated seeds, before any fuzzing (`-runs=0`) | **662 edges** / 3293 ft |
| This run | **~240 M** execs in 1,500 s (~160 k/s aggregate), **755 edges** / 4715 ft; 755 first reached within 66 s (~11 M execs) and flat for the remaining ~229 M |
| Crashes / OOMs / timeouts | **0 / 0 / 0** |
| Outcome | **Negative result** on the binary entity-representation decoders. |

Edge counts are not comparable with target B's 366: the harness itself is instrumented and grew.
The like-for-like comparison is 535 → 755 on this binary.

## 5. What is covered (`-print_coverage=1`)

Eleven stage-2 decoders are reported covered, with their covered/total edges:

| Decoder | Edges | Decoder | Edges |
|---|---|---|---|
| `OBJK_DomainParticipant_Binary` | 19/33 | `OBJK_DataWriter_Binary` | 8/12 |
| `OBJK_Topic_Binary` | 20/37 | `OBJK_DataWriter_Binary_Qos` | 3/4 |
| `OBJK_Publisher_Binary` | 16/24 | `OBJK_DataReader_Binary` | 12/17 |
| `OBJK_Subscriber_Binary` | 17/25 | `OBJK_DataReader_Binary_Qos` | 12/20 |
| `OBJK_Requester_Binary` | 22/45 | `OBJK_Endpoint_QosBinary` | 12/17 |
| `OBJK_Replier_Binary` | 22/45 | | |

`OBJK_PUBLISHER_QosBinary::deserialize` and `OBJK_SUBSCRIBER_QosBinary::deserialize` are listed as
uncovered, but they are **inlined** into their callers at `-O1`: the disassembly of
`OBJK_Publisher_Binary::deserialize` calls `Cdr::deserialize<std::string>(std::vector<…>&)` twice
directly, and the "full" publisher/subscriber seeds (which carry partitions and group data) decode
cleanly in the self-test. Their bodies run; only the out-of-line copies are unreached.

The edges still uncovered inside each decoder were **not** analysed one by one.

**Why it holds:** each optional is a one-byte flag that Fast-CDR rejects unless it is 0 or 1, and
every string and sequence length is checked against the remaining buffer before the read, so a
malformed blob ends in a Fast-CDR exception that `<Entity>::create()` catches.

## 6. Honest boundary

- The harness decodes the binary representation; it does **not** run what the Agent does with the
  decoded values next (the middleware calls in `FastDDSMiddleware` / `FastDDSEntities`). That needs
  a Fast-DDS build and is outside this rig.
- More generally the rig covers **deserializers**. Logic in the submessage handlers and the session
  layer that runs before or after a deserializer is not exercised by it.
- Remaining uncovered `::deserialize` functions are response-side or unused types
  (`STATUS_*`, `INFO_Payload`, `DATA_Payload_*`, `*ActivityInfo`, `TransportAddress*`,
  `PackedSamples` / `Sample`). The Agent dispatches only `FORMAT_DATA` for `WRITE_DATA`, so the
  sample sub-formats are not input-reachable.

## 7. Dedup verdict

No crashes to dedup. NVD re-checked 2026-11-11: the Agent's CVE list is still CVE-2025-63547 and
CVE-2025-63548 (see [`known-territory.md`](known-territory.md)).

## 8. Reproduce

```bash
cd research/uas-autonomy/agent_fuzz
CC=clang CXX=clang++ cmake -B build -DAGENT_SRC=~/src/Micro-XRCE-DDS-Agent -DFETCHCONTENT_SOURCE_DIR_FASTCDR=~/src/Fast-CDR
cmake --build build -j"$(nproc)"
./build/agent_fuzz_standalone --selftest                 # 3 edge seeds + 32 binary-representation seeds
mkdir -p corpus && cp seeds/*.bin corpus/ && ./build/agent_fuzz_standalone --gen-seeds corpus
./build/agent_fuzz -max_len=4096 -dict=xrce.dict -fork="$(nproc)" -max_total_time=1500 corpus/
./build/agent_fuzz -runs=0 -print_coverage=1 corpus/ | grep -E "Binary|Qos"
```

## 9. Sources

- Harness: [`agent_fuzz/`](agent_fuzz/) · predecessor: [`phase2-targetB-agent-parse-results.md`](phase2-targetB-agent-parse-results.md)
- Scope & hypotheses (H3): [`phase2-micro-xrce-dds-scope.md`](phase2-micro-xrce-dds-scope.md) · dedup: [`known-territory.md`](known-territory.md)
- Stage-2 decode sites: `src/cpp/{participant,topic,publisher,subscriber,datawriter,datareader,requester,replier}/*.cpp`;
  endianness: `src/cpp/processor/Processor.cpp` (`process_create_submessage`); types: `src/cpp/types/XRCETypes.cpp` (Agent `a88c712…`)
