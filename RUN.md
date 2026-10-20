# CIS 6614 — Modbus Comparative Fuzzing: Run Procedure

Scope: libmodbus v3.1.10 (vulnerable) / v3.1.11 (fixed) / v3.2.0 (current
release), two threat models, pymodbus v3.15.0.

Files: `harness.c`, `harness_client.c`, `harness_py.py`,
`harness_py_client.py`, `mkseeds.py`, `modbus.dict`

---

## 0. Setup

**Prerequisites.** Docker Desktop (or Docker Engine) must be installed and
running. Nothing else is needed on the host: both toolchains live in
containers.

**Platform.** These runs were done on an Apple Silicon Mac (M1). The
`--platform linux/amd64` flag below forces the x86_64 image, which Docker
executes under emulation, so throughput is roughly 16k executions per second
rather than the rates AFL++ reaches natively. The comparisons here are
internally valid because every run used the same machine, but absolute
throughput is not portable. On a native x86_64 Linux host, drop
`--platform linux/amd64` and expect substantially higher numbers.

On the host:

```bash
mkdir -p ~/fuzzing/work/repo && cd ~/fuzzing/work/repo
cp ~/Downloads/{harness.c,harness_client.c,harness_py.py,harness_py_client.py,mkseeds.py,modbus.dict,RUN.md} .
grep -c LIBMODBUS_VERSION_CHECK harness.c    # must print 1
docker run -it --platform linux/amd64 -v "$(pwd)":/work aflplusplus/aflplusplus bash
```

In the container:

```bash
cd /work && ls
export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_NO_AFFINITY=1
export ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0:detect_odr_violation=0
python3 mkseeds.py                           # seeds/ 13, seeds_client/ 11
```

If `/work` is empty the bind mount failed and results will be lost when the
container is removed. Check from the host and restart if needed:

```bash
docker inspect -f '{{range .Mounts}}{{.Source}} => {{.Destination}}{{"\n"}}{{end}}' <container>
```

---

## 1. Build libmodbus

`AFL_USE_ASAN=1` must be on `configure` too. Without it there are no stack
redzones around `rsp[260]` and the overflow is never detected.

```bash
for v in v3.1.10 v3.1.11 v3.2.0; do
  cd /work
  rm -rf "lib-$v" && git clone -q --depth 1 -b "$v" https://github.com/stephane/libmodbus.git "lib-$v"
  cd "lib-$v" && ./autogen.sh
  AFL_USE_ASAN=1 CC=afl-clang-fast ./configure --enable-static --disable-shared --disable-tests
  AFL_USE_ASAN=1 make -j"$(nproc)"
done
cd /work
```

Under QEMU on Apple Silicon `autogen.sh` takes several minutes per version.

---

## 2. Build harnesses

`REQ_CAP` selects the threat model. Build both.

- `260` — network-reachable: the most `modbus_receive` can pass on.
- `1024` — API contract: caller supplies `req_length` directly.

```bash
cd /work
for v in v3.1.10 v3.1.11 v3.2.0; do
  for cap in 260 1024; do
    AFL_USE_ASAN=1 afl-clang-fast -g -O1 -fno-omit-frame-pointer \
      -fsanitize=fuzzer,address -DREQ_CAP=$cap \
      -I "lib-$v/src" harness.c "lib-$v/src/.libs/libmodbus.a" -o "h_server_${v}_cap${cap}"
  done
  AFL_USE_ASAN=1 afl-clang-fast -g -O1 -fno-omit-frame-pointer \
    -fsanitize=fuzzer,address \
    -I "lib-$v/src" harness_client.c "lib-$v/src/.libs/libmodbus.a" -o "h_client_${v}"
done
ls h_*
```

Throughput check — fewer than 100k runs means something is sleeping:

```bash
./h_server_v3.1.10_cap260 seeds -max_total_time=20 -max_len=260 2>&1 | grep '^Done'
```

---

## 3. Campaigns

```bash
mkdir -p out
for v in v3.1.10 v3.1.11 v3.2.0; do
  for cap in 260 1024; do
    for i in 1 2 3; do
      afl-fuzz -i seeds -o "out/${v}_cap${cap}_t${i}" -s $i -x modbus.dict \
               -E 300000 -m none -- "./h_server_${v}_cap${cap}"
    done
  done
  afl-fuzz -i seeds_client -o "out/client_${v}" -s 1 -x modbus.dict \
           -E 300000 -m none -- "./h_client_${v}"
done
```

Collect:

```bash
for d in out/*/default; do
  echo "== $d"
  grep -E '^(execs_done|execs_per_sec|corpus_count|edges_found|total_edges|saved_crashes|saved_hangs)' "$d/fuzzer_stats"
done | tee results_libmodbus.txt
```

Report `saved_hangs` alongside coverage — discarded hangs are what suppressed
coverage in the earlier campaigns.

---

## 4. Triage

```bash
CR=out/v3.1.10_cap1024_t1/default/crashes
afl-tmin -i "$CR/id:000000,"* -o min.bin -m none -- ./h_server_v3.1.10_cap1024
ASAN_OPTIONS=symbolize=1 ./h_server_v3.1.10_cap1024 min.bin 2>&1 | head -20
```

Reading the report: `[48, 308) 'rsp'` means `rsp` is 260 bytes; a write at
offset 308 is the first byte past it. `WRITE of size N` is the whole memcpy, so
`req_length` = N and the overflow is N − 260. N must equal `wc -c min.bin`.

There is no `xxd` in this image. Decode the fields with python:

```bash
python3 - << 'EOF'
d = open("min.bin", "rb").read()
fc = d[7]
sites = {0x05: "WRITE_SINGLE_COIL (modbus.c:905)",
         0x06: "WRITE_SINGLE_REGISTER (modbus.c:936)",
         0x16: "MASK_WRITE_REGISTER (modbus.c:1058)"}
print("req_length    :", len(d), "-> overflow", len(d) - 260, "bytes")
print("protocol id   : 0x%04x" % int.from_bytes(d[2:4], "big"))
print("mbap length   :", int.from_bytes(d[4:6], "big"), "(actual body", len(d) - 6, ")")
print("function code : 0x%02x" % fc, "->", sites.get(fc, "other"))
print("address       :", int.from_bytes(d[8:10], "big"), "(must be < 500)")
print("data          : 0x%04x" % int.from_bytes(d[10:12], "big"))
EOF
```

Cross-version check with the same PoC:

```bash
mkdir -p gt && cp min.bin gt/poc.bin
for b in h_server_v3.1.10_cap1024 h_server_v3.1.11_cap1024 \
         h_server_v3.2.0_cap1024 h_server_v3.1.10_cap260; do
  ./$b gt/poc.bin > "gt/${b}.log" 2>&1; echo "$b exit=$?"
done
```

134 = SIGABRT under ASan (vulnerable), 0 = clean. Keep `gt/*.log`; without them
a row of "0 crashes" cannot be told apart from a harness that could never find
anything.

Deduplicate:

```bash
for f in "$CR"/id:*; do
  ASAN_OPTIONS=symbolize=1 ./h_server_v3.1.10_cap1024 "$f" 2>&1 \
    | grep -E '^    #[0-2] ' | md5sum | cut -c1-8
done | sort | uniq -c | sort -rn
```

---

## 5. pymodbus

Separate container — the AFL++ image has no Atheris.

```bash
cd ~/fuzzing/work/repo
docker run -it --platform linux/amd64 -v "$(pwd)":/work python:3.11 bash
cd /work
pip install atheris
git clone -q https://github.com/pymodbus-dev/pymodbus.git
cd pymodbus && git checkout v3.15.0 && pip install -e . && cd /work
python3 mkseeds.py
python3 mkseeds_py.py
python3 -c "import atheris; from importlib.metadata import version; print(version('pymodbus'))"
```

`seeds/` holds raw ADUs for the libmodbus harnesses. The Atheris harness reads
its first bytes as control values through `FuzzedDataProvider`, so it needs
`seeds_py/` instead — same ADUs with a control prefix, plus two oversized
frames so libFuzzer raises its length limit early. Using `seeds/` here would
handicap the pymodbus side of the comparison with frames that never parse.

Validate the oracle first. The harness passes only `ModbusException` as a
legitimate rejection; everything else becomes `AssertionError`. Getting this
right is what makes "0 crashes" a measurement instead of a guarantee.

```bash
mkdir -p corpus_py_probe
PM_SIDE=server python3 harness_py.py -runs=2000 -max_len=600 corpus_py_probe seeds_py
```

A flood of `AssertionError` means the whitelist is too narrow — add the
pymodbus exception type from the traceback to `EXPECTED_EXC` in the harness.

Campaigns:

```bash
mkdir -p crashes_py
for i in 1 2 3; do
  mkdir -p corpus_py_srv_t$i corpus_py_cli_t$i    # libFuzzer requires these to exist
  PM_SIDE=server python3 harness_py.py -runs=300000 -seed=$i -max_len=600 \
      -print_final_stats=1 -artifact_prefix=crashes_py/srv_t${i}_ corpus_py_srv_t$i seeds_py
  PM_SIDE=client python3 harness_py_client.py -runs=300000 -seed=$i -max_len=600 \
      -print_final_stats=1 -artifact_prefix=crashes_py/cli_t${i}_ corpus_py_cli_t$i seeds_py
done 2>&1 | tee results_pymodbus.txt
```

`-max_len` must be set explicitly. Without it libFuzzer infers the limit from
the seed sizes and ramps up slowly, so long frames barely get exercised.

If `-runs=` does not terminate, use `-atheris_runs=300000`.

Atheris prints an `Instrumenting ...` block on every launch, so the log is
mostly noise. Pull the numbers out with:

```bash
grep -E '^#[0-9]+\s+DONE|^ERROR|Done [0-9]+ runs|stat::' results_pymodbus.txt
```

Record the final `cov:` and `ft:` values and the corpus size per run.

---

## 6. Cross-implementation replay

The campaigns above fuzz each library separately. This step feeds one
shared set of inputs to both and records what each one does with it.
It is not fuzzing: each input runs once, so the whole thing takes
minutes.

Files: `mkprobes.py`, `replay_libmodbus.c`, `replay_pymodbus.py`,
`run_replay.sh`, `merge_replay.py`.

The replay drivers do **not** reuse the fuzzing harnesses. The Atheris
harness consumes its first bytes through `FuzzedDataProvider`, so the
same file would mean different things to each side. The drivers read
raw ADUs instead, which is what makes the input set genuinely shared.

Generate the inputs once (26 files: 9 valid requests, 17 probes, one
per row of the divergence table):

```bash
cp min.bin .          # optional, includes the CVE input
python3 mkprobes.py
```

In the **AFL++ container**, with `lib-v3.1.10/` and `lib-v3.2.0/` still
built from section 1:

```bash
./run_replay.sh libmodbus
```

In the **python container**:

```bash
./run_replay.sh pymodbus
```

Put the resulting `replay_*.tsv` files in one place and merge:

```bash
python3 merge_replay.py          # rows where the implementations differ
python3 merge_replay.py --all    # every row
```

This writes `replay_table.tex`. The classes are ACCEPT, EXCEPTION,
DROP, REJECT, INCOMPLETE, ERROR and CRASH; the driver sources document
what each means.

---

## 7. Wall-clock cross-check

Confirms that the exec-matched budget is not driving the conclusions.
Thirty minutes at roughly 16k exec/s is about 100x the 300k budget, so
this doubles as a saturation test: if `edges_found` is unchanged, the
coverage plateau is real.

**Run these sequentially, never in parallel.** Two fuzzers on one
machine compete for CPU and the comparison breaks.

AFL++ container:

```bash
afl-fuzz -i seeds -o out/v3.1.10_cap1024_wall -s 1 -x modbus.dict \
         -V 1800 -m none -- ./h_server_v3.1.10_cap1024
```

`-V` is a wall-clock limit in seconds, unlike `-E`. The output
directory name must differ from the exec-matched runs or AFL++ resumes
the old session instead of starting clean.

python container:

```bash
mkdir -p corpus_py_wall
PM_SIDE=server python3 harness_py.py -max_total_time=1800 -max_len=600 \
    -print_final_stats=1 corpus_py_wall seeds_py
```

`-max_len=600` is required. Without it libFuzzer infers the limit from
the seed sizes and barely generates long frames.

Three runs, 90 minutes total: v3.1.10 at both bounds and pymodbus
server. `run_wall.sh` does this; `collect_wall.py` prints both budgets
side by side. Run the two sides sequentially, never at once.

Results obtained:

| Config | Budget | Execs | Cov | Crashes |
|---|---|---:|---:|---:|
| v3.1.10 cap260 | 300k | 300,000 | 132 | 0 |
| | 30 min | 29,377,732 | 132 | 0 |
| v3.1.10 cap1024 | 300k | 300,000 | 131 | 1 |
| | 30 min | 25,201,009 | 132 | 5 |
| pymodbus server | 300k | 300,000 | 113 | N/A |
| | 30 min | 36,874,563 | 117 | N/A |

The five saved crashes are five inputs, not five defects: AFL++ saves
on a new coverage bitmap, not a new root cause. `triage_crashes.py`
groups them by the function code that selects the branch — two at
0x06, two at 0x05, one at 0x16.

---

## 8. Results

| Target | Threat model | Tool | Trials | execs (median) | Coverage | Crashes |
|---|---|---|---|---|---|---|
| libmodbus v3.1.10 server | cap260 | AFL++ | 3 | | edges/total | |
| libmodbus v3.1.10 server | cap1024 | AFL++ | 3 | | edges/total | CVE-2024-10918 |
| libmodbus v3.1.11 server | cap260 | AFL++ | 3 | | edges/total | |
| libmodbus v3.1.11 server | cap1024 | AFL++ | 3 | | edges/total | 0 |
| libmodbus v3.2.0 server | cap260 | AFL++ | 3 | | edges/total | |
| libmodbus v3.2.0 server | cap1024 | AFL++ | 3 | | edges/total | 0 |
| libmodbus client (×3 versions) | — | AFL++ | 1 | | edges/total | |
| pymodbus v3.15.0 server | — | Atheris | 3 | | cov/ft | |
| pymodbus v3.15.0 client | — | Atheris | 3 | | cov/ft | |

Median and min–max range over trials.

Threat-model table:

| Binary | Exit | Meaning |
|---|---|---|
| `h_server_v3.1.10_cap1024` | 134 | vulnerable |
| `h_server_v3.1.11_cap1024` | 0 | patched |
| `h_server_v3.2.0_cap1024` | 0 | fix persists in current release |
| `h_server_v3.1.10_cap260` | 0 | out of threat model |

Rows 1 and 4 are the same binary code and the same input; only `REQ_CAP` differs.

---

## 9. Limitations paragraph

> We restrict the version sweep to v3.1.10 (vulnerable), v3.1.11 (the release
> carrying the fix) and v3.2.0 (the current release at time of writing),
> because the research question concerns input-validation divergence between
> implementations rather than evolution within one. Including v3.2.0 shows the
> fix persists in the shipping version rather than only in the patch release.
>
> Coverage is reported as AFL++ edge counts and Atheris cov/ft counts. These
> units are not comparable across implementations, so cross-implementation
> comparison is qualitative, based on which input classes each library accepts.
>
> Three trials per configuration is below the number recommended for
> significance testing; we report median and range instead. Campaigns ran under
> x86_64 emulation on Apple Silicon. This does not affect the exec-matched
> results, since 300,000 executions is the same work at any speed, but it does
> bound the wall-clock cross-check: a native host would complete considerably
> more executions in the same thirty minutes, so the coverage ceiling we report
> is an upper bound on what this hardware reached, not on what the harness can
> reach.

---

## 10. Export

```bash
cd /work
{
  echo "date: $(date -u +%FT%TZ)"
  echo "clang: $(clang --version | head -1)"
  for d in lib-v*; do echo "$d: $(git -C $d rev-parse HEAD)"; done
  sha256sum harness.c harness_client.c harness_py.py
} > manifest.txt

tar czf /tmp/results.tgz out/*/default/fuzzer_stats out/*/default/plot_data \
  out/*/default/crashes out/*/default/hangs gt/ min.bin \
  results_libmodbus.txt manifest.txt
```

```bash
# host
docker cp <container>:/tmp/results.tgz ~/fuzzing/results.tgz
tar xzf ~/fuzzing/results.tgz -C ~/fuzzing/
```

Repeat for `results_pymodbus.txt` and `crashes_py/` in the python container.
Keep `plot_data` — it is the coverage-over-time CSV.
