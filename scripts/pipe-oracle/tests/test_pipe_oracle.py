import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock


WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_DIR = WORKSPACE_ROOT / "scripts/pipe-oracle"
CASE_DIR = WORKSPACE_ROOT / "test-suit/starryos/qemu/pipe-linux-oracle"
ARTIFACT_ENV = "STARRY_PIPE_ORACLE_ARTIFACT_DIR"

sys.path.insert(0, str(SCRIPT_DIR))

import analyze  # noqa: E402
import coverage  # noqa: E402
import fuzz  # noqa: E402
import generator  # noqa: E402
import replay  # noqa: E402


class PipeOracleRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._oracle_temp = tempfile.TemporaryDirectory()
        cls.oracle_build = Path(cls._oracle_temp.name) / "build"
        subprocess.run(
            ["cmake", "-S", str(CASE_DIR / "c"), "-B", str(cls.oracle_build)],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                "cmake",
                "--build",
                str(cls.oracle_build),
                "--target",
                "pipe-linux-oracle",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        cls.oracle = cls.oracle_build / "pipe-linux-oracle"

    @classmethod
    def tearDownClass(cls):
        cls._oracle_temp.cleanup()

    def test_script_help_works_from_the_command_path(self):
        for script in ("analyze.py", "fuzz.py", "replay.py"):
            result = subprocess.run(
                [sys.executable, str(SCRIPT_DIR / script), "--help"],
                cwd=WORKSPACE_ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("usage:", result.stdout)

    def test_canonical_input_uses_actual_ops_text_and_sha256(self):
        raw_input = bytes(range(32))

        canonical_text, digest = generator.canonicalize_input(raw_input)

        self.assertEqual(
            canonical_text,
            generator.ops_to_text(generator.expand_input(raw_input)),
        )
        self.assertEqual(
            digest,
            hashlib.sha256(canonical_text.encode("utf-8")).hexdigest(),
        )

    def test_analysis_json_is_deterministic_and_satisfies_count_constraints(self):
        first = analyze.analyze(seed=42, samples=128, mutations=256, top=3)
        second = analyze.analyze(seed=42, samples=128, mutations=256, top=3)

        first_json = json.dumps(first, indent=2, sort_keys=True)
        second_json = json.dumps(second, indent=2, sort_keys=True)
        self.assertEqual(first_json, second_json)
        self.assertEqual(
            set(first["sources"]), {"campaign_rng", "independent_rng"}
        )

        for source in first["sources"].values():
            generation = source["generation"]
            mutation = source["mutation"]
            self.assertEqual(
                generation["samples"],
                generation["unique_canonical_scenarios"]
                + generation["duplicate_samples"],
            )
            for field in ("attempts", "raw_changed", "scenario_changed"):
                self.assertEqual(
                    mutation[field],
                    sum(
                        kind_counts[field]
                        for kind_counts in mutation["by_kind"].values()
                    ),
                )
            self.assertGreater(
                mutation["raw_changed_scenario_unchanged"],
                0,
            )
            self.assertEqual(
                sum(generation["parameter_buckets"]["length"].values()),
                generation["operation_counts"]["read"]
                + generation["operation_counts"]["write"],
            )
            self.assertEqual(
                sum(generation["parameter_buckets"]["pipe_size"].values()),
                generation["operation_counts"]["set-size"],
            )
            self.assertEqual(
                sum(generation["parameter_buckets"]["poll_mask"].values()),
                generation["operation_counts"]["poll"],
            )
            for operation, buckets in generation[
                "endpoint_counts_before_operation"
            ].items():
                self.assertEqual(
                    sum(buckets.values()),
                    generation["operation_counts"][operation],
                )
            for scenario in generation["top_scenarios"]:
                self.assertEqual(
                    scenario["digest"],
                    hashlib.sha256(
                        scenario["canonical_text"].encode("utf-8")
                    ).hexdigest(),
                )

    def test_analysis_is_offline_and_does_not_create_files(self):
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            env = os.environ.copy()
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_DIR / "analyze.py"),
                    "--seed",
                    "7",
                    "--samples",
                    "16",
                    "--mutations",
                    "32",
                    "--top",
                    "0",
                    "--format",
                    "json",
                ],
                cwd=temp_path,
                env=env,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(list(temp_path.iterdir()), [])

        with mock.patch.object(
            analyze.fuzz.subprocess,
            "run",
            side_effect=AssertionError("offline analysis must not run subprocesses"),
        ):
            analyze.analyze(seed=7, samples=16, mutations=32, top=0)

    def test_multi_input_batch_is_one_corpus_accepted_by_the_oracle(self):
        scenarios = []
        for fuzz_input in (b"first", b"second", bytes(range(32))):
            scenarios.extend(generator.expand_input(fuzz_input))
        corpus = generator.ops_to_text(scenarios)

        self.assertEqual(corpus.count("version 1\n"), 1)
        scenario_names = [
            line.split(maxsplit=1)[1]
            for line in corpus.splitlines()
            if line.startswith("scenario ")
        ]
        self.assertEqual(len(scenario_names), len(set(scenario_names)))

        with tempfile.TemporaryDirectory() as temp:
            corpus_path = Path(temp) / "pipe.ops"
            trace_path = Path(temp) / "linux.trace"
            corpus_path.write_text(corpus)
            result = subprocess.run(
                [str(self.oracle), "--record", str(corpus_path), str(trace_path)],
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_generated_operations_use_positional_syntax_and_valid_slots(self):
        observed = set()
        for seed in range(512):
            for scenario in generator.expand_input(seed.to_bytes(8, "little")):
                slots = [None] * 16
                for operation in scenario:
                    fields = operation.split()
                    kind = fields[0]
                    observed.add(kind)
                    if kind == "pipe2":
                        self.assertEqual(len(fields), 3)
                        reader, writer = map(int, fields[1:])
                        self.assertNotEqual(reader, writer)
                        self.assertIsNone(slots[reader])
                        self.assertIsNone(slots[writer])
                        slots[reader] = "reader"
                        slots[writer] = "writer"
                    elif kind == "read":
                        self.assertEqual(len(fields), 3)
                        slot, length = map(int, fields[1:])
                        self.assertEqual(slots[slot], "reader")
                        self.assertIn(length, range(8193))
                    elif kind == "write":
                        self.assertEqual(len(fields), 4)
                        slot, length, byte = map(int, fields[1:])
                        self.assertEqual(slots[slot], "writer")
                        self.assertIn(length, range(8193))
                        self.assertIn(byte, range(256))
                    elif kind == "dup":
                        self.assertEqual(len(fields), 3)
                        source, destination = map(int, fields[1:])
                        self.assertIsNotNone(slots[source])
                        self.assertIsNone(slots[destination])
                        slots[destination] = slots[source]
                    elif kind == "close":
                        self.assertEqual(len(fields), 2)
                        slot = int(fields[1])
                        self.assertIsNotNone(slots[slot])
                        slots[slot] = None
                    elif kind == "poll":
                        self.assertEqual(len(fields), 3)
                        slot, events = map(int, fields[1:])
                        self.assertIsNotNone(slots[slot])
                        self.assertGreater(events, 0)
                    elif kind == "set-size":
                        self.assertEqual(len(fields), 3)
                        slot, size = map(int, fields[1:])
                        self.assertEqual(slots[slot], "writer")
                        self.assertGreater(size, 0)
                    elif kind == "get-size":
                        self.assertEqual(len(fields), 2)
                        slot = int(fields[1])
                        self.assertEqual(slots[slot], "writer")
                    elif kind == "fionread":
                        self.assertEqual(len(fields), 2)
                        slot = int(fields[1])
                        self.assertEqual(slots[slot], "reader")
                    else:
                        self.fail(f"unexpected generated operation: {operation}")

        self.assertEqual(
            observed,
            {
                "pipe2",
                "read",
                "write",
                "dup",
                "close",
                "poll",
                "set-size",
                "get-size",
                "fionread",
            },
        )

    def test_coverage_region_ids_are_stable_hashable_and_covered_only(self):
        export = {
            "data": [
                {
                    "files": [
                        {
                            "filename": "/checkout/os/StarryOS/kernel/src/file/pipe.rs",
                            "segments": [
                                [10, 2, 4, True, True, False],
                                [11, 7, 0, True, True, False],
                                [12, 3, 9, True, False, False],
                            ],
                        },
                        {
                            "filename": "/checkout/os/StarryOS/kernel/src/file/other.rs",
                            "segments": [[10, 2, 8, True, True, False]],
                        },
                    ]
                }
            ]
        }

        region_ids = coverage.covered_pipe_region_ids(export)

        self.assertEqual(region_ids, {"os/StarryOS/kernel/src/file/pipe.rs:10:2"})
        self.assertEqual(hash(frozenset(region_ids)), hash(frozenset(region_ids)))

    def test_coverage_uses_active_rust_toolchain_llvm_tools(self):
        with tempfile.TemporaryDirectory() as temp:
            target_libdir = Path(temp) / "lib/rustlib/x86_64-unknown-linux-gnu/lib"
            tool = target_libdir.parent / "bin/llvm-cov"
            tool.parent.mkdir(parents=True)
            tool.touch()
            with mock.patch.object(
                coverage.subprocess,
                "check_output",
                return_value=f"{target_libdir}\n",
            ):
                resolved = coverage.llvm_tool("llvm-cov")

        self.assertEqual(resolved, tool)

    def test_fuzz_qemu_receives_current_batch_artifact_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            artifact_dir = Path(temp).resolve()
            with mock.patch.object(fuzz, "run_guest_compare") as run:
                run.return_value = ("guest", [], True)
                fuzz._run_guest_compare(WORKSPACE_ROOT, artifact_dir)

        run.assert_called_once_with(WORKSPACE_ROOT, artifact_dir)

    def test_fuzz_failure_reports_replayable_artifact_path(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            oracle = workspace / "pipe-linux-oracle"
            oracle.write_bytes(b"oracle")
            failures_dir = workspace / "coverage/pipe-oracle-fuzz/failures"

            def record_host(_elf, _ops, trace):
                trace.write_bytes(b"trace")
                return True

            output = StringIO()
            with (
                mock.patch.object(
                    fuzz, "_find_or_build_host_oracle", return_value=oracle
                ),
                mock.patch.object(fuzz, "_record_host", side_effect=record_host),
                mock.patch.object(
                    fuzz,
                    "_run_guest_compare",
                    return_value=("guest log", [], False),
                ),
                mock.patch.object(fuzz, "_save_batch_failure") as save_failure,
                redirect_stdout(output),
            ):
                failed = fuzz._run_batch(
                    workspace,
                    2,
                    [b"failing input"],
                    set(),
                    set(),
                    failures_dir,
                )

        self.assertTrue(failed)
        failure_path = save_failure.call_args.args[0]
        expected_path = failure_path.relative_to(workspace)
        self.assertIn(f"MISMATCH saved to {expected_path}", output.getvalue())

    def test_replay_qemu_receives_failure_artifact_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            failure_dir = Path(temp).resolve()
            with mock.patch.object(replay, "run_guest_compare") as run:
                run.return_value = ("guest", [], True)
                replay._run_guest_compare(WORKSPACE_ROOT, failure_dir)

        run.assert_called_once_with(WORKSPACE_ROOT, failure_dir)

    def test_qemu_subprocess_gets_absolute_artifact_environment(self):
        with tempfile.TemporaryDirectory() as temp:
            artifact_dir = Path(temp).resolve()
            for name in ("pipe-linux-oracle", "pipe.ops", "linux.trace"):
                (artifact_dir / name).write_bytes(name.encode())
            with mock.patch("runner.subprocess.run") as run:
                run.return_value = subprocess.CompletedProcess([], 0, "ok", "")
                from runner import run_guest_compare

                run_guest_compare(WORKSPACE_ROOT, artifact_dir)

        child_env = run.call_args.kwargs["env"]
        self.assertEqual(child_env[ARTIFACT_ENV], str(artifact_dir))

    def test_cmake_external_artifacts_are_installed_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            artifact_dir = temp_path / "artifacts"
            build_dir = temp_path / "build"
            install_dir = temp_path / "install"
            artifact_dir.mkdir()
            expected = {
                "pipe-linux-oracle": b"external static elf\x00",
                "pipe.ops": b"version 1\nscenario exact\npipe2 0 1\n",
                "linux.trace": b"external trace\x00\x01",
            }
            for name, contents in expected.items():
                (artifact_dir / name).write_bytes(contents)
            env = os.environ.copy()
            env[ARTIFACT_ENV] = str(artifact_dir.resolve())

            subprocess.run(
                [
                    "cmake",
                    "-S",
                    str(CASE_DIR / "c"),
                    "-B",
                    str(build_dir),
                    f"-DCMAKE_INSTALL_PREFIX={install_dir}",
                ],
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["cmake", "--build", str(build_dir), "--target", "install"],
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

            installed = {
                "pipe-linux-oracle": install_dir / "usr/bin/pipe-linux-oracle",
                "pipe.ops": install_dir
                / "usr/share/starry-tests/pipe-linux-oracle/pipe.ops",
                "linux.trace": install_dir
                / "usr/share/starry-tests/pipe-linux-oracle/linux.trace",
            }
            for name, path in installed.items():
                self.assertEqual(path.read_bytes(), expected[name])

    def test_case_defers_detailed_failure_and_enables_coverage(self):
        qemu_config = (CASE_DIR / "qemu-x86_64.toml").read_text()
        build_config = (CASE_DIR / "build-x86_64-unknown-none.toml").read_text()
        shell_init_cmd = qemu_config.split('shell_init_cmd = """', maxsplit=1)[1].split(
            '"""', maxsplit=1
        )[0]

        fail_regex = qemu_config.split("fail_regex = [", maxsplit=1)[1]
        self.assertNotIn("STARRY_PIPE_LINUX_ORACLE_FAILED", fail_regex)
        self.assertIn("AXTEST_COVERAGE_DEFERRED_FAIL", fail_regex)
        self.assertNotIn(
            "AXTEST_COVERAGE_DEFERRED_FAIL",
            shell_init_cmd,
        )
        self.assertIn('AXTEST_COVERAGE = "y"', build_config)


if __name__ == "__main__":
    unittest.main()
