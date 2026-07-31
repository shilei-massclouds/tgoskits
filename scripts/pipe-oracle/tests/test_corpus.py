import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_DIR = WORKSPACE_ROOT / "scripts/pipe-oracle"

sys.path.insert(0, str(SCRIPT_DIR))

import corpus  # noqa: E402
import generator  # noqa: E402
import scenario  # noqa: E402


class PersistentCorpusRegressionTests(unittest.TestCase):
    def test_campaign_restart_loads_saved_canonical_entry(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            store = corpus.CorpusStore(workspace)
            document = generator.generate_document(generator.CampaignRng(7))
            provenance = corpus.CorpusProvenance.generated()

            store.save_entry(document, provenance, {"pipe.rs:7:1"})

            restarted = corpus.CanonicalCorpus.initial()
            loaded = corpus.CorpusStore(workspace).load_corpus()
            for entry in loaded.ordered_entries():
                restarted.add(entry.document)

            self.assertEqual(len(corpus.CanonicalCorpus.initial()), 5)
            self.assertEqual(len(loaded), 1)
            self.assertEqual(len(restarted), 6)
            entry = loaded.ordered_entries()[0]
            metadata = self._metadata(store.corpus_dir / entry.digest)
            self.assertEqual(
                metadata["origin"],
                {
                    "source": "generated",
                    "parent_digest": None,
                    "donor_digest": None,
                    "mutation_type": None,
                },
            )

    def test_canonical_equivalents_create_one_directory(self):
        first = scenario.parse_document(
            "version 1\nscenario first\npipe2 0 1\n"
        )
        second = scenario.parse_document(
            "# spelling and names are not semantic\n"
            "version 0x1\nscenario second\npipe2 0x0 0x1\n"
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = corpus.CorpusStore(Path(temporary_directory))

            self.assertTrue(
                store.save_entry(
                    first,
                    corpus.CorpusProvenance.generated(),
                    {"pipe.rs:1:1"},
                )
            )
            self.assertFalse(
                store.save_entry(
                    second,
                    corpus.CorpusProvenance.generated(),
                    {"pipe.rs:2:1"},
                )
            )

            entry_directories = [
                path for path in store.corpus_dir.iterdir() if path.is_dir()
            ]
            self.assertEqual(len(entry_directories), 1)
            metadata = self._metadata(entry_directories[0])
            self.assertEqual(
                metadata["stability"]["successful_batch_verifications"],
                2,
            )

    def test_mutation_metadata_preserves_parent_donor_and_descendant(self):
        parent = scenario.parse_document(
            "version 1\nscenario parent\npipe2 0 1\n"
        )
        donor = scenario.parse_document(
            "version 1\nscenario donor\npipe2 2 3\nwrite 3 1 97\n"
        )
        descendant = scenario.parse_document(
            "version 1\nscenario child\npipe2 0 1\nwrite 1 1 97\n"
        )
        parent_digest = scenario.canonical_digest(parent)
        donor_digest = scenario.canonical_digest(donor)
        provenance = corpus.CorpusProvenance.mutated(
            parent_digest,
            donor_digest,
            "donor-splice",
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            store = corpus.CorpusStore(Path(temporary_directory))
            store.save_entry(descendant, provenance, {"pipe.rs:7:4", "pipe.rs:3:2"})
            descendant_digest = scenario.canonical_digest(descendant)
            metadata = self._metadata(store.corpus_dir / descendant_digest)

        self.assertEqual(
            metadata["origin"],
            {
                "source": "mutation",
                "parent_digest": parent_digest,
                "donor_digest": donor_digest,
                "mutation_type": "donor-splice",
            },
        )
        self.assertEqual(metadata["canonical_digest"], descendant_digest)
        self.assertEqual(metadata["coverage"]["attribution"], "batch-pending")
        self.assertEqual(
            metadata["coverage"]["first_batch_new_regions"],
            ["pipe.rs:3:2", "pipe.rs:7:4"],
        )
        self.assertEqual(metadata["batch_status"], {"compare": "passed", "replay": "not-run"})

    def test_schema_and_generator_incompatibility_fail_closed(self):
        cases = (
            ("schema_version", 3, "unsupported corpus schema"),
            ("generator_version", "future", "incompatible generator version"),
        )
        for field, value, reason in cases:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary_directory:
                store, entry_dir = self._saved_entry(Path(temporary_directory))
                metadata = self._metadata(entry_dir)
                metadata[field] = value
                (entry_dir / corpus.METADATA_NAME).write_text(
                    json.dumps(metadata), encoding="utf-8"
                )

                with self.assertRaises(corpus.CorpusValidationError) as caught:
                    store.load_corpus()

                self.assertEqual(caught.exception.path, entry_dir)
                self.assertIn(reason, str(caught.exception))

    def test_v1_entry_lazily_upgrades_to_exact_v2_when_it_contributes_again(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            store, entry_dir = self._saved_entry(Path(temporary_directory))
            document = scenario.parse_document((entry_dir / corpus.OPS_NAME).read_bytes())

            self.assertEqual(self._metadata(entry_dir)["schema_version"], 1)

            self.assertTrue(
                store.update_existing_attribution(
                    document,
                    {"pipe.rs:8:2", "pipe.rs:9:3"},
                    "campaign-batch-0002",
                )
            )

            upgraded = self._metadata(entry_dir)
            self.assertEqual(upgraded["schema_version"], 2)
            self.assertEqual(upgraded["coverage"]["attribution"], "exact")
            self.assertEqual(
                upgraded["coverage"]["attributed_regions"],
                ["pipe.rs:8:2", "pipe.rs:9:3"],
            )
            self.assertEqual(
                upgraded["coverage"]["attribution_jobs"],
                ["campaign-batch-0002"],
            )
            self.assertEqual(upgraded["batch_status"]["replay"], "passed")
            self.assertEqual(upgraded["stability"]["status"], "stable")
            self.assertEqual(
                upgraded["stability"]["successful_attribution_verifications"],
                1,
            )
            self.assertEqual(len(store.load_corpus()), 1)

    def test_new_exact_entry_is_written_as_strict_v2(self):
        document = scenario.parse_document(
            "version 1\nscenario exact\npipe2 0 1\nwrite 1 1 97\n"
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = corpus.CorpusStore(Path(temporary_directory))

            self.assertTrue(
                store.admit_attributed_entry(
                    document,
                    corpus.CorpusProvenance.generated(),
                    {"pipe.rs:10:4"},
                    "campaign-batch-0001",
                )
            )

            entry_dir = store.corpus_dir / scenario.canonical_digest(document)
            metadata = self._metadata(entry_dir)
            self.assertEqual(metadata["schema_version"], 2)
            self.assertEqual(
                set(metadata["coverage"]),
                {
                    "attribution",
                    "first_batch_new_regions",
                    "attributed_regions",
                    "attribution_jobs",
                },
            )
            self.assertEqual(len(store.load_corpus()), 1)

    def test_interrupted_v1_to_v2_upgrade_preserves_original_metadata(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            store, entry_dir = self._saved_entry(Path(temporary_directory))
            document = scenario.parse_document((entry_dir / corpus.OPS_NAME).read_bytes())
            original = (entry_dir / corpus.METADATA_NAME).read_bytes()

            with mock.patch.object(
                corpus.os,
                "replace",
                side_effect=OSError("simulated lazy-upgrade interruption"),
            ):
                with self.assertRaisesRegex(
                    OSError, "simulated lazy-upgrade interruption"
                ):
                    store.update_existing_attribution(
                        document,
                        {"pipe.rs:8:2"},
                        "campaign-batch-0002",
                    )

            self.assertEqual((entry_dir / corpus.METADATA_NAME).read_bytes(), original)
            self.assertEqual(len(corpus.CorpusStore(Path(temporary_directory)).load_corpus()), 1)

    def test_digest_noncanonical_and_corrupt_entries_fail_closed(self):
        mutations = (
            (
                "metadata-digest",
                lambda entry_dir: self._rewrite_metadata(
                    entry_dir, "canonical_digest", "0" * 64
                ),
                "canonical digest mismatch",
            ),
            (
                "noncanonical-ops",
                lambda entry_dir: (entry_dir / corpus.OPS_NAME).write_text(
                    "version 0x1\nscenario renamed\npipe2 0x0 0x1\n",
                    encoding="utf-8",
                ),
                "pipe.ops is not canonical",
            ),
            (
                "corrupt-ops",
                lambda entry_dir: (entry_dir / corpus.OPS_NAME).write_bytes(b"\xff"),
                "invalid-encoding",
            ),
            (
                "corrupt-metadata",
                lambda entry_dir: (entry_dir / corpus.METADATA_NAME).write_text(
                    "{", encoding="utf-8"
                ),
                "cannot read JSON",
            ),
        )
        for name, mutate, reason in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary_directory:
                store, entry_dir = self._saved_entry(Path(temporary_directory))
                mutate(entry_dir)

                with self.assertRaises(corpus.CorpusValidationError) as caught:
                    store.load_corpus()

                self.assertIn(str(entry_dir), str(caught.exception))
                self.assertIn(reason, str(caught.exception))

    def test_directory_metadata_digest_and_scenario_limits_fail_closed(self):
        cases = (
            (
                "directory-digest",
                self._rename_to_wrong_digest,
                "pipe.ops digest mismatches directory",
            ),
            (
                "pipe-ops-metadata-digest",
                lambda entry_dir: self._rewrite_metadata(
                    entry_dir, "pipe_ops_sha256", "f" * 64
                ),
                "pipe.ops metadata digest mismatch",
            ),
            (
                "scenario-limit",
                self._replace_with_oversized_scenario_set,
                "too-many-scenarios",
            ),
        )
        for name, mutate, reason in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary_directory:
                store, entry_dir = self._saved_entry(Path(temporary_directory))
                mutate(entry_dir)

                with self.assertRaises(corpus.CorpusValidationError) as caught:
                    store.load_corpus()

                self.assertIn(reason, str(caught.exception))

    def test_interrupted_entry_directory_is_never_loaded(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = corpus.CorpusStore(Path(temporary_directory))
            store.prepare()
            digest = "1" * 64
            interrupted = store.corpus_dir / f".{digest}.tmp-interrupted"
            interrupted.mkdir()
            (interrupted / corpus.OPS_NAME).write_text(
                "version 1\nscenario x\npipe2 0 1\n",
                encoding="utf-8",
            )

            loaded = corpus.CorpusStore(Path(temporary_directory)).load_corpus()

            self.assertEqual(len(loaded), 0)
            self.assertFalse((store.corpus_dir / digest).exists())

    def test_last_verified_metadata_update_is_atomic(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            store, entry_dir = self._saved_entry(Path(temporary_directory))
            original = (entry_dir / corpus.METADATA_NAME).read_bytes()
            document = scenario.parse_document((entry_dir / corpus.OPS_NAME).read_bytes())

            with mock.patch.object(
                corpus.os,
                "replace",
                side_effect=OSError("simulated replace interruption"),
            ):
                with self.assertRaisesRegex(OSError, "simulated replace interruption"):
                    store.save_entry(
                        document,
                        corpus.CorpusProvenance.generated(),
                        {"pipe.rs:9:1"},
                    )

            self.assertEqual((entry_dir / corpus.METADATA_NAME).read_bytes(), original)
            self.assertFalse(
                any(
                    path.name.startswith(".metadata.json.tmp-")
                    for path in entry_dir.iterdir()
                )
            )

            self.assertFalse(
                store.save_entry(
                    document,
                    corpus.CorpusProvenance.generated(),
                    {"pipe.rs:9:1"},
                )
            )
            updated = self._metadata(entry_dir)
            self.assertEqual(updated["first_observed"], self._json_bytes(original)["first_observed"])
            self.assertEqual(
                updated["stability"]["successful_batch_verifications"],
                2,
            )

    def test_coverage_state_is_restored_only_for_the_same_elf(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            first_elf = workspace / "starry-first"
            second_elf = workspace / "starry-second"
            first_elf.write_bytes(b"first instrumented elf")
            second_elf.write_bytes(b"second instrumented elf")
            store = corpus.CorpusStore(workspace)

            first_digest = store.save_coverage_regions(
                first_elf,
                {"pipe.rs:1:2", "pipe.rs:3:4"},
            )
            restarted = corpus.CorpusStore(workspace)

            self.assertEqual(
                restarted.load_coverage_regions(first_elf),
                {"pipe.rs:1:2", "pipe.rs:3:4"},
            )
            self.assertEqual(restarted.load_coverage_regions(second_elf), set())
            second_digest = restarted.save_coverage_regions(
                second_elf,
                {"pipe.rs:8:9"},
            )
            self.assertNotEqual(first_digest, second_digest)
            self.assertEqual(
                {path.stem for path in store.coverage_state_dir.glob("*.json")},
                {first_digest, second_digest},
            )

    def test_campaign_lock_rejects_a_second_owner(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = corpus.CorpusStore(Path(temporary_directory))
            with store.campaign_lock():
                with self.assertRaises(corpus.CampaignLockError):
                    with corpus.CorpusStore(Path(temporary_directory)).campaign_lock():
                        self.fail("the second campaign unexpectedly acquired the lock")

    def test_interrupted_run_save_has_no_loadable_run_directory(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = corpus.CorpusStore(Path(temporary_directory))
            with mock.patch.object(
                corpus.os,
                "replace",
                side_effect=OSError("simulated run rename interruption"),
            ):
                with self.assertRaisesRegex(OSError, "simulated run rename interruption"):
                    store.save_run("run-interrupted", {"result": "passed"})

            self.assertFalse((store.runs_dir / "run-interrupted").exists())
            self.assertEqual(list(store.runs_dir.iterdir()), [])

    def _saved_entry(self, workspace):
        store = corpus.CorpusStore(workspace)
        document = scenario.parse_document(
            "version 1\nscenario saved\npipe2 0 1\n"
        )
        store.save_entry(
            document,
            corpus.CorpusProvenance.generated(),
            {"pipe.rs:1:1"},
        )
        return store, store.corpus_dir / scenario.canonical_digest(document)

    def _metadata(self, entry_dir):
        return json.loads((entry_dir / corpus.METADATA_NAME).read_text(encoding="utf-8"))

    def _rewrite_metadata(self, entry_dir, field, value):
        metadata = self._metadata(entry_dir)
        metadata[field] = value
        (entry_dir / corpus.METADATA_NAME).write_text(
            json.dumps(metadata), encoding="utf-8"
        )

    def _rename_to_wrong_digest(self, entry_dir):
        destination = entry_dir.parent / ("f" * 64)
        entry_dir.rename(destination)

    def _replace_with_oversized_scenario_set(self, entry_dir):
        encoded = "version 1\n" + "".join(
            f"scenario item-{index}\npipe2 0 1\n"
            for index in range(scenario.MAX_SCENARIOS_PER_ENTRY + 1)
        )
        document = scenario.parse_document(encoded)
        canonical = scenario.serialize_document(document).encode("utf-8")
        digest = scenario.canonical_digest(document)
        (entry_dir / corpus.OPS_NAME).write_bytes(canonical)
        metadata = self._metadata(entry_dir)
        metadata["canonical_digest"] = digest
        metadata["pipe_ops_sha256"] = digest
        (entry_dir / corpus.METADATA_NAME).write_text(
            json.dumps(metadata), encoding="utf-8"
        )
        entry_dir.rename(entry_dir.parent / digest)

    def _json_bytes(self, encoded):
        return json.loads(encoded.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
