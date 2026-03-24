PYTHON := python3
VENV_PYTHON := .venv/bin/python3

.PHONY: help artifacts-dir preflight test test-all test-smoke test-e2e test-regression ci-check show-latest show-index show-summary release-snapshot verify-baseline show-baseline-diff freeze-milestone

help:
	@echo "Available targets:"
	@echo "  make artifacts-dir      - create normalized test artifact root"
	@echo "  make preflight          - run environment and project sanity checks"
	@echo "  make test               - run full test suite"
	@echo "  make test-all           - run full test suite"
	@echo "  make test-smoke         - run smoke suite"
	@echo "  make test-e2e           - run end-to-end suite"
	@echo "  make test-regression    - run regression suite"
	@echo "  make ci-check           - run CI contract checks"
	@echo "  make show-latest        - print latest suite pointers"
	@echo "  make show-index         - print artifact index"
	@echo "  make show-summary       - print enriched artifact summary"
	@echo "  make release-snapshot   - write release baseline manifest"
	@echo "  make verify-baseline    - verify current tree against release baseline"
	@echo "  make show-baseline-diff - print human-readable drift report"
	@echo "  make freeze-milestone   - freeze current verified baseline as milestone"

artifacts-dir:
	mkdir -p artifacts/test_runs
	mkdir -p artifacts/test_runs/latest
	mkdir -p artifacts/releases
	mkdir -p artifacts/releases/milestones

preflight: artifacts-dir
	$(VENV_PYTHON) -m scripts.preflight_check

test: test-all

test-all: artifacts-dir
	$(VENV_PYTHON) -m scripts.run_tests --suite all

test-smoke: artifacts-dir
	$(VENV_PYTHON) -m scripts.run_tests --suite smoke

test-e2e: artifacts-dir
	$(VENV_PYTHON) -m scripts.run_tests --suite e2e

test-regression: artifacts-dir
	$(VENV_PYTHON) -m scripts.run_tests --suite regression

ci-check: artifacts-dir
	$(VENV_PYTHON) -m scripts.ci_check

show-latest:
	find artifacts/test_runs/latest -maxdepth 1 -type f | sort | xargs -r -I{} sh -c 'printf "\n== %s ==\n" "{}"; cat "{}"'

show-index:
	cat artifacts/test_runs/index.json

show-summary:
	$(VENV_PYTHON) -m scripts.show_artifact_summary

release-snapshot: artifacts-dir
	$(VENV_PYTHON) -m scripts.release_snapshot

verify-baseline: artifacts-dir
	$(VENV_PYTHON) -m scripts.verify_release_baseline

show-baseline-diff: artifacts-dir
	$(VENV_PYTHON) -m scripts.show_baseline_diff

freeze-milestone: artifacts-dir
	$(VENV_PYTHON) -m scripts.freeze_milestone
