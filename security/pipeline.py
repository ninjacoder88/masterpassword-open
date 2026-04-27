#!/usr/bin/env python3
"""
End-to-end security pipeline:

  Step 1 – threat_modelling.py  → security/findings/threat_model_<ts>.md
  Step 2 – deepagent.py         → security/findings/sast_<ts>.json
                                   (uses threat model as context for all 3 phases)
  Step 3 – eval_report.py       → security/findings/eval_<ts>.json
                                   (scores sast against ground truth)

Usage examples:
  # Run the full pipeline from scratch
  python security/pipeline.py

  # Skip threat modelling (re-use latest existing threat model)
  python security/pipeline.py --skip-threat-model

  # Skip both threat modelling and SAST, only re-evaluate an existing report
  python security/pipeline.py --skip-threat-model --skip-sast

  # Provide specific input files
  python security/pipeline.py \\
      --threat-model-path security/findings/threat_model_2026-04-27_13-42-58.md \\
      --sast-path security/findings/sast_2026-04-27_11-31-53.json
"""
from __future__ import annotations

import argparse
import glob
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FINDINGS_DIR = os.path.join(SCRIPT_DIR, "findings")

# Ensure the security/ directory is on sys.path so we can import peer modules.
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)


def latest_file(pattern: str) -> str | None:
    """Return the lexicographically last file matching *pattern*, or None."""
    matches = sorted(glob.glob(pattern))
    return matches[-1] if matches else None


# ─────────────────────────────────────────────────────────────────────────────
# Step functions
# ─────────────────────────────────────────────────────────────────────────────

def run_threat_model_step() -> str:
    """Execute threat_modelling.py and return the path of the output .md file."""
    from threat_modelling import run_threat_model  # type: ignore[import]

    print("\n" + "=" * 70)
    print("PIPELINE STEP 1 — Threat Modelling")
    print("=" * 70)
    output_path = run_threat_model()
    print(f"\n[Pipeline] Threat model written to: {output_path}")
    return output_path


def run_sast_step(threat_model_path: str | None) -> str:
    """Execute deepagent.py with optional threat model context.

    Returns the path of the produced sast_*.json file.
    """
    from deepagent import run_pipeline  # type: ignore[import]

    print("\n" + "=" * 70)
    print("PIPELINE STEP 2 — SAST Analysis (deepagent)")
    if threat_model_path:
        print(f"  Threat model context : {threat_model_path}")
    print("=" * 70)

    run_pipeline(threat_model_path=threat_model_path)

    sast_path = latest_file(os.path.join(FINDINGS_DIR, "sast_*.json"))
    if not sast_path:
        raise RuntimeError(
            "No sast_*.json found in findings/ after deepagent run. "
            "Check security/logs/ for details."
        )
    print(f"\n[Pipeline] SAST output: {sast_path}")
    return sast_path


def run_eval_step(sast_path: str) -> str:
    """Evaluate *sast_path* against the ground truth.

    Returns the path of the produced eval_*.json file.
    """
    from eval_report import evaluate_report_file  # type: ignore[import]

    ground_truth_path = os.path.join(FINDINGS_DIR, "GROUND_TRUTH.json")
    gt_available = os.path.isfile(ground_truth_path)

    print("\n" + "=" * 70)
    print("PIPELINE STEP 3 — Evaluation")
    print(f"  Report       : {sast_path}")
    print(
        f"  Ground truth : {ground_truth_path}"
        if gt_available
        else "  Ground truth : (not found — evaluation will run without ground truth)"
    )
    print("=" * 70)

    result = evaluate_report_file(
        report_path=sast_path,
        ground_truth_path=ground_truth_path if gt_available else None,
    )

    eval_path = result.get("metadata", {}).get("output_path", "(unknown)")
    scores = result.get("scores", {})
    print(f"\n[Pipeline] Overall score : {scores.get('overall_score', '?')}")
    print(f"[Pipeline] Verdict       : {result.get('verdict', '?')}")
    print(f"[Pipeline] Eval saved    : {eval_path}")
    return eval_path


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run the full security pipeline: "
            "threat model → SAST (deepagent) → evaluation."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--skip-threat-model",
        action="store_true",
        help=(
            "Skip Step 1 (threat modelling). "
            "Requires --threat-model-path or an existing findings/threat_model_*.md."
        ),
    )
    parser.add_argument(
        "--skip-sast",
        action="store_true",
        help=(
            "Skip Step 2 (SAST). "
            "Requires --sast-path or an existing findings/sast_*.json."
        ),
    )
    parser.add_argument(
        "--threat-model-path",
        default=None,
        metavar="PATH",
        help=(
            "Path to a specific threat model .md to use as context for SAST. "
            "Overrides auto-detection of the latest findings/threat_model_*.md."
        ),
    )
    parser.add_argument(
        "--sast-path",
        default=None,
        metavar="PATH",
        help=(
            "Path to a specific sast_*.json to evaluate. "
            "Only used when --skip-sast is set."
        ),
    )
    args = parser.parse_args()

    # ── Step 1: Threat model ──────────────────────────────────────────────────
    if args.skip_threat_model:
        threat_model_path = args.threat_model_path or latest_file(
            os.path.join(FINDINGS_DIR, "threat_model_*.md")
        )
        if threat_model_path:
            print(f"[Pipeline] Step 1 skipped. Using threat model: {threat_model_path}")
        else:
            print(
                "[Pipeline] Step 1 skipped. No existing threat model found — "
                "SAST will run without threat context."
            )
    else:
        threat_model_path = args.threat_model_path or run_threat_model_step()

    # ── Step 2: SAST ─────────────────────────────────────────────────────────
    if args.skip_sast:
        sast_path = args.sast_path or latest_file(
            os.path.join(FINDINGS_DIR, "sast_*.json")
        )
        if not sast_path:
            print(
                "[Pipeline] ERROR: --skip-sast was set but no sast_*.json found "
                "in findings/.",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"[Pipeline] Step 2 skipped. Using SAST report: {sast_path}")
    else:
        sast_path = run_sast_step(threat_model_path)

    # ── Step 3: Eval ─────────────────────────────────────────────────────────
    run_eval_step(sast_path)

    print("\n" + "=" * 70)
    print("[Pipeline] Complete.")
    print("=" * 70)


if __name__ == "__main__":
    main()
