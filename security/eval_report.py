#!/usr/bin/env python3
"""
LLM-as-a-Judge evaluator for DeepAgent SAST report output.

This evaluates the final JSON report produced by security/deepagent.py's
REPORT_PROMPT. It does not run the SAST agent; it scores an existing report.

Usage:
    uv run python security/eval_report.py --report security/findings/sast_run.json
    uv run python security/eval_report.py --report report.json --ground-truth security/findings/GROUND_TRUTH.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from langchain_aws import ChatBedrockConverse
from langchain_core.messages import HumanMessage
from langchain_core.prompts import PromptTemplate

load_dotenv()

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SOURCE_ROOT = REPO_ROOT / "src"


REPORT_CONTRACT = """The SAST agent must return only this JSON report shape:
{
  "summary": {
    "total_findings": <int>,
    "critical": <int>,
    "high": <int>,
    "medium": <int>,
    "low": <int>
  },
  "findings": [
    {
      "id": "FINDING-001",
      "title": "<short descriptive title>",
      "severity": "Critical | High | Medium | Low",
      "owasp_category": "A0X - <Category Name>",
      "cwe": "CWE-<number>",
      "file": "<relative file path>",
      "line": <line number or null>,
      "description": "<1-2 sentences>",
      "evidence": "<exact code snippet or setting value>",
      "attack_scenario": "<concrete attacker action and impact>",
      "remediation": "<specific fix>"
    }
  ]
}
"""

VALID_SEVERITIES = {"critical", "high", "medium", "low"}
REQUIRED_TOP_LEVEL_KEYS = {"summary", "findings"}
REQUIRED_SUMMARY_KEYS = {"total_findings", "critical", "high", "medium", "low"}
REQUIRED_FINDING_KEYS = {
    "id",
    "title",
    "severity",
    "owasp_category",
    "cwe",
    "file",
    "line",
    "description",
    "evidence",
    "attack_scenario",
    "remediation",
}


@dataclass
class LocalValidation:
    parseable_json: bool
    structure_errors: list[str]
    summary_errors: list[str]
    finding_errors: list[str]

    @property
    def passed(self) -> bool:
        return not (self.structure_errors or self.summary_errors or self.finding_errors)

    def to_dict(self) -> dict[str, Any]:
        return {
            "parseable_json": self.parseable_json,
            "passed": self.passed,
            "structure_errors": self.structure_errors,
            "summary_errors": self.summary_errors,
            "finding_errors": self.finding_errors,
        }


@dataclass
class JudgeConfig:
    model_id: str = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
    temperature: float = 0.1


@dataclass
class ReportEvaluationRequest:
    report_path: str | Path
    source_root: str | Path | None = DEFAULT_SOURCE_ROOT
    candidate_findings_path: str | Path | None = None
    ground_truth_path: str | Path | None = None
    judge_model: str = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
    output_path: str | Path | None = None
    temperature: float = 0.1


@dataclass
class FindingMatch:
    ground_truth_id: str
    agent_id: str
    confidence: float
    reasons: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ground_truth_id": self.ground_truth_id,
            "agent_id": self.agent_id,
            "confidence": round(self.confidence, 3),
            "reasons": self.reasons,
        }


def strip_json_fence(text: str) -> str:
    raw = text.strip()
    if raw.startswith("```json"):
        raw = raw.removeprefix("```json").strip()
    elif raw.startswith("```"):
        raw = raw.removeprefix("```").strip()
    if raw.endswith("```"):
        raw = raw.removesuffix("```").strip()
    return raw


def load_json_file(path: Path) -> Any:
    return json.loads(strip_json_fence(path.read_text(encoding="utf-8")))


def write_json_file(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + os.linesep, encoding="utf-8")


def default_eval_output_path(report_path: str | Path) -> Path:
    path = Path(report_path)
    stem = path.stem
    if stem.startswith("sast_"):
        output_stem = "eval_" + stem.removeprefix("sast_")
    else:
        output_stem = stem + "_eval"
    return path.with_name(output_stem + ".json")


def validate_report(report: Any) -> LocalValidation:
    structure_errors: list[str] = []
    summary_errors: list[str] = []
    finding_errors: list[str] = []

    if not isinstance(report, dict):
        return LocalValidation(
            parseable_json=True,
            structure_errors=["Report root must be a JSON object."],
            summary_errors=[],
            finding_errors=[],
        )

    missing_top = REQUIRED_TOP_LEVEL_KEYS - set(report.keys())
    if missing_top:
        structure_errors.append(f"Missing top-level keys: {sorted(missing_top)}")

    summary = report.get("summary")
    findings = report.get("findings")

    if not isinstance(summary, dict):
        summary_errors.append("summary must be an object.")
        summary = {}
    if not isinstance(findings, list):
        finding_errors.append("findings must be an array.")
        findings = []

    missing_summary = REQUIRED_SUMMARY_KEYS - set(summary.keys())
    if missing_summary:
        summary_errors.append(f"Missing summary keys: {sorted(missing_summary)}")

    severity_counts = {severity: 0 for severity in VALID_SEVERITIES}
    for index, finding in enumerate(findings):
        prefix = f"findings[{index}]"
        if not isinstance(finding, dict):
            finding_errors.append(f"{prefix} must be an object.")
            continue

        missing_finding = REQUIRED_FINDING_KEYS - set(finding.keys())
        if missing_finding:
            finding_errors.append(f"{prefix} missing keys: {sorted(missing_finding)}")

        severity = str(finding.get("severity", "")).lower()
        if severity not in VALID_SEVERITIES:
            finding_errors.append(f"{prefix}.severity is invalid: {finding.get('severity')!r}")
        else:
            severity_counts[severity] += 1

        cwe = str(finding.get("cwe", ""))
        if cwe and cwe != "None" and not cwe.startswith("CWE-"):
            finding_errors.append(f"{prefix}.cwe should use CWE-<number> format: {cwe!r}")

    expected_total = len(findings)
    actual_total = summary.get("total_findings")
    if isinstance(actual_total, int) and actual_total != expected_total:
        summary_errors.append(
            f"summary.total_findings is {actual_total}, but findings has {expected_total} items."
        )

    for severity, expected_count in severity_counts.items():
        actual_count = summary.get(severity)
        if isinstance(actual_count, int) and actual_count != expected_count:
            summary_errors.append(
                f"summary.{severity} is {actual_count}, but findings contains {expected_count}."
            )

    return LocalValidation(
        parseable_json=True,
        structure_errors=structure_errors,
        summary_errors=summary_errors,
        finding_errors=finding_errors,
    )


def normalize_text(value: Any) -> str:
    text = str(value or "").lower()
    return re.sub(r"[^a-z0-9]+", " ", text).strip()


def normalize_file_path(value: Any) -> str:
    path = str(value or "").replace("\\", "/").strip().lower()
    path = re.sub(r"^[a-z]:/", "", path)
    path = path.lstrip("/")
    if path.startswith("src/"):
        path = path[4:]
    return path


def token_set(*values: Any) -> set[str]:
    tokens: set[str] = set()
    for value in values:
        tokens.update(token for token in normalize_text(value).split() if len(token) > 2)
    return tokens


def token_overlap_score(left: set[str], right: set[str]) -> float:
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def finding_label(finding: dict[str, Any]) -> str:
    return "{}: {} ({}, {})".format(
        finding.get("id", "unknown"),
        finding.get("title", "untitled"),
        finding.get("cwe", "no CWE"),
        finding.get("severity", "no severity"),
    )


def score_finding_match(ground_truth: dict[str, Any], agent_finding: dict[str, Any]) -> tuple[float, list[str]]:
    score = 0.0
    reasons: list[str] = []

    gt_title = normalize_text(ground_truth.get("title"))
    agent_title = normalize_text(agent_finding.get("title"))
    gt_evidence = normalize_text(ground_truth.get("evidence"))
    agent_evidence = normalize_text(agent_finding.get("evidence"))

    if gt_title and agent_title and gt_title == agent_title:
        score += 0.35
        reasons.append("same title")
    elif gt_title and agent_title:
        title_overlap = token_overlap_score(set(gt_title.split()), set(agent_title.split()))
        if title_overlap >= 0.45:
            score += 0.2
            reasons.append(f"similar title ({title_overlap:.2f})")

    if gt_evidence and agent_evidence:
        if gt_evidence == agent_evidence:
            score += 0.25
            reasons.append("same evidence")
        elif gt_evidence in agent_evidence or agent_evidence in gt_evidence:
            score += 0.18
            reasons.append("overlapping evidence")

    gt_cwe = str(ground_truth.get("cwe") or "").upper()
    agent_cwe = str(agent_finding.get("cwe") or "").upper()
    if gt_cwe and agent_cwe and gt_cwe == agent_cwe:
        score += 0.25
        reasons.append("same CWE")

    gt_file = normalize_file_path(ground_truth.get("file"))
    agent_file = normalize_file_path(agent_finding.get("file"))
    if gt_file and agent_file:
        if gt_file == agent_file:
            score += 0.25
            reasons.append("same file")
        elif gt_file.endswith(agent_file) or agent_file.endswith(gt_file):
            score += 0.2
            reasons.append("compatible file path")

    gt_tokens = token_set(
        ground_truth.get("title"),
        ground_truth.get("description"),
        ground_truth.get("evidence"),
        ground_truth.get("attack_scenario"),
    )
    agent_tokens = token_set(
        agent_finding.get("title"),
        agent_finding.get("description"),
        agent_finding.get("evidence"),
        agent_finding.get("attack_scenario"),
    )
    overlap = token_overlap_score(gt_tokens, agent_tokens)
    if overlap >= 0.3:
        score += 0.2
        reasons.append(f"strong text overlap ({overlap:.2f})")
    elif overlap >= 0.18:
        score += 0.12
        reasons.append(f"moderate text overlap ({overlap:.2f})")
    elif overlap >= 0.1:
        score += 0.06
        reasons.append(f"weak text overlap ({overlap:.2f})")

    gt_owasp = normalize_text(ground_truth.get("owasp_category"))
    agent_owasp = normalize_text(agent_finding.get("owasp_category"))
    if gt_owasp and agent_owasp and gt_owasp.split()[0:1] == agent_owasp.split()[0:1]:
        score += 0.1
        reasons.append("same OWASP category")

    gt_line = ground_truth.get("line")
    agent_line = agent_finding.get("line")
    if isinstance(gt_line, int) and isinstance(agent_line, int) and abs(gt_line - agent_line) <= 5:
        score += 0.05
        reasons.append("nearby line")

    return min(score, 1.0), reasons


def compare_against_ground_truth(
    report: dict[str, Any], ground_truth: Any | None, match_threshold: float = 0.55
) -> dict[str, Any]:
    if not isinstance(ground_truth, dict):
        return {
            "available": False,
            "found_findings": [],
            "missing_findings": [],
            "unmatched_agent_findings": [],
            "recall": None,
            "precision": None,
        }

    gt_findings = [f for f in ground_truth.get("findings", []) if isinstance(f, dict)]
    agent_findings = [f for f in report.get("findings", []) if isinstance(f, dict)]
    unmatched_agent_indexes = set(range(len(agent_findings)))
    matches: list[FindingMatch] = []
    missing: list[dict[str, Any]] = []

    for gt in gt_findings:
        best_index: int | None = None
        best_score = 0.0
        best_reasons: list[str] = []
        for index in unmatched_agent_indexes:
            candidate = agent_findings[index]
            score, reasons = score_finding_match(gt, candidate)
            if score > best_score:
                best_index = index
                best_score = score
                best_reasons = reasons

        if best_index is not None and best_score >= match_threshold:
            unmatched_agent_indexes.remove(best_index)
            matches.append(
                FindingMatch(
                    ground_truth_id=str(gt.get("id") or ""),
                    agent_id=str(agent_findings[best_index].get("id") or ""),
                    confidence=best_score,
                    reasons=best_reasons,
                )
            )
        else:
            missing.append(
                {
                    "id": gt.get("id"),
                    "title": gt.get("title"),
                    "severity": gt.get("severity"),
                    "cwe": gt.get("cwe"),
                    "file": gt.get("file"),
                    "best_match_confidence": round(best_score, 3),
                    "best_match_reasons": best_reasons,
                }
            )

    unmatched_agent_findings = [
        {
            "id": agent_findings[index].get("id"),
            "title": agent_findings[index].get("title"),
            "severity": agent_findings[index].get("severity"),
            "cwe": agent_findings[index].get("cwe"),
            "file": agent_findings[index].get("file"),
        }
        for index in sorted(unmatched_agent_indexes)
    ]

    recall = len(matches) / len(gt_findings) if gt_findings else 1.0
    precision = len(matches) / len(agent_findings) if agent_findings else (1.0 if not gt_findings else 0.0)

    return {
        "available": True,
        "match_threshold": match_threshold,
        "ground_truth_count": len(gt_findings),
        "agent_finding_count": len(agent_findings),
        "found_count": len(matches),
        "missing_count": len(missing),
        "unmatched_agent_count": len(unmatched_agent_findings),
        "recall": round(recall, 3),
        "precision": round(precision, 3),
        "found_findings": [match.to_dict() for match in matches],
        "missing_findings": missing,
        "unmatched_agent_findings": unmatched_agent_findings,
    }


def collect_referenced_evidence(report: dict[str, Any], source_root: Path | None) -> list[dict[str, Any]]:
    if source_root is None or not source_root.exists():
        return []

    source_root = source_root.resolve()

    evidence: list[dict[str, Any]] = []
    for finding in report.get("findings", []):
        if not isinstance(finding, dict):
            continue

        relative_file = str(finding.get("file") or "").strip()
        if not relative_file:
            continue

        normalized_file = normalize_file_path(relative_file)
        candidate = (source_root / normalized_file).resolve()
        try:
            candidate.relative_to(source_root)
        except ValueError:
            evidence.append(
                {
                    "id": finding.get("id"),
                    "file": relative_file,
                    "error": "Referenced file resolves outside source root.",
                }
            )
            continue

        if not candidate.exists() or not candidate.is_file():
            evidence.append(
                {
                    "id": finding.get("id"),
                    "file": relative_file,
                    "normalized_file": normalized_file,
                    "error": "Referenced file does not exist under source root.",
                }
            )
            continue

        line = finding.get("line")
        try:
            lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            evidence.append(
                {"id": finding.get("id"), "file": relative_file, "error": str(exc)}
            )
            continue

        if isinstance(line, int) and line > 0:
            start = max(line - 6, 0)
            end = min(line + 5, len(lines))
        else:
            start = 0
            end = min(40, len(lines))

        snippet = "\n".join(
            f"{line_no}: {content}"
            for line_no, content in enumerate(lines[start:end], start=start + 1)
        )
        evidence.append(
            {
                "id": finding.get("id"),
                "file": relative_file,
                "line": line,
                "snippet": snippet,
            }
        )

    return evidence


class SASTReportJudge:
    def __init__(self, config: JudgeConfig):
        self.config = config
        self.llm = ChatBedrockConverse(
            model_id=config.model_id,
            temperature=config.temperature,
        )

    async def evaluate_report(
        self,
        report: dict[str, Any],
        local_validation: LocalValidation,
        source_evidence: list[dict[str, Any]],
        candidate_findings: Any | None = None,
        ground_truth: Any | None = None,
        ground_truth_coverage: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        prompt = PromptTemplate.from_template(
            """
You are an expert application security evaluation judge. Evaluate the quality of
the final SAST report produced by an agent.

Do not reward formatting alone. The report must be useful to a security engineer:
findings should be real, supported by evidence, correctly prioritized, mapped to
reasonable OWASP/CWE categories, and include concrete attack scenarios and fixes.

## Required Report Contract
{report_contract}

## Local Structural Validation
{local_validation}

## Agent Report To Evaluate
{report_json}

## Source Evidence For Referenced Files
{source_evidence}

## Optional Candidate Findings
{candidate_findings}

## Optional Ground Truth
{ground_truth}

## Deterministic Ground Truth Coverage
{ground_truth_coverage}

## Evaluation Dimensions
Score each dimension from 0.0 to 1.0:
1. summary_score: Summary counts are accurate and useful.
2. finding_validity_score: Findings are real, supported, and not hallucinated.
3. severity_score: Critical/High/Medium/Low ratings match realistic exploitability and impact.
4. taxonomy_score: OWASP and CWE mappings are accurate.
5. evidence_score: Evidence directly proves each finding and references plausible file/line locations.
6. attack_scenario_score: Attack scenarios describe concrete attacker actions and impact.
7. remediation_score: Remediation is specific, implementable, and addresses root cause.
8. precision_score: The report avoids false positives and overclaiming.
9. recall_score: The report catches important issues from candidate findings, ground truth, or source evidence.

Use these weights for overall_score:
- summary_score: 0.05
- finding_validity_score: 0.22
- severity_score: 0.16
- taxonomy_score: 0.10
- evidence_score: 0.15
- attack_scenario_score: 0.10
- remediation_score: 0.10
- precision_score: 0.07
- recall_score: 0.05

Use Deterministic Ground Truth Coverage as the source of truth for whether a
ground-truth item was found or missed. Do not mark a ground-truth finding as
missing if it appears in found_findings. If candidate findings or ground truth
are absent, judge precision and recall from the report and provided source
evidence only, and mention confidence limits.

Return ONLY valid JSON in this exact shape:
{{
  "scores": {{
    "summary_score": 0.0,
    "finding_validity_score": 0.0,
    "severity_score": 0.0,
    "taxonomy_score": 0.0,
    "evidence_score": 0.0,
    "attack_scenario_score": 0.0,
    "remediation_score": 0.0,
    "precision_score": 0.0,
    "recall_score": 0.0,
    "overall_score": 0.0
  }},
  "verdict": "pass | needs_review | fail",
  "finding_reviews": [
    {{
      "id": "FINDING-001",
      "valid": true,
      "severity_correct": true,
      "recommended_severity": "Critical | High | Medium | Low | None",
      "issues": ["short issue text"],
      "feedback": "finding-specific feedback"
    }}
  ],
  "found_findings": ["ground truth finding id found by the agent"],
  "missing_findings": ["important issue the report missed"],
  "false_positives": ["finding id or title that appears unsupported"],
  "feedback": "overall report-quality feedback"
}}
"""
        )

        formatted_prompt = prompt.format(
            report_contract=REPORT_CONTRACT,
            local_validation=json.dumps(local_validation.to_dict(), indent=2),
            report_json=json.dumps(report, indent=2),
            source_evidence=json.dumps(source_evidence, indent=2),
            candidate_findings=json.dumps(candidate_findings, indent=2)
            if candidate_findings is not None
            else "Not provided",
            ground_truth=json.dumps(ground_truth, indent=2)
            if ground_truth is not None
            else "Not provided",
            ground_truth_coverage=json.dumps(ground_truth_coverage, indent=2)
            if ground_truth_coverage is not None
            else "Not provided",
        )

        response = await self.llm.ainvoke([HumanMessage(content=formatted_prompt)])
        raw_response = strip_json_fence(str(response.content))
        evaluation = json.loads(raw_response)
        evaluation["metadata"] = {
            "evaluated_at": datetime.now().isoformat(),
            "judge_model": self.config.model_id,
            "local_validation_passed": local_validation.passed,
        }
        return evaluation


async def evaluate_report_file_async(
    report_path: str | Path,
    source_root: str | Path | None = DEFAULT_SOURCE_ROOT,
    candidate_findings_path: str | Path | None = None,
    ground_truth_path: str | Path | None = None,
    judge_model: str = "us.anthropic.claude-haiku-4-5-20251001-v1:0",
    output_path: str | Path | None = None,
    temperature: float = 0.1,
) -> dict[str, Any]:
    """Evaluate a SAST report file and optionally persist the judge result."""
    request = ReportEvaluationRequest(
        report_path=report_path,
        source_root=source_root,
        candidate_findings_path=candidate_findings_path,
        ground_truth_path=ground_truth_path,
        judge_model=judge_model,
        output_path=output_path,
        temperature=temperature,
    )
    return await evaluate_report_request_async(request)


async def evaluate_report_request_async(request: ReportEvaluationRequest) -> dict[str, Any]:
    """Evaluate a SAST report from a structured request object."""
    report_path = Path(request.report_path)
    if not report_path.exists():
        raise FileNotFoundError(f"Report file not found: {report_path}")

    report = load_json_file(report_path)
    if not isinstance(report, dict):
        raise ValueError("Report JSON root must be an object.")

    validation = validate_report(report)
    source_root = Path(request.source_root).resolve() if request.source_root else None
    source_evidence = collect_referenced_evidence(report, source_root)

    candidate_findings = (
        load_json_file(Path(request.candidate_findings_path))
        if request.candidate_findings_path
        else None
    )
    ground_truth = (
        load_json_file(Path(request.ground_truth_path))
        if request.ground_truth_path
        else None
    )
    ground_truth_coverage = compare_against_ground_truth(report, ground_truth)

    judge = SASTReportJudge(
        JudgeConfig(model_id=request.judge_model, temperature=request.temperature)
    )
    evaluation = await judge.evaluate_report(
        report=report,
        local_validation=validation,
        source_evidence=source_evidence,
        candidate_findings=candidate_findings,
        ground_truth=ground_truth,
        ground_truth_coverage=ground_truth_coverage,
    )
    evaluation["local_validation"] = validation.to_dict()
    evaluation["ground_truth_coverage"] = ground_truth_coverage

    if ground_truth_coverage.get("available"):
        evaluation["found_findings"] = [
            f"{match['ground_truth_id']} found as {match['agent_id']} ({match['confidence']})"
            for match in ground_truth_coverage["found_findings"]
        ]
        evaluation["missing_findings"] = [
            finding_label(finding)
            for finding in ground_truth_coverage["missing_findings"]
        ]
        scores = evaluation.setdefault("scores", {})
        scores["recall_score"] = ground_truth_coverage["recall"]
        scores["precision_score"] = ground_truth_coverage["precision"]

    output_path = Path(request.output_path) if request.output_path else default_eval_output_path(report_path)
    evaluation["metadata"]["output_path"] = str(output_path)
    write_json_file(output_path, evaluation)

    return evaluation


def evaluate_report_file(
    report_path: str | Path,
    source_root: str | Path | None = DEFAULT_SOURCE_ROOT,
    candidate_findings_path: str | Path | None = None,
    ground_truth_path: str | Path | None = None,
    judge_model: str = "us.anthropic.claude-haiku-4-5-20251001-v1:0",
    output_path: str | Path | None = None,
    temperature: float = 0.1,
) -> dict[str, Any]:
    """Synchronous wrapper for scripts that are not already running an event loop."""
    return asyncio.run(
        evaluate_report_file_async(
            report_path=report_path,
            source_root=source_root,
            candidate_findings_path=candidate_findings_path,
            ground_truth_path=ground_truth_path,
            judge_model=judge_model,
            output_path=output_path,
            temperature=temperature,
        )
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate a DeepAgent SAST JSON report with an LLM judge."
    )
    parser.add_argument("--report", required=True, help="Path to SAST report JSON.")
    parser.add_argument(
        "--source-root",
        default=str(DEFAULT_SOURCE_ROOT),
        help="Source root used to verify referenced file/line evidence. Defaults to repository src/.",
    )
    parser.add_argument(
        "--candidate-findings",
        default=None,
        help="Optional JSON file with candidate findings from the analysis phase.",
    )
    parser.add_argument(
        "--ground-truth",
        default=None,
        help="Optional JSON file with expected findings for benchmark evaluation.",
    )
    parser.add_argument(
        "--judge-model",
        default="us.anthropic.claude-haiku-4-5-20251001-v1:0",
        help="Bedrock model id to use as judge.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional path to write evaluation JSON. Defaults to eval_<report timestamp>.json beside the report.",
    )
    return parser


async def async_main() -> int:
    args = build_arg_parser().parse_args()

    try:
        evaluation = await evaluate_report_file_async(
            report_path=args.report,
            source_root=args.source_root,
            candidate_findings_path=args.candidate_findings,
            ground_truth_path=args.ground_truth,
            judge_model=args.judge_model,
            output_path=args.output,
        )
    except json.JSONDecodeError as exc:
        validation = LocalValidation(
            parseable_json=False,
            structure_errors=[f"Report is not parseable JSON: {exc}"],
            summary_errors=[],
            finding_errors=[],
        )
        print(json.dumps({"local_validation": validation.to_dict()}, indent=2))
        return 1

    rendered = json.dumps(evaluation, indent=2)
    print(rendered)

    output_path = evaluation.get("metadata", {}).get("output_path")
    if output_path:
        print(f"\nEvaluation saved: {output_path}")

    return 0


def main() -> None:
    raise SystemExit(asyncio.run(async_main()))


if __name__ == "__main__":
    main()
