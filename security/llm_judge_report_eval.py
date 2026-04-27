#!/usr/bin/env python3
"""
LLM-as-a-Judge evaluator for DeepAgent SAST report output.

This evaluates the final JSON report produced by security/deepagent.py's
REPORT_PROMPT. It does not run the SAST agent; it scores an existing report.

Usage:
    uv run python security/llm_judge_report_eval.py --report security_findings/sast_run.json
    uv run python security/llm_judge_report_eval.py --report report.json --source-root security/repo --output eval.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from langchain_aws import ChatBedrockConverse
from langchain_core.messages import HumanMessage
from langchain_core.prompts import PromptTemplate

load_dotenv()


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


def collect_referenced_evidence(report: dict[str, Any], source_root: Path | None) -> list[dict[str, Any]]:
    if source_root is None or not source_root.exists():
        return []

    evidence: list[dict[str, Any]] = []
    for finding in report.get("findings", []):
        if not isinstance(finding, dict):
            continue

        relative_file = str(finding.get("file") or "").strip()
        if not relative_file:
            continue

        candidate = (source_root / relative_file).resolve()
        try:
            candidate.relative_to(source_root.resolve())
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

If candidate findings or ground truth are absent, judge precision and recall from
the report and provided source evidence only, and mention confidence limits.

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


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate a DeepAgent SAST JSON report with an LLM judge."
    )
    parser.add_argument("--report", required=True, help="Path to SAST report JSON.")
    parser.add_argument(
        "--source-root",
        default=None,
        help="Optional source root used to verify referenced file/line evidence.",
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
        help="Optional path to write evaluation JSON.",
    )
    return parser


async def async_main() -> int:
    args = build_arg_parser().parse_args()

    report_path = Path(args.report)
    if not report_path.exists():
        raise FileNotFoundError(f"Report file not found: {report_path}")

    try:
        report = load_json_file(report_path)
    except json.JSONDecodeError as exc:
        validation = LocalValidation(
            parseable_json=False,
            structure_errors=[f"Report is not parseable JSON: {exc}"],
            summary_errors=[],
            finding_errors=[],
        )
        print(json.dumps({"local_validation": validation.to_dict()}, indent=2))
        return 1

    validation = validate_report(report)
    source_root = Path(args.source_root).resolve() if args.source_root else None
    source_evidence = collect_referenced_evidence(report, source_root)

    candidate_findings = load_json_file(Path(args.candidate_findings)) if args.candidate_findings else None
    ground_truth = load_json_file(Path(args.ground_truth)) if args.ground_truth else None

    judge = SASTReportJudge(JudgeConfig(model_id=args.judge_model))
    evaluation = await judge.evaluate_report(
        report=report,
        local_validation=validation,
        source_evidence=source_evidence,
        candidate_findings=candidate_findings,
        ground_truth=ground_truth,
    )

    evaluation["local_validation"] = validation.to_dict()
    rendered = json.dumps(evaluation, indent=2)
    print(rendered)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered + os.linesep, encoding="utf-8")
        print(f"\nEvaluation saved: {output_path}")

    return 0


def main() -> None:
    raise SystemExit(asyncio.run(async_main()))


if __name__ == "__main__":
    main()
