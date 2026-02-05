# SPDX-FileCopyrightText: Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Intel Score Evaluation Metrics.

Evaluates the quality and accuracy of LLM-generated CVE intelligence scores.
Verifies that scores accurately reflect the technical depth of CVE data
and justifications are grounded in evidence.
"""

from typing import Any
from typing import Optional

from deepeval.metrics import GEval
from deepeval.models.base_model import DeepEvalBaseLLM
from deepeval.test_case import LLMTestCase
from deepeval.test_case import LLMTestCaseParams
from pydantic import BaseModel
from pydantic import Field

# ============================================================================
# Scoring Criteria Reference (for eval context)
# ============================================================================

INTEL_SCORE_CRITERIA = """
INTEL SCORE DIMENSIONS AND MAX POINTS:

1. technical_specificity (max 20 points)
   - Precision and depth of technical details
   - Specific vulnerable functions, methods, or code paths identified

2. clarity (max 10 points)
   - Text structure and grammar
   - Description clarity and understandability

3. component_impact (max 15 points)
   - Clear statement of what is affected
   - Explicit description of consequences

4. reproducibility (max 15 points)
   - Enough detail for attacker to understand exploitation
   - Attack vectors and preconditions described

5. vulnerable_function (max 15 points)
   - Specific function, method, or code snippet named
   - Vulnerable code locations identifiable

6. mitigation (max 10 points)
   - Patches, workarounds, or mitigations described
   - Remediation guidance provided

7. environment (max 10 points)
   - Context about affected environment (OS, version, configuration)
   - Deployment scenarios mentioned

8. configuration (max 5 points)
   - Relevant configuration settings or misconfigurations described

TOTAL POSSIBLE: 100 points
"""

# Max scores for each dimension
INTEL_SCORE_MAX_VALUES = {
    "technical_specificity": 20,
    "clarity": 10,
    "component_impact": 15,
    "reproducibility": 15,
    "vulnerable_function": 15,
    "mitigation": 10,
    "environment": 10,
    "configuration": 5,
}

# ============================================================================
# Data Models
# ============================================================================


class IntelScoreEvalInput(BaseModel):
    """Input data for intel score evaluation."""

    cve_id: str = Field(description="CVE identifier")
    cve_description: str = Field(description="Original CVE description text")
    cvss_vector: Optional[str] = Field(default=None, description="CVSS vector string")
    cwe_name: Optional[str] = Field(default=None, description="CWE classification")

    # The LLM-generated output to evaluate
    scores: dict[str, int] = Field(description="LLM-generated scores per dimension")
    justifications: dict[str, str] = Field(description="LLM-generated justifications")
    total_score: Optional[int] = Field(default=None, description="Calculated total score")


# ============================================================================
# GEval Metric
# ============================================================================


def create_intel_score_fidelity_metric(judge_model: DeepEvalBaseLLM, threshold: float = 0.7) -> GEval:
    """
    Simplified Intel Score Fidelity metric.

    Focuses on two key aspects:
    1. Are scores grounded in CVE data? (no hallucination)
    2. Are scores calibrated correctly? (high-detail CVE = high score)
    """
    return GEval(name="Intel Score Fidelity",
                 criteria="""
        Evaluate if the Intel Scores accurately reflect the CVE data quality.

        INPUT: Original CVE data (description, CVSS, CWE)
        ACTUAL OUTPUT: Generated scores and justifications for 8 dimensions

        EVALUATION CRITERIA:

        1. EVIDENCE GROUNDING (60% weight):
        - Every claim in justifications must exist in the CVE data
        - No fabricated function names, versions, or details
        - Justifications cite specific facts from the CVE text

        2. SCORE CALIBRATION (40% weight):
        - Detailed CVE (specific functions, attack vectors) → High scores (70-100)
        - Moderate detail CVE → Medium scores (40-70)
        - Vague CVE → Low scores (0-40)

        SCORING:
        0.0-0.3: Hallucinations or wildly miscalibrated scores
        0.4-0.6: Mostly accurate with minor issues
        0.7-0.8: Good grounding and calibration
        0.9-1.0: Perfect evidence grounding and calibration
        """,
                 evaluation_params=[LLMTestCaseParams.INPUT, LLMTestCaseParams.ACTUAL_OUTPUT],
                 model=judge_model,
                 threshold=threshold,
                 verbose_mode=True)


# ============================================================================
# Metric Suite
# ============================================================================


class IntelScoreMetricSuite:
    """
    Runs Intel Score evaluation metrics and aggregates results.

    Evaluates the quality and accuracy of LLM-generated CVE intelligence scores.
    """

    def __init__(self, judge_model: DeepEvalBaseLLM):
        """
        Initialize metric suite.

        Args:
            judge_model: DeepEval LLM model for evaluation
        """
        if judge_model is None:
            raise ValueError("judge_model is required for IntelScoreMetricSuite")

        self.judge_model = judge_model
        self.fidelity_metric = create_intel_score_fidelity_metric(judge_model)

    def _format_scores_output(self, input_data: IntelScoreEvalInput) -> str:
        """Format scores and justifications as readable output for evaluation."""
        lines = ["=== GENERATED INTEL SCORES ===\n"]

        # Format scores
        lines.append("SCORES:")
        for dim, score in input_data.scores.items():
            max_score = INTEL_SCORE_MAX_VALUES.get(dim, 0)
            lines.append(f"  {dim}: {score}/{max_score}")

        if input_data.total_score is not None:
            lines.append(f"\n  TOTAL: {input_data.total_score}/100")

        # Format justifications
        lines.append("\nJUSTIFICATIONS:")
        for dim, justification in input_data.justifications.items():
            lines.append(f"  {dim}: {justification}")

        return "\n".join(lines)

    def _format_cve_input(self, input_data: IntelScoreEvalInput) -> str:
        """Format CVE data as input context."""
        lines = [f"CVE ID: {input_data.cve_id}", f"CVE Description: {input_data.cve_description}"]
        if input_data.cvss_vector:
            lines.append(f"CVSS Vector: {input_data.cvss_vector}")
        if input_data.cwe_name:
            lines.append(f"CWE: {input_data.cwe_name}")

        return "\n".join(lines)

    def evaluate(self, input_data: IntelScoreEvalInput) -> dict[str, Any]:
        """
        Run intel score fidelity evaluation.

        Args:
            input_data: IntelScoreEvalInput with CVE data and LLM-generated scores

        Returns:
            Dict with evaluation results including score, passed status, and reasoning
        """
        results = {}

        # Build test case
        cve_input = self._format_cve_input(input_data)
        scores_output = self._format_scores_output(input_data)

        test_case = LLMTestCase(input=cve_input, actual_output=scores_output)

        # Run fidelity metric
        try:
            self.fidelity_metric.measure(test_case)
            results["Intel Score Fidelity"] = {
                "score": self.fidelity_metric.score,
                "passed": self.fidelity_metric.score >= self.fidelity_metric.threshold,
                "reason": self.fidelity_metric.reason,
            }
        except Exception as e:
            results["Intel Score Fidelity"] = {
                "score": 0.0,
                "passed": False,
                "reason": f"Error: {e}",
            }

        # Calculate overall (single metric for now)
        scores = [r["score"] for r in results.values()]
        overall_score = sum(scores) / len(scores) if scores else 0
        passed_count = sum(1 for r in results.values() if r["passed"])

        return {
            "overall_score": overall_score,
            "passed": passed_count == len(results),
            "passed_count": f"{passed_count}/{len(results)}",
            "individual_results": results,
            "cve_id": input_data.cve_id,
            "total_intel_score": input_data.total_score,
        }
