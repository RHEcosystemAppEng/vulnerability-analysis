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
Justification Evaluation Metric.

Single GEval metric for evaluating CVE justification (label + reason) based on JUSTIFICATION_PROMPT requirements:
1. Label must be one of 12 predefined categories
2. Label must be consistent with the summary verdict
3. Reason must cite evidence from the summary
4. Label and reason must be logically aligned
"""

from typing import Any

from deepeval.metrics import GEval
from deepeval.models.base_model import DeepEvalBaseLLM
from deepeval.test_case import LLMTestCase
from deepeval.test_case import LLMTestCaseParams
from pydantic import BaseModel
from pydantic import Field


# ============================================================================
# Constants
# ============================================================================

# Valid justification labels based on VEX standard and JUSTIFICATION_PROMPT
VALID_LABELS = [
    "false_positive",
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_runtime",
    "protected_at_perimeter",
    "protected_by_mitigating_control",
    "uncertain",
    "vulnerable"
]


# ============================================================================
# Data Models
# ============================================================================


class JustificationEvalInput(BaseModel):
    """Input data for justification evaluation."""

    cve_id: str = Field(description="CVE identifier")
    justification_label: str = Field(description="The justification label (e.g., 'vulnerable', 'code_not_present')")
    justification_reason: str = Field(description="The detailed justification reason")
    summary: str = Field(default="", description="The analysis summary (input to justification generation)")

    @classmethod
    def from_extraction(
        cls,
        cve_id: str,
        justification_label: str,
        justification_reason: str,
        summary: str = "",
    ) -> "JustificationEvalInput":
        """Create from extractor output.

        Args:
            cve_id: CVE identifier
            justification_label: Extracted justification label
            justification_reason: Extracted justification reason
            summary: Extracted summary text (the input for justification)

        Returns:
            JustificationEvalInput ready for evaluation
        """
        return cls(
            cve_id=cve_id,
            justification_label=justification_label,
            justification_reason=justification_reason,
            summary=summary,
        )


# ============================================================================
# Metric
# ============================================================================


def create_justification_metric(judge_model: DeepEvalBaseLLM, threshold: float = 0.7) -> GEval:
    """
    Single GEval metric for justification evaluation.

    Based on JUSTIFICATION_PROMPT requirements:
    - Label must be one of 12 valid categories
    - Label must match summary verdict
    - Reason must cite evidence from summary
    - Label and reason must be consistent
    """
    labels_str = ", ".join(VALID_LABELS)

    return GEval(
        name="Justification Quality",
        criteria=f"""
        Evaluate a CVE justification (label + reason) based on these PROMPT REQUIREMENTS:

        THE JUSTIFICATION SHOULD FOLLOW THESE INSTRUCTIONS:
        1. Select ONE category from 12 predefined labels:
           [{labels_str}]
        2. Label selection rules:
           - "vulnerable": ONLY if code is PRESENT, USED, REACHABLE, and NO mitigations
           - Other labels: Select based on PRIMARY reason for non-exploitability
           - Follow logical precedence order (code_not_present > code_not_reachable > etc.)
        3. Provide reasoning citing specific evidence from the summary

        CONTEXT provides the investigation summary (the input to justification generation).
        ACTUAL OUTPUT is "Label: <label>\\n\\nReason: <reasoning>".

        EVALUATION CRITERIA:

        1. LABEL-SUMMARY CONSISTENCY (40% weight):
        - Does the label match the summary verdict?
          * Summary says "exploitable" → label should be "vulnerable"
          * Summary says "not exploitable" → label should be a non-vulnerable category
          * Summary says "uncertain" → label should be "uncertain"
        - Is the label one of the 12 valid categories?
        - Is it the MOST appropriate category for the findings described in the summary?

        2. REASON-SUMMARY FAITHFULNESS (30% weight):
        - Does the reason cite specific evidence from the summary?
        - No fabricated details or contradictions with the summary
        - Technical details (function names, components) match the summary

        3. LABEL-REASON CONSISTENCY (30% weight):
        - Does the reason logically support the chosen label?
        - Are they aligned?
        - Example: If label is "code_not_reachable", reason should explain why code isn't reachable
        - Example: If label is "vulnerable", reason should explain why all exploit conditions are met

        SCORING RUBRIC:

        Score 0.0-0.3 (FAIL):
        - Label contradicts summary verdict (e.g., summary says "not exploitable" but label is "vulnerable")
        - Reason fabricates evidence not in summary
        - Label is not from the valid list

        Score 0.4-0.6 (ADEQUATE):
        - Label somewhat aligned with summary but could be more precise
        - Reason vague or incomplete, weak evidence citation
        - Label and reason loosely connected

        Score 0.7-0.8 (GOOD):
        - Label clearly matches summary verdict
        - Reason cites specific evidence from summary
        - Label and reason are logically consistent
        - Appropriate category selected

        Score 0.9-1.0 (EXCELLENT):
        - Perfect label-summary alignment
        - Rich, specific citations from summary in reason
        - Label is the most precise category for the findings
        - Label and reason form a coherent, professional justification
        """,
        evaluation_params=[LLMTestCaseParams.CONTEXT, LLMTestCaseParams.ACTUAL_OUTPUT],
        model=judge_model,
        threshold=threshold,
        verbose_mode=True
    )


# ============================================================================
# Metric Suite (simplified - single metric)
# ============================================================================


class JustificationMetricSuite:
    """
    Runs justification evaluation metric.
    """

    def __init__(self, judge_model: DeepEvalBaseLLM):
        """
        Initialize metric suite.

        Args:
            judge_model: DeepEval LLM model for evaluation
        """
        if judge_model is None:
            raise ValueError("judge_model is required for JustificationMetricSuite")

        self.judge_model = judge_model
        self.quality_metric = create_justification_metric(judge_model)

    def evaluate(self, input_data: JustificationEvalInput) -> dict[str, Any]:
        """
        Run metric on a justification.

        Args:
            input_data: JustificationEvalInput with label, reason, and summary context

        Returns:
            Dict with score, passed status, and reason
        """
        # Format output for evaluation
        justification_output = f"Label: {input_data.justification_label}\n\nReason: {input_data.justification_reason}"

        test_case = LLMTestCase(
            input=f"CVE: {input_data.cve_id}",
            actual_output=justification_output,
            context=[input_data.summary] if input_data.summary else ["No summary available"]
        )

        try:
            self.quality_metric.measure(test_case)
            result = {
                "score": self.quality_metric.score,
                "passed": self.quality_metric.score >= self.quality_metric.threshold,
                "reason": self.quality_metric.reason,
            }
        except Exception as e:
            result = {
                "score": 0.0,
                "passed": False,
                "reason": f"Error: {e}",
            }

        return {
            "overall_score": result["score"],
            "passed": result["passed"],
            "reason": result["reason"],
            "cve_id": input_data.cve_id,
            "justification_label": input_data.justification_label
        }
