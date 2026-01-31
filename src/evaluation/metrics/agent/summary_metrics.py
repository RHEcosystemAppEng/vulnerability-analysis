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
Summary Evaluation Metric.

Single GEval metric for evaluating CVE analysis summaries based on the SUMMARY_PROMPT requirements:
1. 3-5 sentence paragraph
2. Opens with explicit verdict ("The CVE is exploitable" / "not exploitable" / "uncertain")
3. Cites specific evidence (function names, file paths, components)
4. Uses only definitive findings, ignores inconclusive items
"""

from typing import Any

from deepeval.metrics import GEval
from deepeval.models.base_model import DeepEvalBaseLLM
from deepeval.test_case import LLMTestCase
from deepeval.test_case import LLMTestCaseParams
from pydantic import BaseModel
from pydantic import Field

# ============================================================================
# Data Models
# ============================================================================


class SummaryEvalInput(BaseModel):
    """Input data for summary evaluation."""

    cve_id: str = Field(description="CVE identifier")
    cve_description: str = Field(default="", description="CVE description for context")
    summary: str = Field(description="The generated summary to evaluate")
    checklist_questions: list[str] = Field(default_factory=list,
                                           description="Checklist questions that were investigated")
    checklist_responses: list[str] = Field(default_factory=list,
                                           description="Responses to checklist questions (evidence for summary)")

    @classmethod
    def from_extraction(
        cls,
        cve_id: str,
        cve_description: str,
        summary: str,
        checklist_step_details: list[Any],
    ) -> "SummaryEvalInput":
        """Create from extractor output.

        Args:
            cve_id: CVE identifier
            cve_description: CVE description
            summary: Extracted summary text
            checklist_step_details: List of ChecklistStepDetail objects

        Returns:
            SummaryEvalInput ready for evaluation
        """
        questions = [step.question for step in checklist_step_details]
        responses = [step.response for step in checklist_step_details]

        return cls(
            cve_id=cve_id,
            cve_description=cve_description,
            summary=summary,
            checklist_questions=questions,
            checklist_responses=responses,
        )


# ============================================================================
# Metric
# ============================================================================


def create_summary_metric(judge_model: DeepEvalBaseLLM, threshold: float = 0.7) -> GEval:
    """
    Single GEval metric for summary evaluation.

    Based on SUMMARY_PROMPT requirements:
    - 3-5 sentence paragraph
    - Opens with explicit verdict
    - Cites specific evidence
    - Faithful to investigation results
    """
    return GEval(name="Summary Quality",
                 criteria="""
        Evaluate a CVE exploitability summary based on these PROMPT REQUIREMENTS:

        THE SUMMARY SHOULD FOLLOW THESE INSTRUCTIONS:
        1. Write a 3-5 sentence paragraph
        2. VERDICT (sentence 1): Begin with explicit statement
           - "The CVE is exploitable" / "The CVE is not exploitable" / "Exploitability is uncertain"
        3. EVIDENCE (sentences 2-4): Support with specific findings
           - Cite concrete results: functions found/absent, reachability status, configuration states
           - Use technical details: function names, file paths, components
           - Connect findings to exploitability conditions
        4. FOCUS: Use only definitive checklist results; ignore inconclusive items

        CONTEXT provides the investigation results (checklist questions and responses).
        ACTUAL OUTPUT is the generated summary to evaluate.

        EVALUATION CRITERIA:

        1. STRUCTURE (25% weight):
        - Is the summary 3-5 sentences long?
        - Does it start with an explicit verdict statement?

        2. VERDICT ACCURACY (25% weight):
        - Does the verdict correctly reflect the investigation findings?
        - Is the verdict one of the three valid options?
        - Would a security analyst agree with this conclusion?

        3. EVIDENCE CITATION (25% weight):
        - Does it cite specific technical details (function names, file paths, components)?
        - Are the citations traceable to the investigation results?
        - Does it connect findings to exploitability conditions?

        4. FAITHFULNESS (25% weight):
        - No fabricated evidence or hallucinated details
        - No contradictions with investigation results
        - Only uses definitive results (not inconclusive ones)

        SCORING RUBRIC:

        Score 0.0-0.3 (FAIL):
        - Verdict contradicts investigation findings
        - Contains fabricated evidence
        - Wrong structure (not 3-5 sentences, no verdict opening)

        Score 0.4-0.6 (ADEQUATE):
        - Verdict generally matches findings
        - Some evidence citation but vague
        - Structure mostly correct

        Score 0.7-0.8 (GOOD):
        - Correct verdict clearly stated at beginning
        - Multiple specific technical citations
        - All claims traceable to investigation results
        - Good structure

        Score 0.9-1.0 (EXCELLENT):
        - Perfect verdict alignment with findings
        - Rich, specific citations throughout
        - Professional quality, actionable for security analysts
        - Follows all prompt instructions precisely
        """,
                 evaluation_params=[LLMTestCaseParams.CONTEXT, LLMTestCaseParams.ACTUAL_OUTPUT],
                 model=judge_model,
                 threshold=threshold,
                 verbose_mode=True)


# ============================================================================
# Metric Suite (simplified - single metric)
# ============================================================================


class SummaryMetricSuite:
    """
    Runs summary evaluation metric.
    """

    def __init__(self, judge_model: DeepEvalBaseLLM):
        """
        Initialize metric suite.

        Args:
            judge_model: DeepEval LLM model for evaluation
        """
        if judge_model is None:
            raise ValueError("judge_model is required for SummaryMetricSuite")

        self.judge_model = judge_model
        self.quality_metric = create_summary_metric(judge_model)

    def evaluate(self, input_data: SummaryEvalInput) -> dict[str, Any]:
        """
        Run metric on a summary.

        Args:
            input_data: SummaryEvalInput with summary and investigation context

        Returns:
            Dict with score, passed status, and reason
        """
        # Build context from checklist Q&A
        context_parts = []
        for i, (q, r) in enumerate(zip(input_data.checklist_questions, input_data.checklist_responses), 1):
            if r:  # Only include if response exists
                context_parts.append(f"Q{i}: {q}\nFinding: {r}")

        context_str = "\n\n".join(context_parts) if context_parts else "No investigation findings available"

        test_case = LLMTestCase(input=f"CVE: {input_data.cve_id}\nDescription: {input_data.cve_description}",
                                actual_output=input_data.summary,
                                context=[context_str])

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
            "cve_id": input_data.cve_id
        }
