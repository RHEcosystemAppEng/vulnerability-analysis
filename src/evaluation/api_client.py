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
API Client for exploit-iq-client ML-OPS endpoints.

Handles fetching analysis jobs and traces, and submitting evaluation results.
"""

import os
from typing import Any
from typing import Optional

import httpx
from pydantic import BaseModel
from pydantic import Field

# Logger with compatibility for both old and new structure
try:
    from evaluation.utils.logger import get_logger
    logger = get_logger(__name__)
except ImportError:
    # Fallback to vuln_analysis logger
    from vuln_analysis.logging.loggers_factory import LoggingFactory
    logger = LoggingFactory.get_agent_logger(__name__)


class APIConfig(BaseModel):
    """Configuration for API client."""

    base_url: str = Field(default_factory=lambda: os.getenv("BASE") or os.getenv("EXPLOIT_IQ_API_BASE", ""))
    token: Optional[str] = Field(default_factory=lambda: os.getenv("TOKEN") or os.getenv("EXPLOIT_IQ_API_TOKEN"))
    timeout: int = Field(default=60, description="Request timeout in seconds")


class ExploitIQClient:
    """
    Client for exploit-iq-client ML-OPS API.

    Provides methods to:
    - Fetch completed jobs
    - Fetch traces for jobs
    - Submit evaluation results
    """

    def __init__(self, config: Optional[APIConfig] = None):
        """
        Initialize API client.

        Args:
            config: Optional API configuration. Defaults to environment variables.
        """
        self.config = config or APIConfig()
        self.base_url = self.config.base_url.rstrip("/")
        logger.info("Initialized ExploitIQClient with base_url: %s", self.base_url)

    def _get_headers(self) -> dict[str, str]:
        """Get request headers with authentication."""
        headers = {"Content-Type": "application/json"}
        if self.config.token:
            headers["Authorization"] = f"Bearer {self.config.token}"
        return headers

    async def fetch_jobs(self, status: str = "completed", limit: Optional[int] = None) -> list[dict[str, Any]]:
        """
        Fetch jobs from the API.

        Args:
            status: Filter by job status (default: "completed")
            limit: Maximum number of jobs to fetch

        Returns:
            List of job dictionaries
        """
        url = f"{self.base_url}/api/v1/jobs/all"
        params = {"status": status}
        if limit:
            params["limit"] = limit

        logger.info("Fetching jobs with status=%s from %s", status, url)

        async with httpx.AsyncClient(timeout=self.config.timeout, verify=False) as client:
            try:
                response = await client.get(url, params=params, headers=self._get_headers())
                response.raise_for_status()
                jobs = response.json()
                logger.info("Fetched %d jobs", len(jobs) if isinstance(jobs, list) else 1)
                return jobs if isinstance(jobs, list) else [jobs]
            except httpx.HTTPError as e:
                logger.error("Failed to fetch jobs: %s", e)
                raise

    async def fetch_job_by_id(self, job_id: str) -> dict[str, Any]:
        """
        Fetch a specific job by job_id.

        Args:
            job_id: Job identifier

        Returns:
            Job dictionary
        """
        url = f"{self.base_url}/api/v1/jobs"
        params = {"jobId": job_id}

        logger.info("Fetching job with job_id=%s", job_id)

        async with httpx.AsyncClient(timeout=self.config.timeout, verify=False) as client:
            try:
                response = await client.get(url, params=params, headers=self._get_headers())
                response.raise_for_status()
                jobs = response.json()
                # API returns a list, get the first one
                if isinstance(jobs, list) and len(jobs) > 0:
                    logger.info("Successfully fetched job %s", job_id)
                    return jobs[0]
                elif isinstance(jobs, dict):
                    return jobs
                else:
                    logger.error("No job found with job_id=%s", job_id)
                    raise ValueError(f"Job not found: {job_id}")
            except httpx.HTTPError as e:
                logger.error("Failed to fetch job %s: %s", job_id, e)
                raise

    async def fetch_traces(self, job_id: str) -> list[dict[str, Any]]:
        """
        Fetch traces for a specific job.

        Args:
            job_id: Job identifier

        Returns:
            List of trace dictionaries
        """
        url = f"{self.base_url}/api/v1/traces/all"
        params = {"jobId": job_id}  # API uses camelCase

        logger.info("Fetching traces for job_id=%s", job_id)

        async with httpx.AsyncClient(timeout=self.config.timeout, verify=False) as client:
            try:
                response = await client.get(url, params=params, headers=self._get_headers())
                response.raise_for_status()
                traces = response.json()
                logger.info("Fetched %d traces for job %s", len(traces) if isinstance(traces, list) else 0, job_id)
                return traces if isinstance(traces, list) else []
            except httpx.HTTPError as e:
                logger.error("Failed to fetch traces for job %s: %s", job_id, e)
                raise

    async def submit_evaluation(self,
                                job_id: str,
                                trace_id: str,
                                cve: str,
                                component: str,
                                component_version: str,
                                execution_start_timestamp: str,
                                evaluation_results: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Submit evaluation results for a job.

        Args:
            job_id: Job identifier
            trace_id: Trace identifier
            cve: CVE identifier
            component: Component name (e.g., "werkzeug")
            component_version: Component version (e.g., "3.0.5")
            execution_start_timestamp: Execution start timestamp (ISO format)
            evaluation_results: List of evaluation metric dicts with keys:
                - llm_node: e.g., "CHECKLIST_GENERATION", "AGENT_LOOP", "CALCULATE_CVE_SCORE"
                - metric_name: e.g., "CHECKLIST_PROMPT_ALIGNMENT", "AGENT_LOOP_ANSWER_QUALITY"
                - metric_score: float score (converted to string)
                - metric_reasoning: reasoning text
                - model_input: (only for AGENT_LOOP) checklist question
                - model_output: (only for AGENT_LOOP) agent response

        Returns:
            Response from the API
        """
        url = f"{self.base_url}/api/v1/evals"

        # Build payload as list of evaluation records
        payload = []
        for result in evaluation_results:
            record = {
                "job_id": job_id,
                "execution_start_timestamp": execution_start_timestamp,
                "trace_id": trace_id,
                "cve": cve,
                "component": component,
                "component_version": component_version,
                "llm_node": result.get("llm_node", "UNKNOWN"),
                "metric_name": result.get("metric_name"),
                "metric_score": str(result.get("metric_score", 0.0)),
                "metric_reasoning": result.get("metric_reasoning", "")
            }

            # Add model_input and model_output for AGENT_LOOP metrics
            if result.get("llm_node") == "AGENT_LOOP":
                record["model_input"] = result.get("model_input", "")
                record["model_output"] = result.get("model_output", "")

            payload.append(record)

        logger.info("Submitting %d evaluation metrics for job_id=%s", len(payload), job_id)

        async with httpx.AsyncClient(timeout=self.config.timeout, verify=False) as client:
            try:
                response = await client.post(url, json=payload, headers=self._get_headers())
                response.raise_for_status()
                result = response.json()
                logger.info("Successfully submitted evaluation for job %s", job_id)
                return result
            except httpx.HTTPError as e:
                logger.error("Failed to submit evaluation for job %s: %s", job_id, e)
                logger.error("Response: %s", e.response.text if hasattr(e, 'response') else 'N/A')
                raise

    def load_from_local_files(self, jobs_file: str, traces_file: str) -> tuple[list[dict], list[dict]]:
        """
        Load jobs and traces from local JSON files (for testing/development).

        Args:
            jobs_file: Path to jobs.json
            traces_file: Path to traces.json

        Returns:
            Tuple of (jobs, traces)
        """
        import json

        logger.info("Loading from local files: jobs=%s, traces=%s", jobs_file, traces_file)

        with open(jobs_file, 'r') as f:
            jobs = json.load(f)

        with open(traces_file, 'r') as f:
            traces = json.load(f)

        logger.info("Loaded %d jobs and %d traces from local files", len(jobs), len(traces))
        return jobs, traces
