# SPDX-FileCopyrightText: Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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


import logging
import os
import queue
import time
import typing
from http import HTTPStatus

import json5
import mrc
from pydantic import BaseModel

from morpheus.common import FiberQueue
from morpheus.common import HttpEndpoint
from morpheus.config import Config
from morpheus.pipeline.preallocator_mixin import PreallocatorMixin
from morpheus.pipeline.single_output_source import SingleOutputSource
from morpheus.pipeline.stage_schema import StageSchema
from morpheus.stages.input.http_server_source_stage import SUPPORTED_METHODS
from morpheus.utils.http_utils import HTTPMethod
from morpheus.utils.http_utils import HttpParseResponse
from morpheus.utils.http_utils import MimeTypes
from morpheus.utils.producer_consumer_queue import Closed

logger = logging.getLogger(f"morpheus.{__name__}")


class PydanticHttpStage(PreallocatorMixin, SingleOutputSource):
    """
    Source stage that starts an HTTP server and listens for incoming requests on a specified endpoint.

    Parameters
    ----------
    config : `morpheus.config.Config`
        Pipeline configuration instance.
    bind_address : str, default "127.0.0.1"
        The address to bind the HTTP server to.
    port : int, default 8080
        The port to bind the HTTP server to.
    endpoint : str, default "/"
        The endpoint to listen for requests on.
    method : `morpheus.utils.http_utils.HTTPMethod`, optional, case_sensitive = False
        HTTP method to listen for. Valid values are "POST" and "PUT".
    accept_status: `http.HTTPStatus`, default 201, optional
        The HTTP status code to return when a request is accepted. Valid values must be in the 2xx range.
    sleep_time : float, default 0.1
        Amount of time in seconds to sleep if the request queue is empty.
    queue_timeout : int, default 5
        Maximum amount of time in seconds to wait for a request to be added to the queue before rejecting requests.
    max_queue_size : int, default None
        Maximum number of requests to queue before rejecting requests. If `None` then `config.edge_buffer_size` will be
        used.
    num_server_threads : int, default None
        Number of threads to use for the HTTP server. If `None` then `os.cpu_count()` will be used.
    max_payload_size : int, default 10
        The maximum size in megabytes of the payload that the server will accept in a single request.
    request_timeout_secs : int, default 30
        The maximum amount of time in seconds for any given request.
    lines : bool, default False
        If False, the HTTP server will expect each request to be a JSON array of objects. If True, the HTTP server will
        expect each request to be a JSON object per line.
    stop_after : int, default 0
        Stops ingesting after processing `stop_after` requests. Useful for testing. Disabled if `0`
    payload_to_df_fn : callable, default None
        A callable that takes the HTTP payload string as the first argument and the `lines` parameter is passed in as
        the second argument and returns a cudf.DataFrame. When supplied, the C++ implementation of this stage is
        disabled, and the Python impl is used.
    """

    def __init__(self,
                 config: Config,
                 *,
                 bind_address: str = "127.0.0.1",
                 port: int = 8080,
                 endpoint: str = "/message",
                 method: HTTPMethod = HTTPMethod.POST,
                 accept_status: HTTPStatus = HTTPStatus.CREATED,
                 sleep_time: float = 0.1,
                 queue_timeout: int = 5,
                 max_queue_size: int = None,
                 num_server_threads: int = None,
                 max_payload_size: int = 10,
                 request_timeout_secs: int = 30,
                 lines: bool = False,
                 stop_after: int = 0,
                 input_schema: type[BaseModel]):
        super().__init__(config)
        self._bind_address = bind_address
        self._port = port
        self._endpoint = endpoint
        self._method = method
        self._accept_status = accept_status
        self._sleep_time = sleep_time
        self._queue_timeout = queue_timeout
        self._max_queue_size = max_queue_size or config.edge_buffer_size
        self._num_server_threads = num_server_threads or os.cpu_count()
        self._max_payload_size_bytes = max_payload_size * 1024 * 1024
        self._request_timeout_secs = request_timeout_secs
        self._lines = lines
        self._stop_after = stop_after

        # These are only used when C++ mode is disabled
        self._queue: FiberQueue = None
        self._processing = False
        self._messages_processed = 0
        self._input_schema = input_schema
        self._http_server = None

        if method not in SUPPORTED_METHODS:
            raise ValueError(f"Unsupported method: {method}")

        if accept_status.value < 200 or accept_status.value > 299:
            raise ValueError(f"Invalid accept_status: {accept_status}")

    @property
    def name(self) -> str:
        """Unique name of the stage."""
        return "from-cve-http"

    def supports_cpp_node(self) -> bool:
        """Disabling the C++ impl allows for the `source_code_repos` keys to be preserved"""
        return False

    def compute_schema(self, schema: StageSchema):
        schema.output_schema.set_type(self._input_schema)

    def stop(self):
        """
        Performs cleanup steps when pipeline is stopped.
        """
        logger.debug("Stopping %s", self.name)
        self._processing = False
        # Indicate we need to stop
        if self._http_server is not None:
            self._http_server.stop()

        return super().stop()

    def _parse_payload(self, payload: str) -> HttpParseResponse:
        try:
            payload_dict = json5.loads(payload)

            message = self._input_schema.model_validate(payload_dict)

        except Exception as e:
            err_msg = f"Error occurred converting HTTP payload to {self._input_schema}: {e}"
            logger.error("%s", err_msg, exc_info=True)
            return HttpParseResponse(status_code=HTTPStatus.BAD_REQUEST.value,
                                     content_type=MimeTypes.TEXT.value,
                                     body=err_msg)

        try:
            self._queue.put(message, block=True, timeout=self._queue_timeout)
            return HttpParseResponse(status_code=self._accept_status.value, content_type=MimeTypes.TEXT.value, body="")

        except (queue.Full, Closed) as e:
            err_msg = "HTTP payload queue is "
            if isinstance(e, queue.Full):
                err_msg += "full"
            else:
                err_msg += "closed"
            logger.error(err_msg)
            return HttpParseResponse(status_code=HTTPStatus.SERVICE_UNAVAILABLE.value,
                                     content_type=MimeTypes.TEXT.value,
                                     body=err_msg)

        except Exception as e:
            err_msg = "Error occurred while pushing payload to queue"
            logger.error("%s: %s", err_msg, e)
            return HttpParseResponse(status_code=HTTPStatus.INTERNAL_SERVER_ERROR.value,
                                     content_type=MimeTypes.TEXT.value,
                                     body=err_msg)

    def _generate_frames(self, subscription: mrc.Subscription) -> typing.Iterator[BaseModel]:
        from morpheus.common import FiberQueue
        from morpheus.common import HttpServer

        endpoints = [HttpEndpoint(py_parse_fn=self._parse_payload, url=self._endpoint, method=self._method.value)]
        with (FiberQueue(self._max_queue_size) as self._queue,
              HttpServer(bind_address=self._bind_address,
                         port=self._port,
                         endpoints=endpoints,
                         num_threads=self._num_server_threads,
                         max_payload_size=self._max_payload_size_bytes,
                         request_timeout=self._request_timeout_secs) as self._http_server):

            self._processing = True
            while self._processing:
                # Read as many messages as we can from the queue if it's empty check to see if we should be shutting
                # down. It is important that any messages we received that are in the queue are processed before we
                # shutdown since we already returned an OK response to the client.
                message: self._input_schema | None = None
                try:
                    # Intentionally not using self._queue_timeout here since that value is rather high
                    message = self._queue.get(block=False, timeout=0.1)
                except queue.Empty:
                    if (not self._http_server.is_running() or self.is_stop_requested()
                            or not subscription.is_subscribed()):
                        self._processing = False
                    else:
                        time.sleep(self._sleep_time)
                except Closed:
                    logger.error("Queue closed unexpectedly, shutting down")
                    self._processing = False

                if message is not None:
                    yield message
                    self._messages_processed += 1

                    if self._stop_after > 0 and self._messages_processed >= self._stop_after:
                        logger.info("Processed %d messages; stop processing", self._messages_processed)
                        self._processing = False

    def _build_source(self, builder: mrc.Builder) -> mrc.SegmentObject:

        node = builder.make_source(self.unique_name, self._generate_frames)

        return node
