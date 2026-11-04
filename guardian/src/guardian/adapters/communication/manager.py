import asyncio
import logging
import threading
from collections.abc import Mapping
from concurrent.futures import TimeoutError as FutureTimeoutError
from typing import Any

from fastapi import FastAPI

from guardian.adapters.contract.errors import MappingError
from guardian.security.errors import SecurityRejection

from .base import CommunicationAdapter, HandlerResult, IncomingMessage, MessageHandler
from .registry import AdapterRegistry

logger = logging.getLogger(__name__)


class AsyncPipelineHandler:
    """Synchronous adapter callback backed by bounded async workers.

    MQTT callbacks never wait for the pipeline: they enqueue with ``put_nowait``
    and return. REST callbacks wait for one worker result so HTTP rejection
    codes remain truthful, but the async pipeline itself runs on the event loop.
    """

    def __init__(self, pipeline: Any, logger: Any, *, max_queue_size: int = 128, workers: int = 2):
        if max_queue_size <= 0 or workers <= 0:
            raise ValueError("max_queue_size and workers must be positive")
        self.pipeline = pipeline
        self.logger = logger
        self.max_queue_size = max_queue_size
        self.worker_count = workers
        self._loop: asyncio.AbstractEventLoop | None = None
        self._queue: asyncio.Queue[tuple[IncomingMessage, asyncio.Future[HandlerResult]]] | None = None
        self._tasks: list[asyncio.Task[None]] = []
        self._ready = False
        self._capacity = threading.BoundedSemaphore(max_queue_size)

    @property
    def ready(self) -> bool:
        return self._ready

    async def start(self) -> None:
        if self._ready:
            return
        self._loop = asyncio.get_running_loop()
        self._queue = asyncio.Queue(maxsize=self.max_queue_size)
        self._tasks = [
            asyncio.create_task(self._worker(), name=f"guardian-pipeline-{i}")
            for i in range(self.worker_count)
        ]
        self._ready = True

    async def stop(self) -> None:
        if not self._ready or self._queue is None:
            return
        self._ready = False
        for _ in self._tasks:
            await self._queue.put((None, None))  # type: ignore[arg-type]
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        self._queue = None
        self._loop = None

    def __call__(self, message: IncomingMessage) -> HandlerResult:
        if not self._ready or self._loop is None or self._queue is None:
            return HandlerResult(False, "PIPELINE_NOT_CONFIGURED", "Guardian pipeline is not ready.", http_status=503)
        if not self._capacity.acquire(blocking=False):
            return HandlerResult(False, "QUEUE_FULL", "Guardian processing queue is full.", http_status=503)

        if message.transport == "mqtt":
            try:
                self._loop.call_soon_threadsafe(self._enqueue_mqtt, message)
            except RuntimeError:
                self._capacity.release()
                return HandlerResult(
                    False,
                    "PIPELINE_NOT_CONFIGURED",
                    "Guardian pipeline is not ready.",
                    http_status=503,
                )
            # Paho acknowledges after this callback returns. The bounded
            # reservation above is the only synchronous admission operation.
            return HandlerResult(True, "QUEUED", "Message queued for processing.")

        try:
            completion = asyncio.run_coroutine_threadsafe(self._enqueue(message), self._loop).result(timeout=1.0)
        except (asyncio.QueueFull, FutureTimeoutError):
            self._capacity.release()
            return HandlerResult(False, "QUEUE_FULL", "Guardian processing queue is full.", http_status=503)

        try:
            return asyncio.run_coroutine_threadsafe(self._await_completion(completion), self._loop).result(timeout=30.0)
        except FutureTimeoutError:
            return HandlerResult(False, "PROCESSING_TIMEOUT", "Guardian processing timed out.", http_status=504)

    async def _enqueue(self, message: IncomingMessage) -> asyncio.Future[HandlerResult]:
        assert self._queue is not None
        completion: asyncio.Future[HandlerResult] = asyncio.get_running_loop().create_future()
        try:
            self._queue.put_nowait((message, completion))
        except asyncio.QueueFull:
            self._capacity.release()
            raise
        return completion

    def _enqueue_mqtt(self, message: IncomingMessage) -> None:
        """Enqueue from the event-loop thread without waiting in Paho."""
        if not self._ready or self._queue is None:
            self._capacity.release()
            return
        completion = self._loop.create_future() if self._loop is not None else None
        try:
            self._queue.put_nowait((message, completion))
        except asyncio.QueueFull:
            # This should only be possible during shutdown/races; admission
            # remains fail-closed and the delivery is not claimed processed.
            self._capacity.release()
            logger.warning("MQTT processing queue became full after admission")

    @staticmethod
    async def _await_completion(completion: asyncio.Future[HandlerResult]) -> HandlerResult:
        return await completion

    async def _worker(self) -> None:
        assert self._queue is not None
        while True:
            message, completion = await self._queue.get()
            if message is None:
                return
            self._capacity.release()
            try:
                from guardian.orchestration.pipeline import TransportContext

                result = await self.pipeline.process_incoming(
                    message.payload,
                    self.logger,
                    transport_context=TransportContext(
                        transport=message.transport,
                        source=message.source,
                        metadata=dict(message.metadata),
                        received_at=message.received_at,
                    ),
                )
                outcome = HandlerResult(True, "ACCEPTED", "Message processed.", response=result)
            except SecurityRejection as exc:
                outcome = HandlerResult(
                    False,
                    exc.code.value,
                    exc.public_message,
                    response=exc.to_public_dict(),
                    http_status=exc.http_status,
                )
            except MappingError as exc:
                outcome = HandlerResult(
                    False,
                    exc.code.value,
                    exc.detail,
                    response=exc.to_public_dict(),
                    http_status=exc.http_status,
                )
            except Exception as exc:
                logger.exception("Pipeline worker failed")
                outcome = HandlerResult(False, "PIPELINE_ERROR", type(exc).__name__, http_status=500)
            if (
                outcome.accepted
                and isinstance(outcome.response, dict)
                and outcome.response.get("status") == "UNSUPPORTED_CORE_EVENT_KIND"
            ):
                outcome = HandlerResult(
                    False,
                    "UNSUPPORTED_CORE_EVENT_KIND",
                    str(outcome.response.get("detail", "")),
                    response=outcome.response,
                    http_status=422,
                )
            if not completion.done():
                completion.set_result(outcome)


def _build_rest(
    handler: MessageHandler,
    **options: Any
) -> CommunicationAdapter:
    from .rest import RestAdapter
    return RestAdapter(handler, **options)


def _build_mqtt(
    handler: MessageHandler,
    **options: Any
) -> CommunicationAdapter:
    from .mqtt import MqttAdapter
    return MqttAdapter(handler, **options)


class AdapterManager:

    def __init__(
        self,
        handler: MessageHandler,
        *,
        registry: AdapterRegistry | None = None
    ):
        self.handler = handler

        self.registry = (
            registry if registry is not None
            else AdapterRegistry()
        )

        if registry is None:
            self.registry.register("rest", _build_rest)
            self.registry.register("mqtt", _build_mqtt)

        self.adapters: dict[str, CommunicationAdapter] = {}
        self._running = False
        self._configured = False

    @property
    def running(self) -> bool:
        """Whether all configured communication adapters started successfully."""
        return self._running

    def configure(
        self,
        config: Mapping[str, Mapping[str, Any]],
        *,
        app: FastAPI | None = None
    ):
        if self._configured or self._running:
            raise RuntimeError("Manager already configured")

        created = {}
        routers = []

        for name, raw_options in config.items():
            options = dict(raw_options)
            enabled = options.pop("enabled", True)

            if not isinstance(enabled, bool):
                raise ValueError(
                    f"enabled must be boolean for {name}"
                )

            if not enabled:
                continue

            adapter = self.registry.create(
                name, self.handler, options
            )

            router = getattr(adapter, "router", None)

            if router is not None:
                if app is None:
                    raise ValueError(
                        f"FastAPI app required for {name}"
                    )
                routers.append(router)

            created[name] = adapter

        if app is not None:
            for router in routers:
                # Lifespan may configure a fresh handler for a new event loop
                # (notably in tests). Remove the manager-owned route first so
                # an old stopped handler cannot shadow the current one.
                paths = {getattr(route, "path", None) for route in router.routes}
                app.router.routes = [
                    route for route in app.router.routes
                    if getattr(route, "path", None) not in paths
                    and type(route).__name__ != "_IncludedRouter"
                ]
                app.include_router(router)

        self.adapters = created
        self._configured = True

    def start(self):
        if not self._configured:
            raise RuntimeError(
                "Call configure() before start()"
            )

        if self._running:
            return

        started = []

        try:
            for adapter in self.adapters.values():
                adapter.start()
                started.append(adapter)

        except Exception:
            for adapter in reversed(started):
                try:
                    adapter.stop()
                except Exception:
                    logger.exception(
                        "Failed to roll back adapter startup"
                    )
            raise

        self._running = True

    def stop(self):
        if not self._running:
            return

        first_error = None

        for adapter in reversed(list(self.adapters.values())):
            try:
                adapter.stop()
            except Exception as exc:
                logger.exception("Failed to stop adapter")
                if first_error is None:
                    first_error = exc

        self._running = False

        if first_error is not None:
            raise RuntimeError(
                "At least one adapter failed to stop"
            ) from first_error
