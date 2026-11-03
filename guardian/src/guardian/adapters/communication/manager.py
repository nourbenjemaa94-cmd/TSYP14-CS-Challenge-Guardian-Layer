import logging
from collections.abc import Mapping
from typing import Any

from fastapi import FastAPI

from .base import CommunicationAdapter, MessageHandler
from .registry import AdapterRegistry

logger = logging.getLogger(__name__)


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