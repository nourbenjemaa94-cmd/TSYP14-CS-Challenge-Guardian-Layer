from collections.abc import Callable
from typing import Any

from .base import CommunicationAdapter, MessageHandler

AdapterFactory = Callable[..., CommunicationAdapter]


class AdapterRegistry:

    def __init__(self):
        self._factories: dict[str, AdapterFactory] = {}

    def register(
        self,
        name: str,
        factory: AdapterFactory
    ) -> None:
        key = name.strip().lower()

        if not key or not callable(factory):
            raise ValueError("Invalid adapter registration")

        if key in self._factories:
            raise ValueError(
                f"Adapter already registered: {key}"
            )

        self._factories[key] = factory

    def create(
        self,
        name: str,
        handler: MessageHandler,
        options: dict[str, Any]
    ) -> CommunicationAdapter:
        key = name.strip().lower()

        try:
            factory = self._factories[key]
        except KeyError as exc:
            raise ValueError(
                f"Unsupported protocol: {key}"
            ) from exc

        return factory(handler, **options)

    def available(self) -> tuple[str, ...]:
        return tuple(sorted(self._factories))