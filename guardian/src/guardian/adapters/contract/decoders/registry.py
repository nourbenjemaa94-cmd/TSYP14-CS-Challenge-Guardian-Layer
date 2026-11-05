from __future__ import annotations

from guardian.adapters.contract.decoders.base import FormatDecoder
from guardian.adapters.contract.decoders.json_decoder import JsonDecoder

_REGISTERED: dict[str, FormatDecoder] = {"json": JsonDecoder()}


def decoder_for(format_id: str) -> FormatDecoder:
    """Return the decoder for ``format_id``. Only ``json`` is registered."""
    decoder = _REGISTERED.get(format_id)
    if decoder is None:
        raise KeyError(format_id)
    return decoder
