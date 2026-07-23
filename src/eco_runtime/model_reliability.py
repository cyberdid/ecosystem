from __future__ import annotations

"""Reusable checks distilled from local live dogfooding.

Two lessons cost real debugging time and belong in code, not only a note:

1. **Truncation is not a model verdict.** An empty or partial body with
   ``finish_reason == "length"`` means the token budget ran out — often on a
   reasoning model whose hidden thinking consumed it — and the right response is
   to retry with more budget, never to record "the model cannot do this".
2. **Some models ignore strict grammar.** A deployment that does not honor the
   strict ``json_schema`` response format (it returns prose instead) must be
   driven with prompt-stated JSON plus extraction. Its transport is chosen from
   its observed admission behaviour, not assumed.
"""

from dataclasses import dataclass
from typing import Any, Literal


@dataclass(frozen=True)
class CompletionOutcome:
    kind: Literal["complete", "truncated", "empty"]
    should_retry_with_more_tokens: bool

    def as_record(self) -> dict[str, Any]:
        return {"kind": self.kind, "shouldRetryWithMoreTokens": self.should_retry_with_more_tokens}


def classify_completion(content: Any, finish_reason: Any) -> CompletionOutcome:
    """Classify a raw completion so truncation is never mistaken for failure.

    - ``finish_reason == "length"`` → ``truncated`` (retry with more tokens),
      whether the body is empty or partial.
    - a clean stop with no content → ``empty`` (a genuine non-answer, no retry).
    - a clean stop with content → ``complete``.
    """

    if finish_reason == "length":
        return CompletionOutcome("truncated", True)
    if not isinstance(content, str) or not content.strip():
        return CompletionOutcome("empty", False)
    return CompletionOutcome("complete", False)


TransportMethod = Literal["strict-json-schema", "prompt-json-extract"]


def recommend_transport(*, honors_strict_grammar: bool) -> TransportMethod:
    """Pick a structured-output transport from a model's observed behaviour.

    A model that honors the strict ``json_schema`` grammar may use it directly; a
    model that ignores it (emitting prose) must use prompt-stated JSON plus
    liberal extraction. This is the routing an admission verdict informs.
    """

    return "strict-json-schema" if honors_strict_grammar else "prompt-json-extract"
