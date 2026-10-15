import re
from collections.abc import Iterable

from thefuzz import fuzz

AUTO_APPROVE_THRESHOLD = 95
REVIEW_THRESHOLD = 45


def classify_name_match(
    ocr_text: str, authorized_names: Iterable[str]
) -> tuple[str, str, int | None]:
    ocr_tokens = re.findall(r"[a-z0-9]+", ocr_text.casefold())
    if not ocr_tokens:
        return "DENIED", "UNKNOWN_VISITOR", None

    scores: list[tuple[int, str, int]] = []
    for name in authorized_names:
        name_tokens = re.findall(r"[a-z0-9]+", name.casefold())
        if not name_tokens:
            continue
        token_scores = [
            max(fuzz.ratio(name_token, ocr_token) for ocr_token in ocr_tokens)
            for name_token in name_tokens
        ]
        scores.append((round(sum(token_scores) / len(token_scores)), name, min(token_scores)))

    if not scores:
        return "DENIED", "UNKNOWN_VISITOR", None

    scores.sort(reverse=True)
    best_score, best_name, weakest_token_score = scores[0]
    second_score = scores[1][0] if len(scores) > 1 else 0

    if (
        best_score >= AUTO_APPROVE_THRESHOLD
        and weakest_token_score >= AUTO_APPROVE_THRESHOLD
        and best_score - second_score >= 5
    ):
        return "APPROVED", best_name, best_score
    if best_score >= REVIEW_THRESHOLD:
        return "PENDING_REVIEW", best_name, best_score
    return "DENIED", "UNKNOWN_VISITOR", best_score
