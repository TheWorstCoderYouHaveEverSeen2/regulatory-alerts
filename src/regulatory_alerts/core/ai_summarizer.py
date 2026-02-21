"""AI-powered document summarization using Claude Haiku 4.5.

Generates structured summaries with:
- 2-3 sentence actionable summary
- Key points (bullet list)
- Topic classification
- Document type classification
- Relevance scoring (rule-based)
"""

import json
import logging
from datetime import datetime, timezone
from decimal import Decimal

import anthropic
from sqlalchemy.orm import Session

from regulatory_alerts.config import get_settings
from regulatory_alerts.models.alert import ProcessedAlert
from regulatory_alerts.models.document import FeedDocument

logger = logging.getLogger(__name__)

TOPIC_TAXONOMY = [
    "enforcement",
    "crypto",
    "securities",
    "derivatives",
    "aml_bsa",
    "disclosure",
    "market_structure",
    "investment_advisers",
    "broker_dealers",
    "insider_trading",
    "fraud",
    "registration",
    "reporting",
    "fintech",
]

DOCUMENT_TYPES = [
    "enforcement_action",
    "proposed_rule",
    "final_rule",
    "guidance",
    "no_action_letter",
    "press_release",
    "litigation_release",
    "order",
]

SYSTEM_PROMPT = """You are a regulatory intelligence analyst. You analyze government regulatory documents and produce structured summaries for financial services compliance professionals.

Always respond with valid JSON only. No markdown, no explanation outside the JSON."""

USER_PROMPT_TEMPLATE = """Analyze this regulatory document and provide a structured summary.

Document Title: {title}
Agency: {agency}
Source URL: {url}
Published: {published_at}
Feed Summary: {raw_summary}

Respond with this JSON structure:
{{
  "summary": "2-3 sentence plain-English summary. Focus on: WHO is affected, WHAT action is required or what happened, and WHY it matters. Be specific and actionable.",
  "document_type": "one of: {document_types}",
  "key_points": ["point 1", "point 2", "point 3"],
  "topics": ["select relevant tags from: {topics}"]
}}"""


def _calculate_relevance_score(document_type: str, topics: list[str], title: str) -> float:
    """Rule-based relevance scoring (0.0 - 1.0).

    Higher scores for enforcement actions, final rules, and high-interest topics.
    """
    score = 0.5

    # Document type weight
    if document_type in ("enforcement_action", "final_rule"):
        score += 0.3
    elif document_type in ("proposed_rule", "guidance"):
        score += 0.2
    elif document_type in ("litigation_release", "order"):
        score += 0.25

    # High-priority topic boost
    high_priority = {"crypto", "enforcement", "fraud", "insider_trading", "aml_bsa"}
    if any(t in high_priority for t in topics):
        score += 0.15

    # Urgency keywords in title
    title_lower = title.lower()
    if any(kw in title_lower for kw in ("emergency", "immediate", "halt", "suspend", "freeze")):
        score += 0.1

    return min(round(score, 2), 1.0)


def _calculate_cost(input_tokens: int, output_tokens: int) -> Decimal:
    """Calculate API cost for Claude Haiku 4.5.

    Pricing: $1.00 / 1M input tokens, $5.00 / 1M output tokens
    """
    input_cost = Decimal(str(input_tokens)) * Decimal("0.000001")
    output_cost = Decimal(str(output_tokens)) * Decimal("0.000005")
    return input_cost + output_cost


def summarize_document(
    session: Session,
    doc: FeedDocument,
) -> ProcessedAlert | None:
    """Generate an AI summary for a feed document.

    Args:
        session: SQLAlchemy sync session
        doc: FeedDocument to summarize

    Returns:
        ProcessedAlert if successful, None on failure
    """
    settings = get_settings()

    if not settings.ANTHROPIC_API_KEY:
        logger.error("ANTHROPIC_API_KEY not set — cannot summarize")
        return None

    prompt = USER_PROMPT_TEMPLATE.format(
        title=doc.title,
        agency=doc.agency,
        url=doc.url,
        published_at=doc.published_at.strftime("%Y-%m-%d %H:%M UTC") if doc.published_at else "Unknown",
        raw_summary=doc.raw_summary or "(No summary available from feed)",
        document_types=", ".join(DOCUMENT_TYPES),
        topics=", ".join(TOPIC_TAXONOMY),
    )

    try:
        client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
        response = client.messages.create(
            model=settings.CLAUDE_MODEL,
            max_tokens=settings.CLAUDE_MAX_TOKENS,
            temperature=0.3,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception as e:
        logger.error("Claude API error for doc %d: %s", doc.id, e)
        doc.processing_status = "failed"
        return None

    # Parse response — guard against empty content list
    if not response.content:
        logger.error("Claude returned empty content for doc %d", doc.id)
        doc.processing_status = "failed"
        return None

    raw_text = response.content[0].text.strip()

    # Strip markdown code fences if the model wraps JSON
    if raw_text.startswith("```"):
        lines = raw_text.split("\n")
        raw_text = "\n".join(lines[1:-1]) if lines[-1].strip() == "```" else "\n".join(lines[1:])

    try:
        result = json.loads(raw_text)
    except json.JSONDecodeError:
        logger.error("Failed to parse AI response as JSON for doc %d: %s", doc.id, raw_text[:200])
        doc.processing_status = "failed"
        return None

    summary = result.get("summary", "")
    document_type = result.get("document_type", "press_release")
    key_points = result.get("key_points", [])
    topics = result.get("topics", [])

    # Validate document_type
    if document_type not in DOCUMENT_TYPES:
        document_type = "press_release"

    # Validate topics
    topics = [t for t in topics if t in TOPIC_TAXONOMY]

    relevance_score = _calculate_relevance_score(document_type, topics, doc.title)
    cost = _calculate_cost(response.usage.input_tokens, response.usage.output_tokens)

    alert = ProcessedAlert(
        feed_document_id=doc.id,
        summary=summary,
        key_points=key_points,
        topics=json.dumps(topics) if topics else None,
        relevance_score=relevance_score,
        document_type=document_type,
        ai_model=settings.CLAUDE_MODEL,
        ai_cost_usd=cost,
    )
    session.add(alert)

    # Update document status
    doc.processing_status = "completed"
    doc.document_type = document_type
    doc.processed_at = datetime.now(timezone.utc)

    logger.info(
        "Summarized doc %d: type=%s, score=%.2f, cost=$%.6f",
        doc.id,
        document_type,
        relevance_score,
        cost,
    )

    return alert
