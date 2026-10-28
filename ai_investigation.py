
def is_successful_analysis(ai_result):
    """Return True only when the result is not an AI error message."""
    if not isinstance(ai_result, str) or not ai_result.strip():
        return False

    unavailable_prefixes = (
        "AI analysis unavailable:",
        "AI service temporarily unavailable:",
        "AI analysis failed:",
    )

    return not ai_result.startswith(unavailable_prefixes)
