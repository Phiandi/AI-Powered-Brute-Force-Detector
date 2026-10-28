
from ai_investigation import is_successful_analysis


def test_valid_analysis_is_successful():
    result = "Repeated failed login attempts were detected."

    assert is_successful_analysis(result) is True


def test_unavailable_analysis_is_not_successful():
    result = "AI analysis unavailable: missing API key."

    assert is_successful_analysis(result) is False


def test_temporary_service_error_is_not_successful():
    result = "AI service temporarily unavailable: try again."

    assert is_successful_analysis(result) is False


def test_failed_analysis_is_not_successful():
    result = "AI analysis failed: request error."

    assert is_successful_analysis(result) is False


def test_empty_result_is_not_successful():
    assert is_successful_analysis("") is False


def test_non_string_result_is_not_successful():
    assert is_successful_analysis(None) is False
