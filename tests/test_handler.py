"""Investigator flow: one work-queue job, recall, investigate, store once, notify."""

from __future__ import annotations

import json
import logging
import time
import urllib.error
from typing import Any
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError
from pytest_mock import MockerFixture

from devops_agent import handler as handler_module
from devops_agent.config import Settings
from devops_agent.findings import store_finding
from devops_agent.handler import handler
from devops_agent.models import FindingKind, InvestigationJob, Severity
from tests.conftest import (
    ALARM_NAME,
    FUNCTION_KEY,
    GITHUB_APP_ID,
    GITHUB_INSTALLATION_ID,
    GITHUB_ORG,
    FakeInvestigator,
    client_error,
    converse_response,
    github_private_pem,
    has_float,
    job,
    patch_investigator,
    report,
    sqs_record,
    tool_use,
)


@pytest.fixture()
def aws(mocker: MockerFixture) -> FakeInvestigator:
    return patch_investigator(mocker)


def _event(*jobs: InvestigationJob) -> dict[str, Any]:
    return {
        "Records": [
            sqs_record(item.model_dump(mode="json", by_alias=True), message_id=f"msg-{n}")
            for n, item in enumerate(jobs, start=1)
        ]
    }


def _prompt(aws: FakeInvestigator) -> str:
    text: str = aws.bedrock.calls[0]["messages"][0]["content"][0]["text"]
    return text


@pytest.mark.parametrize("body", ["not json", json.dumps({"finding_id": "f-1"}), ""])
def test_record_that_is_not_a_job_is_dropped(aws: FakeInvestigator, body: str) -> None:
    result = handler({"Records": [sqs_record(body)]}, None)
    assert result == {"batchItemFailures": []}
    assert aws.table.puts == []
    assert aws.bedrock.calls == []


def test_high_finding_is_stored_redacted_and_published(aws: FakeInvestigator) -> None:
    aws.bedrock.script.append(
        converse_response(
            report(
                "medium", summary="Key AKIA" + "ABCDEFGHIJKLMNOP appeared in logs with password=x"
            )
        )
    )
    work = job(finding_id="f-1")
    assert handler(_event(work), None) == {"batchItemFailures": []}

    [item] = aws.table.findings()
    assert item["pk"] == "finding#f-1"
    assert item["kind"] == "alarm"
    assert item["resource_key"] == FUNCTION_KEY
    assert item["severity"] == "high"
    assert item["severity_floor"] == "high"
    assert item["proposed_severity"] == "medium"
    assert item["alarm_name"] == ALARM_NAME
    assert "AKIA" not in item["summary"]
    assert "password=[redacted]" in item["summary"]
    assert not has_float(item)

    [(operation, call)] = aws.sns.calls
    assert operation == "publish"
    assert "AKIA" not in call["Message"]
    assert json.loads(call["Message"])["severity"] == "error"


def test_slack_off_stores_a_high_finding_without_publishing(
    aws: FakeInvestigator, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SLACK_ENABLED", "false")
    handler_module.get_settings.cache_clear()
    aws.bedrock.script.append(converse_response(report("high")))
    assert handler(_event(job(finding_id="f-off")), None) == {"batchItemFailures": []}

    [item] = aws.table.findings()
    assert item["severity"] == "high"
    assert aws.sns.calls == []


def test_medium_finding_is_stored_but_not_published(
    aws: FakeInvestigator, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "staging")
    monkeypatch.setenv("SLACK_TOPIC_ARN", "arn:aws:sns:us-east-1:111122223333:ops-alerts-staging")
    handler_module.get_settings.cache_clear()
    aws.bedrock.script.append(converse_response(report("low")))
    handler(_event(job(floor=Severity.MEDIUM)), None)
    [item] = aws.table.findings()
    assert item["severity"] == "medium"
    assert aws.sns.calls == []


def test_floor_comes_from_the_job(aws: FakeInvestigator) -> None:
    aws.bedrock.script.append(converse_response(report("low")))
    handler(_event(job(floor=Severity.CRITICAL)), None)
    [item] = aws.table.findings()
    assert item["severity"] == "critical"
    assert "list_tags_for_resource" not in aws.cloudwatch.operations()


def _prior(aws: FakeInvestigator, n: int, title: str, **fields: Any) -> None:
    aws.table.items[f"finding#f-{n}"] = {
        "pk": f"finding#f-{n}",
        "finding_id": f"f-{n}",
        "created_at": f"2026-09-2{n}T00:00:00+00:00",
        "resource_key": FUNCTION_KEY,
        "title": title,
        "likely_cause": f"cause of {title}",
        "severity": "high",
        "fix_effort": "low",
        **fields,
    }


def test_only_reviewed_prior_findings_reach_the_prompt(aws: FakeInvestigator) -> None:
    work = job(finding_id="f-new")
    _prior(aws, 0, "Confirmed cold start", status="closed", resolution="confirmed")
    _prior(aws, 1, "Load test noise", status="closed", resolution="false_positive")
    _prior(aws, 2, "Wrong guess", status="closed", resolution="wrong")
    _prior(aws, 3, "Open timeout", status="open")
    _prior(aws, 5, "Incomplete run", status="closed", resolution="confirmed", outcome="incomplete")
    _prior(aws, 4, "Linked here", status="closed", resolution="confirmed", linked_to="f-new")
    aws.bedrock.script.append(converse_response(report("high")))
    handler(_event(work), None)

    prompt = _prompt(aws)
    assert "confirmed past cause, severity high: Confirmed cold start" in prompt
    assert "cause of Confirmed cold start" in prompt
    assert "past false alarm, severity high: Load test noise" in prompt
    assert "Wrong guess" not in prompt
    assert "Open timeout" not in prompt
    assert "Linked here" not in prompt
    assert "Incomplete run" not in prompt
    [query] = aws.table.queries
    assert query["IndexName"] == "by_resource"
    assert query["ExpressionAttributeValues"] == {":key": FUNCTION_KEY}
    assert query["ScanIndexForward"] is False
    assert query["Limit"] == handler_module.RECALL_PAGE
    assert aws.table.items["finding#f-new"]["previous_finding_id"] == "f-5"
    assert aws.table.items["finding#f-new"]["prior_finding_ids"] == ["f-1", "f-0"]


def test_reviewed_prior_findings_are_capped(aws: FakeInvestigator) -> None:
    for n in range(5):
        _prior(aws, n, f"Confirmed {n}", status="closed", resolution="confirmed")
    aws.bedrock.script.append(converse_response(report("high")))
    handler(_event(job()), None)
    prompt = _prompt(aws)
    assert [f"Confirmed {n}" in prompt for n in range(5)] == [False, False, True, True, True]


def test_context_bundle_is_in_the_prompt_and_summarized_on_the_finding(
    aws: FakeInvestigator,
) -> None:
    aws.bedrock.script.append(converse_response(report("high")))
    handler(_event(job(finding_id="f-1")), None)

    prompt = _prompt(aws)
    assert prompt.index("Alarm name:") < prompt.index("<context>\n## alarm\n")
    summary = aws.table.items["finding#f-1"]["context_summary"]
    assert summary["sections"] == {
        "alarm": "unavailable",
        "metric": "unavailable",
        "log_sources": "unavailable",
        "log_patterns": "not_applicable",
        "changes": "available",
        "siblings": "available",
        "database_events": "not_applicable",
        "instance": "not_applicable",
        "service_notes": "not_applicable",
        "sources_last_time": "available",
    }
    assert summary["counts"] == {"changes": 0, "siblings": 0, "sources_last_time": 0}
    assert summary["truncated"] is False
    assert "## " not in json.dumps(summary)


def _query_logs_turn() -> dict[str, Any]:
    return converse_response(
        tool_use("query_logs", {"log_group": "/aws/lambda/a", "query": "fields @message"}, "q"),
        tool_use("recent_changes", {}, "e"),
    )


def _logs_with_rows(aws: FakeInvestigator) -> None:
    aws.logs.responses["start_query"] = {"queryId": "q"}
    aws.logs.responses["get_query_results"] = {
        "status": "Complete",
        "results": [[{"field": "@message", "value": "boom"}]],
    }


def test_useful_sources_are_remembered_after_a_reported_investigation(
    aws: FakeInvestigator,
) -> None:
    _logs_with_rows(aws)
    aws.bedrock.script.extend([_query_logs_turn(), converse_response(report("high"))])
    handler(_event(job()), None)

    item = aws.table.items[f"obs#{FUNCTION_KEY}"]
    [entry] = item["entries"]
    assert entry["tool"] == "query_logs"
    assert entry["input"] == {"log_group": "/aws/lambda/a", "query": "fields @message"}
    assert entry["at"]
    assert "resource_key" not in item
    assert item["ttl"] > time.time() + 89 * 86400


def test_useful_sources_are_not_remembered_when_incomplete(aws: FakeInvestigator) -> None:
    _logs_with_rows(aws)
    aws.bedrock.script.extend([_query_logs_turn(), client_error("ValidationException")])
    handler(_event(job()), None)
    assert f"obs#{FUNCTION_KEY}" not in aws.table.items


def test_useful_sources_are_capped_newest_first(aws: FakeInvestigator) -> None:
    stored = [
        {"tool": "get_metric", "input": {"metric_name": f"m{n}"}, "at": "2026-09-01"}
        for n in range(10)
    ]
    aws.table.items[f"obs#{FUNCTION_KEY}"] = {"pk": f"obs#{FUNCTION_KEY}", "entries": stored}
    _logs_with_rows(aws)
    aws.bedrock.script.extend([_query_logs_turn(), converse_response(report("high"))])
    handler(_event(job()), None)

    entries = aws.table.items[f"obs#{FUNCTION_KEY}"]["entries"]
    assert len(entries) == 10
    assert entries[0]["tool"] == "query_logs"
    assert entries[1:] == stored[:9]


def test_stored_sources_of_tools_that_do_not_exist_are_dropped(aws: FakeInvestigator) -> None:
    kept = {"tool": "get_metric", "input": {"metric_name": "m"}, "at": "2026-09-01"}
    gone = {"tool": "describe_widget", "input": {"name": "w"}, "at": "2026-09-01"}
    aws.table.items[f"obs#{FUNCTION_KEY}"] = {
        "pk": f"obs#{FUNCTION_KEY}",
        "entries": [gone, kept, {"input": {}}],
    }
    _logs_with_rows(aws)
    aws.bedrock.script.extend([_query_logs_turn(), converse_response(report("high"))])
    handler(_event(job()), None)

    entries = aws.table.items[f"obs#{FUNCTION_KEY}"]["entries"]
    assert [entry["tool"] for entry in entries] == ["query_logs", "get_metric"]
    assert entries[1] == kept


def test_remembered_sources_reach_the_next_bundle(aws: FakeInvestigator) -> None:
    aws.table.items[f"obs#{FUNCTION_KEY}"] = {
        "pk": f"obs#{FUNCTION_KEY}",
        "entries": [
            {"tool": "query_logs", "input": {"log_group": "/aws/lambda/kept"}, "at": "2026-09-01"}
        ],
    }
    aws.bedrock.script.append(converse_response(report("high")))
    handler(_event(job(finding_id="f-1")), None)

    prompt = _prompt(aws)
    sources_at = prompt.index("## sources_last_time\n")
    assert "/aws/lambda/kept" in prompt[sources_at:]
    assert aws.table.items["finding#f-1"]["context_summary"]["counts"]["sources_last_time"] == 1


def test_failure_to_remember_sources_keeps_the_finding(aws: FakeInvestigator) -> None:
    _logs_with_rows(aws)
    aws.table.errors["update_item"] = client_error("ProvisionedThroughputExceededException")
    aws.bedrock.script.extend([_query_logs_turn(), converse_response(report("high"))])
    assert handler(_event(job(finding_id="f-1")), None) == {"batchItemFailures": []}
    assert aws.table.items["finding#f-1"]["outcome"] == "reported"


def test_incident_prompt_lists_the_alarms_and_slack_names_the_storm(aws: FakeInvestigator) -> None:
    storm = job(
        "orders-errors",
        "payments-errors",
        "search-latency",
        kind=FindingKind.INCIDENT,
        alarm_count=6,
        finding_id="inc-1",
    )
    aws.bedrock.script.append(converse_response(report("high")))
    handler(_event(storm), None)

    prompt = _prompt(aws)
    assert "storm: 6 alarms" in prompt
    for name in ("orders-errors", "payments-errors", "search-latency"):
        assert f"- {name} at " in prompt
    item = aws.table.items["finding#inc-1"]
    assert item["kind"] == "incident"
    assert item["alarm_name"] == "orders-errors"
    assert item["member_alarms"] == ["orders-errors", "payments-errors", "search-latency"]
    assert item["alarm_count"] == 6
    [(_, call)] = aws.sns.calls
    assert call["Subject"] == "[DevOps agent] PROD HIGH: Storm: 6 alarms in 60 s"


def test_linked_alarms_are_read_from_the_jobs_active_items(aws: FakeInvestigator) -> None:
    queue_key = "AWS/SQS:QueueName=orders"
    work = job(keys=(FUNCTION_KEY, queue_key), finding_id="f-1")
    aws.table.items[f"active#{FUNCTION_KEY}"] = {
        "pk": f"active#{FUNCTION_KEY}",
        "finding_id": "f-1",
        "linked_alarms": ["payment-duration", "payment-throttles"],
        "ttl": 0,
    }
    aws.table.items[f"active#{queue_key}"] = {
        "pk": f"active#{queue_key}",
        "finding_id": "someone-else",
        "linked_alarms": ["orders-age"],
        "ttl": 0,
    }
    aws.bedrock.script.append(converse_response(report("high")))
    handler(_event(work), None)
    item = aws.table.items["finding#f-1"]
    assert item["linked_alarms"] == ["payment-duration", "payment-throttles"]


def test_redelivered_job_with_a_stored_finding_is_a_no_op(aws: FakeInvestigator) -> None:
    work = job(finding_id="f-1")
    aws.bedrock.script.append(converse_response(report("high")))
    handler(_event(work), None)
    puts = len(aws.table.puts)

    assert handler(_event(work), None) == {"batchItemFailures": []}
    assert len(aws.bedrock.calls) == 1
    assert len(aws.table.puts) == puts
    assert len(aws.sns.calls) == 1


def test_finding_stored_meanwhile_is_not_published_twice(
    aws: FakeInvestigator, mocker: MockerFixture
) -> None:
    mocker.patch.object(handler_module, "store_finding", return_value=False)
    aws.bedrock.script.append(converse_response(report("high")))
    assert handler(_event(job()), None) == {"batchItemFailures": []}
    assert aws.sns.calls == []


def test_incomplete_investigation_is_recorded(aws: FakeInvestigator) -> None:
    aws.bedrock.script.append(client_error("ValidationException"))
    handler(_event(job(finding_id="f-1")), None)
    item = aws.table.items["finding#f-1"]
    assert item["outcome"] == "incomplete"
    assert item["severity"] == "high"


def test_remaining_time_comes_from_context(aws: FakeInvestigator) -> None:
    context = MagicMock()
    context.get_remaining_time_in_millis.return_value = 5_000
    handler(_event(job()), context)
    [item] = aws.table.findings()
    assert item["outcome"] == "incomplete"
    assert aws.bedrock.calls == []


def test_agent_clients_are_only_the_agents_own(mocker: MockerFixture) -> None:
    boto3 = mocker.patch.object(handler_module, "boto3")
    handler_module.agent_clients.cache_clear()
    clients = handler_module.agent_clients("us-east-1", "table")
    services = [call.args[0] for call in boto3.client.call_args_list]
    assert services == ["bedrock-runtime", "sns", "sts"]
    boto3.resource.return_value.Table.assert_called_once_with("table")
    assert clients.table is boto3.resource.return_value.Table.return_value
    handler_module.agent_clients.cache_clear()


def test_crash_stores_an_incomplete_finding_under_the_job_id(
    aws: FakeInvestigator, mocker: MockerFixture
) -> None:
    attempts: list[str] = []

    def fail_first(table: Any, finding: Any) -> bool:
        attempts.append(finding.outcome)
        if len(attempts) == 1:
            raise RuntimeError("password=hunter2 in the item")
        return store_finding(table, finding)

    mocker.patch.object(handler_module, "store_finding", side_effect=fail_first)
    aws.bedrock.script.append(converse_response(report("high")))
    result = handler(_event(job(finding_id="f-1")), None)

    assert result == {"batchItemFailures": []}
    assert attempts == ["reported", "incomplete"]
    item = aws.table.items["finding#f-1"]
    assert item["outcome"] == "incomplete"
    assert item["severity"] == "high"
    assert item["resource_key"] == FUNCTION_KEY
    assert "RuntimeError" in item["summary"]
    assert "hunter2" not in json.dumps(item)
    assert aws.sns.calls == []


def test_crash_on_store_reports_the_record_for_retry(
    aws: FakeInvestigator, mocker: MockerFixture
) -> None:
    mocker.patch.object(handler_module, "store_finding", side_effect=RuntimeError("boom"))
    aws.bedrock.script.append(converse_response(report("high")))
    result = handler(_event(job()), None)
    assert result == {"batchItemFailures": [{"itemIdentifier": "msg-1"}]}
    assert aws.table.findings() == []


def test_failure_before_investigation_is_recorded(aws: FakeInvestigator) -> None:
    aws.table.errors["query"] = client_error("ProvisionedThroughputExceededException")
    handler(_event(job(finding_id="f-1")), None)
    item = aws.table.items["finding#f-1"]
    assert "ClientError" in item["summary"]
    assert aws.bedrock.calls == []


def test_unreadable_table_reports_the_record_for_retry(aws: FakeInvestigator) -> None:
    aws.table.errors["get_item"] = client_error("InternalServerError")
    result = handler(_event(job()), None)
    assert result == {"batchItemFailures": [{"itemIdentifier": "msg-1"}]}
    assert aws.bedrock.calls == []


def test_topic_is_required_when_notifications_are_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SLACK_TOPIC_ARN")
    with pytest.raises(ValidationError, match="slack_topic_arn is required"):
        Settings()  # type: ignore[call-arg]


def test_topic_is_optional_when_notifications_are_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SLACK_TOPIC_ARN")
    monkeypatch.delenv("SLACK_CHANNEL")
    monkeypatch.delenv("SLACK_ENABLED")
    settings = Settings()  # type: ignore[call-arg]
    assert settings.slack_enabled is False
    assert settings.slack_topic_arn is None


@pytest.mark.parametrize(
    "arn", ["ops-alerts-prod", "arn:aws:sqs:us-east-1:111122223333:ops", "arn:aws:sns:x:1:t"]
)
def test_topic_must_be_an_sns_topic_arn(arn: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SLACK_TOPIC_ARN", arn)
    with pytest.raises(ValidationError, match="slack_topic_arn"):
        Settings()  # type: ignore[call-arg]


def test_bedrock_client_has_one_attempt_and_a_bounded_read(mocker: MockerFixture) -> None:
    boto3 = mocker.patch.object(handler_module, "boto3")
    handler_module.agent_clients.cache_clear()
    handler_module.agent_clients("us-east-1", "table")
    [bedrock_call] = [c for c in boto3.client.call_args_list if c.args[0] == "bedrock-runtime"]
    config = bedrock_call.kwargs["config"]
    assert config.read_timeout == 60
    assert config.retries == {"mode": "standard", "max_attempts": 1}
    handler_module.agent_clients.cache_clear()


def test_botocore_logging_is_quiet() -> None:
    assert logging.getLogger("botocore").level == logging.WARNING


DD_API_KEY = "ddapi0123456789abcdef0123456789ab"
DD_APP_KEY = "ddapp0123456789abcdef0123456789abcdef0123"


def _offered_tools(aws: FakeInvestigator) -> set[str]:
    return {
        tool["toolSpec"]["name"]
        for tool in aws.bedrock.calls[0]["toolConfig"]["tools"]
        if "toolSpec" in tool
    }


def test_datadog_search_runs_with_both_keys_and_never_leaks_them(
    aws: FakeInvestigator,
    monkeypatch: pytest.MonkeyPatch,
    mocker: MockerFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("DD_API_KEY", DD_API_KEY)
    monkeypatch.setenv("DATADOG_APP_KEY", DD_APP_KEY)
    urlopen = mocker.patch(
        "urllib.request.urlopen",
        side_effect=urllib.error.HTTPError(
            "https://api.datadoghq.com/api/v2/logs/events/search",
            403,
            "Forbidden",
            None,  # type: ignore[arg-type]
            None,
        ),
    )
    aws.bedrock.script.extend(
        [
            converse_response(tool_use("search_datadog_logs", {"service": "checkout-api-prod"})),
            converse_response(report()),
        ]
    )
    assert handler(_event(job(finding_id="f-1")), None) == {"batchItemFailures": []}

    assert "search_datadog_logs" in _offered_tools(aws)
    sent = json.loads(urlopen.call_args.args[0].data)
    assert sent["filter"]["to"] == "2026-09-29T14:05:00+00:00"
    result = aws.bedrock.calls[1]["messages"][-1]["content"][0]["toolResult"]
    assert result["status"] == "error"
    assert "HTTP 403" in result["content"][0]["text"]
    assert len(aws.table.findings()) == 1
    stored = json.dumps([*aws.table.puts, *aws.table.updates], default=str)
    out = capsys.readouterr()
    for text in (json.dumps(aws.bedrock.calls, default=str), stored, out.out, out.err):
        assert DD_API_KEY not in text
        assert DD_APP_KEY not in text


def test_datadog_search_is_not_offered_without_the_app_key(
    aws: FakeInvestigator, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DD_API_KEY", DD_API_KEY)
    aws.bedrock.script.append(converse_response(report()))
    assert handler(_event(job(finding_id="f-1")), None) == {"batchItemFailures": []}
    assert "search_datadog_logs" not in _offered_tools(aws)
    assert "Datadog" not in aws.bedrock.calls[0]["system"][0]["text"]


def _set_github_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GH_APP_ID", GITHUB_APP_ID)
    monkeypatch.setenv("GH_APP_INSTALLATION_ID", GITHUB_INSTALLATION_ID)
    monkeypatch.setenv("GH_APP_PRIVATE_KEY", github_private_pem())
    monkeypatch.setenv("GH_ORG", GITHUB_ORG)


def test_github_tools_run_with_all_credentials_and_never_leak_them(
    aws: FakeInvestigator,
    monkeypatch: pytest.MonkeyPatch,
    mocker: MockerFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _set_github_credentials(monkeypatch)
    token = "ghs_" + "P0o9I8u7Y6t5" * 3
    exchange = MagicMock()
    exchange.__enter__.return_value.read.return_value = json.dumps(
        {"token": token, "expires_at": "2099-01-01T00:00:00Z"}
    ).encode()
    urlopen = mocker.patch(
        "urllib.request.urlopen",
        side_effect=[
            exchange,
            urllib.error.HTTPError(
                "https://api.github.com/orgs/acme/repos",
                403,
                "Forbidden",
                None,  # type: ignore[arg-type]
                None,
            ),
        ],
    )
    aws.bedrock.script.extend(
        [
            converse_response(tool_use("github_list_repos", {"name": "payment"})),
            converse_response(report()),
        ]
    )
    assert handler(_event(job(finding_id="f-1")), None) == {"batchItemFailures": []}

    assert {"github_list_repos", "github_recent_changes"} <= _offered_tools(aws)
    assert "GitHub" in aws.bedrock.calls[0]["system"][0]["text"]
    assert (
        urlopen.call_args_list[0]
        .args[0]
        .full_url.startswith(f"https://api.github.com/app/installations/{GITHUB_INSTALLATION_ID}/")
    )
    result = aws.bedrock.calls[1]["messages"][-1]["content"][0]["toolResult"]
    assert result["status"] == "error"
    assert "HTTP 403" in result["content"][0]["text"]
    stored = json.dumps([*aws.table.puts, *aws.table.updates], default=str)
    out = capsys.readouterr()
    for text in (json.dumps(aws.bedrock.calls, default=str), stored, out.out, out.err):
        assert token not in text
        assert "PRIVATE KEY" not in text


@pytest.mark.parametrize("missing", ["GH_APP_ID", "GH_APP_INSTALLATION_ID", "GH_APP_PRIVATE_KEY"])
def test_github_tools_are_not_offered_without_every_credential(
    aws: FakeInvestigator, monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    _set_github_credentials(monkeypatch)
    monkeypatch.delenv(missing)
    aws.bedrock.script.append(converse_response(report()))
    assert handler(_event(job(finding_id="f-1")), None) == {"batchItemFailures": []}
    assert not {name for name in _offered_tools(aws) if name.startswith("github_")}
    assert "GitHub" not in aws.bedrock.calls[0]["system"][0]["text"]


def _tokens_pk() -> str:
    return "budget#tokens#day#" + handler_module.datetime.now(handler_module.UTC).strftime(
        "%Y-%m-%d"
    )


def test_weighted_tokens_are_added_to_the_day_and_both_counts_recorded(
    aws: FakeInvestigator,
) -> None:
    aws.bedrock.script.append(
        {
            **converse_response(report("high")),
            "usage": {
                "inputTokens": 1200,
                "outputTokens": 300,
                "cacheReadInputTokens": 0,
                "cacheWriteInputTokens": 9000,
            },
        }
    )
    aws.table.items[_tokens_pk()] = {"pk": _tokens_pk(), "count": 500, "ttl": 1}
    assert handler(_event(job(finding_id="f-tokens")), None) == {"batchItemFailures": []}
    weighted = 1200 + 5 * 300 + 1.25 * 9000
    assert aws.table.items[_tokens_pk()]["count"] == 500 + weighted
    assert aws.table.items["finding#f-tokens"]["tokens_used"] == 10_500
    assert aws.table.items["finding#f-tokens"]["weighted_tokens"] == weighted
    assert not {"status", "resource_key"} & set(aws.table.items[_tokens_pk()])


def test_token_count_failure_still_stores_the_finding(
    aws: FakeInvestigator, mocker: MockerFixture
) -> None:
    mocker.patch.object(handler_module, "add_daily_tokens", side_effect=RuntimeError("boom"))
    aws.bedrock.script.append(
        {**converse_response(report("high")), "usage": {"inputTokens": 10, "outputTokens": 5}}
    )
    assert handler(_event(job(finding_id="f-1")), None) == {"batchItemFailures": []}
    assert aws.table.items["finding#f-1"]["tokens_used"] == 15
    assert aws.table.items["finding#f-1"]["weighted_tokens"] == 35


def test_run_without_usage_adds_nothing(aws: FakeInvestigator) -> None:
    aws.bedrock.script.append(converse_response(report("high")))
    handler(_event(job(finding_id="f-1")), None)
    assert _tokens_pk() not in aws.table.items
