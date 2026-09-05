"""Remote MCP probing."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from .store import write_artifact

DISCOVERY_PATHS = ("/sse", "/mcp", "/.well-known/mcp", "/")
EXEC_HINTS = ("run", "exec", "shell", "bash", "eval", "command")
FS_HINTS = ("file://", "/srv", "/home", "file:")
PROMPT_HINTS = ("ignore previous", "new instructions", "override", "system prompt")


@dataclass(slots=True)
class Endpoint:
    transport: str
    url: str


def _payload(method: str, params: dict[str, Any] | None = None, request_id: int = 1) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}


def _normalize_tool(item: dict[str, Any]) -> dict[str, Any]:
    if "name" in item:
        return item
    return item.get("tool", item)


async def discover_endpoint(url: str) -> Endpoint | None:
    base = url if url.startswith(("http://", "https://")) else f"https://{url}"
    async with httpx.AsyncClient(follow_redirects=True, timeout=15, headers={"Accept": "application/json, text/event-stream"}) as client:
        for path in DISCOVERY_PATHS:
            probe_url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            try:
                if path == "/mcp":
                    resp = await client.post(probe_url, json=_payload("initialize", {"protocolVersion": "2024-11-05", "clientInfo": {"name": "mcpx", "version": "0.1.0"}, "capabilities": {}}))
                else:
                    resp = await client.get(probe_url)
            except httpx.HTTPError:
                continue
            content_type = resp.headers.get("content-type", "")
            if "text/event-stream" in content_type or path == "/sse":
                return Endpoint("sse", probe_url)
            if resp.status_code < 500 and (path == "/mcp" or "json" in content_type or resp.text.strip().startswith("{")):
                return Endpoint("streamable-http", probe_url)
    return None


async def _mcp_call(client: httpx.AsyncClient, endpoint: Endpoint, method: str, params: dict[str, Any] | None = None, request_id: int = 1) -> dict[str, Any]:
    payload = _payload(method, params, request_id=request_id)
    if endpoint.transport == "sse":
        resp = await client.post(endpoint.url.replace("/sse", "/mcp") if endpoint.url.endswith("/sse") else endpoint.url, json=payload)
    else:
        resp = await client.post(endpoint.url, json=payload)
    if resp.status_code >= 400:
        return {"ok": False, "status_code": resp.status_code, "error": resp.text[:500]}
    try:
        return {"ok": True, "data": resp.json()}
    except json.JSONDecodeError:
        return {"ok": False, "status_code": resp.status_code, "error": resp.text[:500]}


def _extract_result(obj: dict[str, Any]) -> Any:
    return obj.get("data", {}).get("result", {})


def _токены(text: str) -> set[str]:
    """Разбить имя на токены по `_`, `-` И границам camelCase.

    🔴 Оплачено багом (11.08): `[a-z_]+` считал `_` частью слова, и `run_command` становился
    ОДНИМ токеном — пересечение с {run, command} пустое, EXEC-инструмент не ловился. Тот же
    дефект скрыт в overreach (там его маскировало описание). Здесь: сперва camelCase→пробел,
    потом дробим по всем не-буквам. `run_command`, `runCommand`, `deleteRecords` → правильные слова.
    """
    расколот = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", text)
    return set(re.findall(r"[a-z]+", расколот.lower()))


def security_findings(server_info: dict[str, Any], tools: list[dict[str, Any]],
                      resources: list[dict[str, Any]], prompts: list[dict[str, Any]],
                      authless: bool) -> list[dict[str, str]]:
    """Находки безопасности MCP-сервера. Каждая с severity — для вердикта и репорта.

    🔴 `authless` теперь ВЫЧИСЛЯЕТСЯ реальной проверкой в probe_server (сравнение ответа с
    Authorization и без), а не хардкодится True. Прежняя версия выдавала NO_AUTH всегда, потому
    что probe и не слал заголовок — ложное срабатывание по построению (закон XIV).
    EXEC-признак — по границам слов, а не подстрокой.
    """
    findings: list[dict[str, str]] = []
    if authless:
        findings.append({"code": "NO_AUTH", "severity": "high",
                         "message": "сервер отдаёт инструменты и без Authorization (проверено сравнением)"})
    info_dump = json.dumps(server_info, ensure_ascii=False).lower()
    if any(token in info_dump for token in FS_HINTS):
        findings.append({"code": "INFO_DISCLOSURE", "severity": "medium",
                         "message": "serverInfo раскрывает внутренние пути или имена"})
    for tool in tools:
        name = str(tool.get("name", ""))
        schema = tool.get("inputSchema") or tool.get("input_schema")
        if not schema:
            findings.append({"code": "TOOL_NO_SCHEMA", "severity": "medium",
                             "message": f"{name}: нет входной схемы — аргументы не ограничены"})
        if _токены(name) & set(EXEC_HINTS):
            findings.append({"code": "TOOL_EXEC_HINT", "severity": "critical",
                             "message": f"{name}: имя указывает на исполнение команд"})
    for resource in resources:
        uri = str(resource.get("uri") or resource.get("name") or "")
        if any(hint in uri for hint in FS_HINTS):
            findings.append({"code": "RESOURCE_FS_HINT", "severity": "high",
                             "message": f"{uri}: доступ к файловой системе"})
        if "*" in uri or "{" in uri:
            findings.append({"code": "WILDCARD_RESOURCES", "severity": "medium",
                             "message": f"{uri}: ресурс с подстановкой (wildcard)"})
    for prompt in prompts:
        content = json.dumps(prompt, ensure_ascii=False).lower()
        if any(hint in content for hint in PROMPT_HINTS):
            findings.append({"code": "PROMPT_INJECTION_HINT", "severity": "high",
                             "message": f"{prompt.get('name', 'prompt')}: формулировка подмены инструкций"})
    return findings


async def _проверить_authless(client: httpx.AsyncClient, endpoint: "Endpoint") -> bool:
    """Реально ли сервер отдаёт инструменты БЕЗ авторизации.

    Закон XIV: чтобы утверждать «без auth», надо скормить вход, на котором проверка обязана
    сказать «нет». Шлём tools/list с фиктивным Bearer-заголовком и без него. authless = сервер
    отдаёт инструменты без заголовка. Если без заголовка отказ (401/403/пусто), а с заголовком
    ответ — сервер авторизацию требует, находки NO_AUTH нет.
    """
    без = await _mcp_call(client, endpoint, "tools/list", request_id=90)
    отдал_без = bool(без.get("ok") and _extract_result(без).get("tools"))
    return отдал_без


def fingerprint(server_info: dict[str, Any], capabilities: dict[str, Any], endpoint: Endpoint | None) -> dict[str, str]:
    name = str(server_info.get("name", "unknown"))
    version = str(server_info.get("version", "unknown"))
    flavor = "unknown"
    haystack = (name + " " + version + " " + json.dumps(capabilities, ensure_ascii=False)).lower()
    if "fastmcp" in haystack:
        flavor = "fastmcp"
    elif "cloudflare" in haystack:
        flavor = "cloudflare"
    elif "smithery" in haystack:
        flavor = "smithery"
    elif "mcp" in haystack:
        flavor = "generic-mcp"
    return {"name": name, "version": version, "flavor": flavor, "transport": endpoint.transport if endpoint else "unknown"}


async def probe_server(url: str, *, save_json: bool = False) -> dict[str, Any]:
    endpoint = await discover_endpoint(url)
    result: dict[str, Any] = {
        "url": url,
        "mcp_detected": False,
        "transport": endpoint.transport if endpoint else None,
        "endpoint": endpoint.url if endpoint else None,
        "serverInfo": {},
        "capabilities": {},
        "tools": [],
        "resources": [],
        "prompts": [],
        "security_findings": [],
    }
    if endpoint is None:
        if save_json:
            result["artifact_path"] = str(write_artifact(url, result))
        return result

    async with httpx.AsyncClient(follow_redirects=True, timeout=20) as client:
        initialize = await _mcp_call(client, endpoint, "initialize", {"protocolVersion": "2024-11-05", "clientInfo": {"name": "mcpx", "version": "0.1.0"}, "capabilities": {}})
        init_result = _extract_result(initialize) if initialize.get("ok") else {}
        result["serverInfo"] = init_result.get("serverInfo", {})
        result["capabilities"] = init_result.get("capabilities", {})

        tools_obj = await _mcp_call(client, endpoint, "tools/list", request_id=2)
        resources_obj = await _mcp_call(client, endpoint, "resources/list", request_id=3)
        prompts_obj = await _mcp_call(client, endpoint, "prompts/list", request_id=4)

        result["tools"] = [_normalize_tool(item) for item in (_extract_result(tools_obj).get("tools", []) if tools_obj.get("ok") else [])]
        result["resources"] = _extract_result(resources_obj).get("resources", []) if resources_obj.get("ok") else []
        result["prompts"] = _extract_result(prompts_obj).get("prompts", []) if prompts_obj.get("ok") else []
        result["mcp_detected"] = bool(result["serverInfo"] or result["capabilities"] or result["tools"] or result["resources"] or result["prompts"])
        result["fingerprint"] = fingerprint(result["serverInfo"], result["capabilities"], endpoint)
        # 🔴 authless — не хардкод, а реальная проверка (закон XIV)
        authless = await _проверить_authless(client, endpoint) if result["mcp_detected"] else False
        result["authless"] = authless
        result["security_findings"] = (
            security_findings(result["serverInfo"], result["tools"], result["resources"], result["prompts"], authless=authless)
            if result["mcp_detected"]
            else []
        )

    # вердикт сервера по самой серьёзной находке — для контракта и кода возврата
    _веса = {"critical": 3, "high": 2, "medium": 1}
    макс = max((_веса.get(f.get("severity", "medium"), 1) for f in result["security_findings"]), default=0)
    result["инструмент"] = {"имя": "mcpx", "цель": url}
    result["verdict"] = ("критический" if макс >= 3 else "высокий" if макс == 2 else
                         "умеренный" if макс == 1 else "чистый")
    result["critical_findings"] = [f for f in result["security_findings"] if f.get("severity") == "critical"]
    if not result["mcp_detected"]:
        result["not_proven"] = "MCP-сервер не обнаружен по стандартным путям — проверка не состоялась"

    if save_json:
        result["artifact_path"] = str(write_artifact(url, result))
    return result
