from __future__ import annotations

import asyncio
import json
import re
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from ..http_client import HttpClient
from ..models import Finding, ScanConfig, ScanModule, Severity

API_DOC_PATHS = [
    "/swagger.json", "/swagger.yaml", "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json", "/swagger-ui.html", "/swagger-ui/",
    "/openapi.json", "/openapi.yaml", "/api-docs", "/api-docs/",
    "/api-docs/v1", "/api-docs/v2", "/api-docs/v3",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/graphql", "/graphiql", "/graphql/console", "/playground",
    "/api/graphql", "/graphql/schema", "/__graphql",
    "/api/swagger.json", "/api/openapi.json",
    "/api/v1/swagger.json", "/api/v2/swagger.json",
    "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
    "/rest/api/1.0/", "/rest/api/2/",
    "/.well-known/openapi.json",
    "/redoc", "/redoc.html", "/api/redoc",
    "/docs", "/docs/", "/api/docs/",
]

COMMON_API_ENDPOINTS = [
    "/api/users", "/api/user", "/api/accounts", "/api/account",
    "/api/login", "/api/logout", "/api/auth", "/api/auth/login",
    "/api/token", "/api/tokens", "/api/refresh", "/api/auth/refresh",
    "/api/register", "/api/signup", "/api/profile",
    "/api/admin", "/api/admin/users", "/api/settings",
    "/api/config", "/api/configs", "/api/configuration",
    "/api/health", "/api/ping", "/api/status", "/api/version",
    "/api/info", "/api/metrics", "/api/stats",
    "/api/products", "/api/product", "/api/items", "/api/item",
    "/api/orders", "/api/order", "/api/cart", "/api/catalog",
    "/api/search", "/api/query",
    "/api/files", "/api/upload", "/api/download",
    "/api/messages", "/api/notifications", "/api/events",
    "/api/keys", "/api/secrets", "/api/credentials",
    "/api/debug", "/api/test", "/api/internal",
    "/v1/users", "/v1/auth", "/v1/login", "/v1/token",
    "/v2/users", "/v2/auth", "/v2/login",
    "/rest/users", "/rest/user", "/rest/login",
    "/api/v1/users", "/api/v1/auth", "/api/v1/token",
    "/api/v2/users", "/api/v2/auth",
    "/actuator", "/actuator/health", "/actuator/info",
    "/actuator/env", "/actuator/mappings", "/actuator/beans",
    "/actuator/configprops", "/actuator/conditions",
    "/actuator/metrics", "/actuator/loggers",
    "/.netlify/functions/", "/_api/",
    "/wp-json/", "/wp-json/wp/v2/",
    "/index.php/api/", "/api.php",
]

GRAPHQL_INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        args { name type { name kind } }
        type { name kind }
      }
    }
  }
}
"""


class APIScanner:
    def __init__(self, config: ScanConfig, client: HttpClient) -> None:
        self.config = config
        self.client = client

    async def scan(self, base_url: str) -> list[Finding]:
        findings: list[Finding] = []

        doc_findings = await self._find_api_docs(base_url)
        findings.extend(doc_findings)

        graphql_findings = await self._test_graphql(base_url)
        findings.extend(graphql_findings)

        endpoint_findings = await self._probe_api_endpoints(base_url)
        findings.extend(endpoint_findings)

        actuator_findings = await self._check_spring_actuator(base_url)
        findings.extend(actuator_findings)

        return findings

    async def _find_api_docs(self, base_url: str) -> list[Finding]:
        findings: list[Finding] = []
        base = base_url.rstrip("/")
        semaphore = asyncio.Semaphore(min(self.config.threads, 20))

        async def check_path(path: str) -> Optional[Finding]:
            async with semaphore:
                url = f"{base}{path}"
                resp = await self.client.get(url, retries=1)
                if not resp or resp.status_code not in (200, 301, 302):
                    return None

                is_swagger = any(k in resp.body for k in ["swagger", "openapi", "paths", "info"])
                is_graphql = "graphql" in path.lower() or "graphiql" in resp.body.lower()
                is_json = resp.content_type and "json" in resp.content_type
                is_yaml = path.endswith(".yaml") or path.endswith(".yml")

                if not (is_swagger or is_graphql or is_json or is_yaml or "api" in path.lower()):
                    return None

                title = "API Documentation Exposed"
                description = f"API documentation found at {path}."
                severity = Severity.MEDIUM

                if "swagger" in path.lower() or "openapi" in path.lower():
                    title = "Swagger/OpenAPI Documentation Exposed"
                    description = "API specification exposed. Reveals all endpoints, parameters, authentication methods, and data schemas."
                    severity = Severity.HIGH
                elif "graphql" in path.lower() or "graphiql" in resp.body.lower():
                    title = "GraphQL Endpoint Exposed"
                    severity = Severity.MEDIUM

                try:
                    data = json.loads(resp.body)
                    endpoints = []
                    if "paths" in data:
                        endpoints = list(data["paths"].keys())[:10]
                    elif "data" in data and "__schema" in str(data):
                        endpoints = ["GraphQL schema found"]
                    evidence = f"Endpoints preview: {endpoints}" if endpoints else f"HTTP {resp.status_code}"
                except Exception:
                    evidence = f"HTTP {resp.status_code}"

                return Finding(
                    url=url,
                    title=title,
                    severity=severity,
                    module=ScanModule.VULNS,
                    description=description,
                    evidence=evidence,
                    recommendation="Restrict API documentation access to authenticated users in production environments.",
                )

        results = await asyncio.gather(*[check_path(p) for p in API_DOC_PATHS], return_exceptions=True)
        for r in results:
            if isinstance(r, Finding):
                findings.append(r)

        return findings

    async def _test_graphql(self, base_url: str) -> list[Finding]:
        findings: list[Finding] = []
        base = base_url.rstrip("/")

        graphql_endpoints = ["/graphql", "/api/graphql", "/graphql/v1", "/__graphql", "/graph"]

        for path in graphql_endpoints:
            url = f"{base}{path}"

            resp = await self.client.post(
                url,
                json_data={"query": GRAPHQL_INTROSPECTION_QUERY},
                extra_headers={"Content-Type": "application/json"},
                retries=1,
            )

            if resp and resp.status_code == 200 and "__schema" in resp.body:
                try:
                    data = json.loads(resp.body)
                    schema_data = data.get("data", {}).get("__schema", {})
                    types = schema_data.get("types", [])
                    type_names = [t["name"] for t in types if t.get("name") and not t["name"].startswith("__")][:20]

                    findings.append(Finding(
                        url=url,
                        title="GraphQL Introspection Enabled",
                        severity=Severity.HIGH,
                        module=ScanModule.VULNS,
                        description="GraphQL introspection is enabled, revealing the full API schema including all types, queries, and mutations.",
                        evidence=f"Types discovered: {', '.join(type_names)}",
                        recommendation="Disable introspection in production. Only enable for authenticated developers.",
                    ))
                except json.JSONDecodeError:
                    pass

            batch_resp = await self.client.post(
                url,
                json_data=[{"query": "{ __typename }"}, {"query": "{ __typename }"}],
                extra_headers={"Content-Type": "application/json"},
                retries=1,
            )
            if batch_resp and batch_resp.status_code == 200 and "__typename" in batch_resp.body:
                findings.append(Finding(
                    url=url,
                    title="GraphQL Batching Enabled",
                    severity=Severity.MEDIUM,
                    module=ScanModule.VULNS,
                    description="GraphQL query batching is enabled, which can be used for brute-force amplification attacks.",
                    evidence="Batched query returned multiple results",
                    recommendation="Limit query complexity and disable or rate-limit batch operations.",
                ))

        return findings

    async def _probe_api_endpoints(self, base_url: str) -> list[Finding]:
        findings: list[Finding] = []
        base = base_url.rstrip("/")
        semaphore = asyncio.Semaphore(min(self.config.threads, 25))
        found_endpoints: list[dict] = []

        async def probe(path: str) -> Optional[dict]:
            async with semaphore:
                url = f"{base}{path}"
                resp = await self.client.get(url, retries=1)
                if not resp or resp.status_code in (404, 400, 0):
                    return None
                if resp.status_code in (200, 201, 401, 403):
                    is_api = (
                        (resp.content_type and ("json" in resp.content_type or "xml" in resp.content_type))
                        or resp.body.strip().startswith(("{", "["))
                    )
                    if is_api or resp.status_code in (401, 403):
                        return {
                            "path": path,
                            "url": url,
                            "status": resp.status_code,
                            "content_type": resp.content_type,
                            "requires_auth": resp.status_code in (401, 403),
                        }
                return None

        results = await asyncio.gather(*[probe(p) for p in COMMON_API_ENDPOINTS], return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                found_endpoints.append(r)

        unauthenticated = [e for e in found_endpoints if not e["requires_auth"]]
        authenticated = [e for e in found_endpoints if e["requires_auth"]]

        if unauthenticated:
            paths = [e["path"] for e in unauthenticated[:15]]
            findings.append(Finding(
                url=base_url,
                title=f"Unauthenticated API Endpoints Found ({len(unauthenticated)})",
                severity=Severity.MEDIUM,
                module=ScanModule.VULNS,
                description=f"Found {len(unauthenticated)} API endpoints accessible without authentication.",
                evidence="Endpoints: " + ", ".join(paths),
                recommendation="Ensure all API endpoints require proper authentication. Implement API gateway with auth enforcement.",
            ))

        for ep in unauthenticated:
            if any(s in ep["path"] for s in ["/admin", "/config", "/secret", "/key", "/debug", "/internal"]):
                findings.append(Finding(
                    url=ep["url"],
                    title=f"Sensitive API Endpoint Exposed: {ep['path']}",
                    severity=Severity.HIGH,
                    module=ScanModule.VULNS,
                    description=f"Sensitive API endpoint {ep['path']} is accessible without authentication (HTTP {ep['status']}).",
                    evidence=f"HTTP {ep['status']} at {ep['url']}",
                    recommendation="Immediately restrict access to this endpoint and require authentication.",
                ))

        if authenticated:
            paths = [e["path"] for e in authenticated[:10]]
            findings.append(Finding(
                url=base_url,
                title=f"Protected API Endpoints Discovered ({len(authenticated)})",
                severity=Severity.INFO,
                module=ScanModule.VULNS,
                description=f"Found {len(authenticated)} API endpoint(s) that require authentication.",
                evidence="Endpoints: " + ", ".join(paths),
                recommendation="Verify authentication mechanisms are properly implemented (not just checking headers).",
            ))

        return findings

    async def _check_spring_actuator(self, base_url: str) -> list[Finding]:
        findings: list[Finding] = []
        base = base_url.rstrip("/")

        actuator_url = f"{base}/actuator"
        resp = await self.client.get(actuator_url, retries=1)

        if not resp or resp.status_code != 200:
            return findings

        try:
            data = json.loads(resp.body)
            links = data.get("_links", {})
            available = list(links.keys())
        except Exception:
            available = []

        if available or resp.status_code == 200:
            findings.append(Finding(
                url=actuator_url,
                title="Spring Boot Actuator Exposed",
                severity=Severity.HIGH,
                module=ScanModule.VULNS,
                description="Spring Boot Actuator is publicly accessible. It exposes internal application metrics, environment variables, and configuration.",
                evidence=f"Available endpoints: {', '.join(available[:15])}",
                recommendation="Restrict actuator endpoints to localhost or internal network. Require authentication for all actuator paths.",
            ))

        dangerous_actuator_paths = {
            "/actuator/env": ("Environment Variables Exposed", Severity.CRITICAL,
                              "Exposes all environment variables including secrets and API keys."),
            "/actuator/heapdump": ("Heap Dump Available", Severity.CRITICAL,
                                   "Java heap dump downloadable - contains all application memory including passwords and tokens."),
            "/actuator/threaddump": ("Thread Dump Available", Severity.HIGH,
                                     "Thread dump exposes internal application state."),
            "/actuator/beans": ("Spring Beans Configuration Exposed", Severity.HIGH,
                                "Exposes all Spring bean definitions and configuration."),
            "/actuator/mappings": ("Request Mappings Exposed", Severity.MEDIUM,
                                   "Reveals all application endpoint mappings."),
            "/actuator/configprops": ("Configuration Properties Exposed", Severity.HIGH,
                                      "Exposes all configuration properties including sensitive values."),
            "/actuator/loggers": ("Logger Configuration Exposed", Severity.MEDIUM,
                                  "Log level can be modified to increase information disclosure."),
            "/actuator/conditions": ("Conditions Report Exposed", Severity.LOW,
                                     "Exposes Spring auto-configuration conditions."),
        }

        for path, (title, severity, desc) in dangerous_actuator_paths.items():
            url = f"{base}{path}"
            resp = await self.client.get(url, retries=1)
            if resp and resp.status_code == 200:
                evidence = resp.body[:300] if "env" in path or "config" in path else f"HTTP 200 at {url}"
                findings.append(Finding(
                    url=url,
                    title=title,
                    severity=severity,
                    module=ScanModule.VULNS,
                    description=desc,
                    evidence=evidence,
                    recommendation="Disable or require authentication for this actuator endpoint.",
                ))

        return findings
