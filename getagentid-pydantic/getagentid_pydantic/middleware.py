"""AgentID verification helpers and pydantic-ai middleware."""

from __future__ import annotations

from typing import Any, Callable, Optional

import httpx
import jwt

from .models import TrustHeader, VerifyResult

DEFAULT_API_URL = "https://getagentid.dev"


async def verify_agent(
    agent_id: str,
    *,
    api_url: str = DEFAULT_API_URL,
    timeout: float = 10.0,
) -> VerifyResult:
    """Call POST /api/v1/agents/verify and return a typed VerifyResult.

    Args:
        agent_id: The AgentID identifier to verify.
        api_url: Base URL of the AgentID API.
        timeout: HTTP request timeout in seconds.

    Returns:
        VerifyResult with all verification data.

    Raises:
        httpx.HTTPStatusError: If the API returns an error status.
        httpx.ConnectError: If the API is unreachable.
    """
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.post(
            f"{api_url}/api/v1/agents/verify",
            json={"agent_id": agent_id},
        )
        response.raise_for_status()
        data = response.json()
    return VerifyResult.model_validate(data)


async def get_trust_header(
    agent_id: str,
    *,
    api_url: str = DEFAULT_API_URL,
    timeout: float = 10.0,
) -> TrustHeader:
    """Call GET /api/v1/agents/trust-header, decode the JWT, return typed TrustHeader.

    The JWT is decoded **without** signature verification because the
    trust-header endpoint itself is the authoritative source.  If you need
    cryptographic verification, validate the signature against the AgentID
    public key separately.

    Args:
        agent_id: The AgentID identifier.
        api_url: Base URL of the AgentID API.
        timeout: HTTP request timeout in seconds.

    Returns:
        TrustHeader with decoded claims.

    Raises:
        httpx.HTTPStatusError: If the API returns an error status.
        ValueError: If the response does not contain a valid JWT token.
    """
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(
            f"{api_url}/api/v1/agents/trust-header",
            params={"agent_id": agent_id},
        )
        response.raise_for_status()
        data = response.json()

    token: str | None = data.get("token") or data.get("trust_header")
    if not token:
        raise ValueError(
            f"No JWT token found in trust-header response for agent {agent_id}"
        )

    # Decode without verification — the API is the trust anchor.
    claims = jwt.decode(token, options={"verify_signature": False})
    return TrustHeader.model_validate(claims)


class AgentIDMiddleware:
    """Middleware that verifies an agent's identity before execution.

    Wraps a pydantic-ai agent run to ensure the caller meets a minimum
    trust level before the agent processes the request.

    Usage::

        from pydantic_ai import Agent
        from getagentid_pydantic import AgentIDMiddleware

        agent = Agent("openai:gpt-4o", system_prompt="You are helpful.")
        middleware = AgentIDMiddleware(min_trust_level=2)

        # Verify, then run
        result = await middleware.run(agent, "Hello!", agent_id="agent_abc123")

    Args:
        min_trust_level: Minimum trust level required to proceed (0-5).
        api_url: Base URL of the AgentID API.
        on_reject: Optional callback invoked when verification fails.
            Receives the VerifyResult and should return a message string.
    """

    def __init__(
        self,
        *,
        min_trust_level: int = 1,
        api_url: str = DEFAULT_API_URL,
        on_reject: Optional[Callable[[VerifyResult], str]] = None,
    ) -> None:
        self.min_trust_level = min_trust_level
        self.api_url = api_url
        self.on_reject = on_reject

    async def verify(self, agent_id: str) -> VerifyResult:
        """Verify an agent and return the result."""
        return await verify_agent(agent_id, api_url=self.api_url)

    async def run(
        self,
        agent: Any,
        prompt: str,
        *,
        agent_id: str,
        **run_kwargs: Any,
    ) -> Any:
        """Verify the agent's identity, then delegate to ``agent.run()``.

        Args:
            agent: A pydantic-ai ``Agent`` instance.
            prompt: The user prompt to pass to the agent.
            agent_id: The AgentID identifier of the calling agent.
            **run_kwargs: Additional keyword arguments forwarded to ``agent.run()``.

        Returns:
            The result of ``agent.run()`` if verification passes.

        Raises:
            PermissionError: If the agent is not verified or does not meet
                the minimum trust level.
        """
        result = await self.verify(agent_id)

        if not result.verified:
            msg = f"Agent {agent_id} failed identity verification."
            if self.on_reject:
                msg = self.on_reject(result)
            raise PermissionError(msg)

        trust = result.trust_level or 0
        if trust < self.min_trust_level:
            msg = (
                f"Agent {agent_id} trust level {trust} "
                f"is below the required minimum of {self.min_trust_level}."
            )
            if self.on_reject:
                msg = self.on_reject(result)
            raise PermissionError(msg)

        return await agent.run(prompt, **run_kwargs)
