# getagentid-pydantic

AgentID identity verification plugin for [pydantic-ai](https://ai.pydantic.dev). Provides typed Pydantic v2 models and middleware to verify AI agent identities through the [AgentID](https://getagentid.dev) registry before execution.

## Install

```bash
pip install getagentid-pydantic
```

## Quick start

### Verify an agent

```python
import asyncio
from getagentid_pydantic import verify_agent

async def main():
    result = await verify_agent("agent_abc123")
    print(result.verified)        # True / False
    print(result.trust_level)     # 0-5
    print(result.trust_level_label)  # e.g. "Established"
    print(result.receipt)         # cryptographic receipt

asyncio.run(main())
```

### Use the middleware with pydantic-ai

```python
from pydantic_ai import Agent
from getagentid_pydantic import AgentIDMiddleware

agent = Agent("openai:gpt-4o", system_prompt="You are helpful.")
middleware = AgentIDMiddleware(min_trust_level=2)

# Only agents with trust level >= 2 can execute
result = await middleware.run(agent, "Summarise this report.", agent_id="agent_abc123")
print(result.data)
```

### Get a trust header

```python
from getagentid_pydantic import get_trust_header

header = await get_trust_header("agent_abc123")
print(header.trust_level)
print(header.behavioral_risk_score)
print(header.scarring_score)
```

## Links

- AgentID registry: https://getagentid.dev
- GitHub: https://github.com/haroldmalikfrimpong-ops/getagentid
