"""Typed Pydantic v2 models for all AgentID API responses."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class AgentIdentity(BaseModel):
    """Core agent identity record."""

    agent_id: str
    name: str
    did: Optional[str] = None
    trust_level: int = 0
    trust_level_label: Optional[str] = None
    capabilities: list[str] = Field(default_factory=list)
    verified: bool = False
    active: bool = True
    certificate_valid: Optional[bool] = None


class InteractionPattern(BaseModel):
    """Behavioural interaction pattern metrics."""

    completion_ratio: Optional[float] = None
    sequence_depth: Optional[int] = None
    co_signed_outputs: Optional[int] = None
    relationship_to_completion_ratio: Optional[float] = None
    evaluation_window: Optional[str] = None


class ContextContinuity(BaseModel):
    """Context continuity scoring."""

    score: Optional[float] = None
    auto_context_epoch: Optional[str] = None
    signals: list[str] = Field(default_factory=list)


class Behaviour(BaseModel):
    """Behavioural risk assessment."""

    risk_score: Optional[float] = None
    warnings: list[str] = Field(default_factory=list)


class BlockchainRecord(BaseModel):
    """On-chain attestation record."""

    tx_hash: Optional[str] = None
    cluster: Optional[str] = None
    explorer_url: Optional[str] = None


class Receipt(BaseModel):
    """Cryptographic receipt for a verified action."""

    receipt_id: Optional[str] = None
    action: Optional[str] = None
    agent_id: Optional[str] = None
    timestamp: Optional[str] = None
    data_hash: Optional[str] = None
    signature: Optional[str] = None
    compound_digest: Optional[str] = None
    compound_digest_ed25519_signature: Optional[str] = None
    policy_hash: Optional[str] = None
    blockchain: Optional[BlockchainRecord] = None


class VerifyResult(BaseModel):
    """Full response from POST /api/v1/agents/verify."""

    verified: bool = False
    agent_id: Optional[str] = None
    did: Optional[str] = None
    trust_level: Optional[int] = None
    trust_level_label: Optional[str] = None
    permissions: list[str] = Field(default_factory=list)
    spending_limit: Optional[float] = None
    trust_score: Optional[float] = None
    certificate_valid: Optional[bool] = None
    negative_signals: Optional[int] = None
    resolved_signals: Optional[int] = None
    scarring_score: Optional[float] = None
    incident_history: list[Any] = Field(default_factory=list)
    interaction_pattern: Optional[InteractionPattern] = None
    context_continuity: Optional[ContextContinuity] = None
    behaviour: Optional[Behaviour] = None
    receipt: Optional[Receipt] = None
    blockchain: Optional[BlockchainRecord] = None
    wallet: Optional[str] = None
    solana_wallet: Optional[str] = None
    resolution_source: Optional[str] = None
    resolved_at: Optional[str] = None


class TrustHeader(BaseModel):
    """Decoded JWT trust header for an agent."""

    agent_id: str
    trust_level: Optional[int] = None
    trust_level_label: Optional[str] = None
    context_continuity_score: Optional[float] = None
    behavioral_risk_score: Optional[float] = None
    scarring_score: Optional[float] = None
    negative_signals: Optional[int] = None
    resolved_signals: Optional[int] = None
    attestation_count: Optional[int] = None
    did: Optional[str] = None
    evaluatedAt: Optional[str] = None
    iat: Optional[int] = None
    exp: Optional[int] = None
