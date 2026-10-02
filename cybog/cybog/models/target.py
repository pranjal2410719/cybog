"""
cybog/models/target.py - Target and discovered asset models.
"""
from __future__ import annotations
import uuid
from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class TargetStatus(str, Enum):
    PENDING = "PENDING"
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class Target(BaseModel):
    target_id: str = Field(default_factory=lambda: f"target-{uuid.uuid4().hex[:12]}")
    domain: str
    status: TargetStatus = TargetStatus.PENDING
    source_batch: Optional[str] = None
    added_at: datetime = Field(default_factory=datetime.utcnow)


class IP(BaseModel):
    address: str
    target_id: str
    sources: list[str] = Field(default_factory=list)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class Host(BaseModel):
    hostname: str
    target_id: str
    ips: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class Port(BaseModel):
    host: str
    port: int
    protocol: str = "tcp"
    state: str = "open"
    target_id: str
    sources: list[str] = Field(default_factory=list)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class Service(BaseModel):
    host: str
    port: int
    scheme: str
    url: str
    technology: list[str] = Field(default_factory=list)
    status_code: Optional[int] = None
    title: Optional[str] = None
    target_id: str
    source: str = ""
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class URL(BaseModel):
    url: str
    target_id: str
    source: str = ""
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class Endpoint(BaseModel):
    url: str
    method: str = "GET"
    path: str = ""
    target_id: str
    source: str = ""
    status_code: Optional[int] = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class Parameter(BaseModel):
    name: str
    endpoint: str
    param_type: str = "query"
    target_id: str
    source: str = ""
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
