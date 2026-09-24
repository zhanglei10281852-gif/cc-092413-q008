from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ReportCreate(BaseModel):
    township: str = Field(..., min_length=2, max_length=40)
    contact_name: str = Field(..., min_length=1, max_length=50)
    contact_phone: str = Field(..., min_length=5, max_length=20)
    address: str = Field(..., min_length=2, max_length=200)
    damage_description: str = Field(..., min_length=1, max_length=2000)
    damage_level: Literal["轻微", "一般", "严重", "特别严重"]
    classification: Literal["general", "sensitive", "critical"] = "general"
    event_id: int | None = None


class PolicyUpdate(BaseModel):
    max_classification: Literal["general", "sensitive", "critical"]
    field_tier: Literal["public", "masked", "full"]


class ExportCreate(BaseModel):
    township: str | None = Field(default=None, max_length=40)
    classification: Literal["general", "sensitive", "critical"] | None = None
    damage_level: Literal["轻微", "一般", "严重", "特别严重"] | None = None


class ExportRevoke(BaseModel):
    reason: str = Field(..., min_length=1, max_length=200)
