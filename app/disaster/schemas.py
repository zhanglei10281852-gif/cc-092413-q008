from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Classification = Literal["public", "internal", "restricted"]


class DisasterReportCreate(BaseModel):
    township: str = Field(..., min_length=1, max_length=80)
    reporter_name: str = Field(..., min_length=1, max_length=60)
    contact_phone: str = Field(..., min_length=7, max_length=20)
    address: str = Field(..., min_length=1, max_length=200)
    damage_description: str = Field(..., min_length=1, max_length=2000)
    classification: Classification = "internal"


class DisasterReportPatch(BaseModel):
    classification: Classification | None = None
    status: Literal["pending", "verified", "archived"] | None = None


class ExportRequest(BaseModel):
    classification: Classification = "restricted"
    township: str | None = Field(default=None, max_length=80)
