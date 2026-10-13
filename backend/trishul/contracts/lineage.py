# SPDX-License-Identifier: Apache-2.0
"""Lineage graph contracts."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from trishul.contracts.labels import Label


class LineageNode(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    id: str = Field(min_length=1)
    kind: Literal["source", "derivation", "transformation", "sink"]
    label: Label
    ref: str


class LineageEdge(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    src: str
    dst: str
    op: str


class LineageGraph(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    nodes: tuple[LineageNode, ...] = ()
    edges: tuple[LineageEdge, ...] = ()
