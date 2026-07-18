from __future__ import annotations
import hashlib, time, enum
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class PluginType(str, enum.Enum):
    EXPLOIT = "exploit"
    PAYLOAD = "payload"
    POST_EXPLOIT = "post_exploit"

class PluginMeta(BaseModel):
    name: str
    version: str = "1.0"
    author: str = "DataPulse"
    description: str = ""
    plugin_type: PluginType
    protocols: List[str] = []

class ExploitResult(BaseModel):
    plugin_name: str
    target: str
    payload: str
    output: str
    success: bool
    session_id: Optional[str] = None
    duration_ms: float = 0.0
    raw: Dict[str, Any] = Field(default_factory=dict)

class Session(BaseModel):
    session_id: str = Field(default_factory=lambda: hashlib.sha256(str(time.time()).encode()).hexdigest()[:12])
    target: str
    protocol: str
    access_level: str = "user"
    established_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    alive: bool = True
    tunnel: Any = None
