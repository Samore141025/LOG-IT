"""Forensics module: Privacy PII masking and cryptographic hash-chain ledger.

Provides:
- mask_sensitive_data: Redacts passwords, auth tokens, SSNs, credit cards.
- ForensicLedger: Computes SHA-256 Merkle chain blocks ensuring tamper-proof audit trails.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import UUID

# Regex patterns for sensitive data masking
RE_PASSWORD_PARAM = re.compile(r"(?i)(password|passwd|pwd|secret|api_key|token|access_token)=([^&\s]+)")
RE_BEARER_AUTH = re.compile(r"(?i)Bearer\s+([A-Za-z0-9_\-\.]+)")
RE_CREDIT_CARD = re.compile(r"\b(?:\d[ -]*?){13,16}\b")
RE_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def mask_sensitive_data(text: str) -> str:
    """Mask common sensitive credentials, tokens, and PII from raw log text."""
    if not text:
        return text
    
    # Mask password key-value parameters
    redacted = RE_PASSWORD_PARAM.sub(r"\1=[REDACTED]", text)
    # Mask bearer tokens
    redacted = RE_BEARER_AUTH.sub(r"Bearer [REDACTED_TOKEN]", redacted)
    # Mask SSNs
    redacted = RE_SSN.sub(r"***-**-****", redacted)
    
    # Mask credit card numbers (simple length check)
    def _cc_mask(match: re.Match[str]) -> str:
        s = re.sub(r"[ -]", "", match.group(0))
        if 13 <= len(s) <= 16:
            return f"****-****-****-{s[-4:]}"
        return match.group(0)

    redacted = RE_CREDIT_CARD.sub(_cc_mask, redacted)
    return redacted


class ForensicLedger:
    """Cryptographic tamper-proof ledger chaining sequential log and finding batches with SHA-256."""

    def __init__(self, ledger_path: str = "forensic_ledger.json"):
        self.ledger_path = Path(ledger_path)
        self.chain: List[Dict[str, Any]] = self._load()

    def _load(self) -> List[Dict[str, Any]]:
        if self.ledger_path.is_file():
            try:
                with open(self.ledger_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        return data
            except Exception:
                pass
        return []

    def save(self) -> None:
        try:
            with open(self.ledger_path, "w", encoding="utf-8") as f:
                json.dump(self.chain, f, indent=2)
        except Exception:
            pass

    def get_last_hash(self) -> str:
        if not self.chain:
            return "0" * 64
        return str(self.chain[-1].get("block_hash", "0" * 64))

    def record_batch(self, event_ids: List[UUID | str], finding_count: int) -> str:
        """Add an immutable block to the chain."""
        prev_hash = self.get_last_hash()
        ts = datetime.now(timezone.utc).isoformat()
        
        # Calculate digest over batch IDs
        sorted_ids = sorted([str(eid) for eid in event_ids])
        batch_digest = hashlib.sha256(",".join(sorted_ids).encode("utf-8")).hexdigest()
        
        block_content = f"{prev_hash}|{ts}|{batch_digest}|{finding_count}"
        block_hash = hashlib.sha256(block_content.encode("utf-8")).hexdigest()
        
        block: Dict[str, Any] = {
            "index": len(self.chain) + 1,
            "timestamp": ts,
            "event_count": len(event_ids),
            "finding_count": finding_count,
            "prev_hash": prev_hash,
            "batch_digest": batch_digest,
            "block_hash": block_hash,
        }
        self.chain.append(block)
        self.save()
        return block_hash

    def verify_integrity(self) -> Dict[str, Any]:
        """Verify the mathematical validity of the complete cryptographic hash chain."""
        if not self.chain:
            return {"valid": True, "total_blocks": 0, "message": "Ledger is empty. No blocks to verify."}

        for i, block in enumerate(self.chain):
            expected_prev = "0" * 64 if i == 0 else self.chain[i - 1]["block_hash"]
            if block.get("prev_hash") != expected_prev:
                return {
                    "valid": False,
                    "failed_at_block": i + 1,
                    "reason": f"Previous hash mismatch at block {i + 1}",
                }
            
            raw = f"{block['prev_hash']}|{block['timestamp']}|{block['batch_digest']}|{block['finding_count']}"
            computed = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            if computed != block.get("block_hash"):
                return {
                    "valid": False,
                    "failed_at_block": i + 1,
                    "reason": f"Block hash tampering detected at block {i + 1}",
                }

        return {
            "valid": True,
            "total_blocks": len(self.chain),
            "latest_hash": self.chain[-1]["block_hash"],
            "message": "All cryptographic blocks intact. Zero evidence of tampering.",
        }
