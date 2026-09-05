"""Educational versioned key-management module for RSA and ECC keys."""

import json
import os
import secrets
import stat
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.crypto.ecc import generate_ecc_keypair
from app.crypto.rsa import generate_rsa_keypair


@dataclass
class KeyRecord:
    key_id: str
    algorithm: str
    version: int
    status: str
    public: dict[str, Any]
    private: dict[str, Any]
    created_at: str


class KeyManagementModule:
    """Generate, persist, rotate, retire, and revoke asymmetric keys."""

    def __init__(self, path: str | Path = ".govpay-kms.json"):
        self.path = Path(path)
        self.records: dict[str, KeyRecord] = {}
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            values = json.loads(self.path.read_text(encoding="utf-8"))
            self.records = {f"{item['key_id']}:v{item['version']}": KeyRecord(**item) for item in values}

    def _save(self) -> None:
        self.path.write_text(json.dumps([asdict(item) for item in self.records.values()], indent=2), encoding="utf-8")
        try:
            os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

    def generate(self, algorithm: str, key_id: str | None = None) -> KeyRecord:
        algorithm = algorithm.upper()
        key_id = key_id or f"{algorithm.lower()}-{secrets.token_hex(8)}"
        version = 1 + max((item.version for item in self.records.values() if item.key_id == key_id), default=0)
        if algorithm == "RSA":
            pair = generate_rsa_keypair()
            public, private = asdict(pair.public), asdict(pair.private)
        elif algorithm == "ECC":
            pair = generate_ecc_keypair()
            public, private = asdict(pair.public), asdict(pair.private)
        else:
            raise ValueError("algorithm must be RSA or ECC")
        record = KeyRecord(key_id, algorithm, version, "active", public, private, datetime.now(timezone.utc).isoformat())
        self.records[f"{key_id}:v{version}"] = record
        self._save()
        return record

    def get_active(self, key_id: str) -> KeyRecord:
        active = [item for item in self.records.values() if item.key_id == key_id and item.status == "active"]
        if not active:
            raise ValueError("key is not active")
        return max(active, key=lambda item: item.version)

    def get_for_decryption(self, key_id: str, version: int) -> KeyRecord:
        records = [item for item in self.records.values() if item.key_id == key_id and item.version == version]
        if not records or records[0].status == "revoked":
            raise ValueError("key version is unavailable")
        return records[0]

    def rotate(self, key_id: str) -> KeyRecord:
        current = self.get_active(key_id)
        current.status = "retired"
        rotated = self.generate(current.algorithm, key_id)
        self._save()
        return rotated

    def revoke(self, key_id: str) -> None:
        if not any(item.key_id == key_id for item in self.records.values()):
            raise ValueError("key is not available")
        for record in self.records.values():
            if record.key_id == key_id:
                record.status = "revoked"
        self._save()
