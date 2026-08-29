"""Append-only, hash-chained SQLite event ledger for local persistent memory."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict

from .canonical import (
    CausalFrontierError,
    canonical_bytes,
    read_json_bytes,
    require_id,
    require_id_list,
    require_sha256,
    require_utc_timestamp,
)

GENESIS = "0" * 64
APPLICATION_ID = 0x4346524E  # CFRN
USER_VERSION = 1
EVENT_SCHEMAS = {
    "CAPSULE_COMPILED": {"case_sha256", "analysis_sha256", "run_id"},
    "CAPSULE_VERIFIED": {"run_id", "manifest_sha256"},
    "COUNTERFACTUAL_REHEARSAL": {
        "predecessor_run_id",
        "predecessor_active_world_ids",
        "predecessor_case_state",
        "experiment_id",
        "outcome_id",
        "branch_plan_sha256",
        "successor_run_id",
        "successor_active_world_ids",
        "successor_case_state",
        "status",
    },
}
TABLE_DEFINITIONS = {
    "metadata": """
        CREATE TABLE metadata (
            key TEXT PRIMARY KEY NOT NULL,
            value TEXT NOT NULL
        ) WITHOUT ROWID
    """,
    "events": """
        CREATE TABLE events (
            seq INTEGER PRIMARY KEY,
            event_id TEXT NOT NULL UNIQUE,
            ts TEXT NOT NULL,
            type TEXT NOT NULL,
            subject TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            prev_digest TEXT NOT NULL,
            digest TEXT NOT NULL UNIQUE
        )
    """,
}
TRIGGER_DEFINITIONS = {
    "events_no_update": """
        CREATE TRIGGER events_no_update
        BEFORE UPDATE ON events
        BEGIN SELECT RAISE(ABORT, 'events are append-only'); END
    """,
    "events_no_delete": """
        CREATE TRIGGER events_no_delete
        BEFORE DELETE ON events
        BEGIN SELECT RAISE(ABORT, 'events are append-only'); END
    """,
    "metadata_no_update": """
        CREATE TRIGGER metadata_no_update
        BEFORE UPDATE ON metadata
        BEGIN SELECT RAISE(ABORT, 'metadata is immutable'); END
    """,
    "metadata_no_delete": """
        CREATE TRIGGER metadata_no_delete
        BEFORE DELETE ON metadata
        BEGIN SELECT RAISE(ABORT, 'metadata is immutable'); END
    """,
}


def _normalized_sql(value: str) -> str:
    return " ".join(value.split()).rstrip(";")


def _verify_schema_definitions(connection: sqlite3.Connection) -> None:
    tables = dict(connection.execute("SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name"))
    if set(tables) != set(TABLE_DEFINITIONS):
        raise CausalFrontierError("ledger table inventory differs from the registered schema")
    for name, expected in TABLE_DEFINITIONS.items():
        if _normalized_sql(tables[name]) != _normalized_sql(expected):
            raise CausalFrontierError("ledger table definition mismatch: %s" % name)
    triggers = dict(connection.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger' ORDER BY name"))
    if set(triggers) != set(TRIGGER_DEFINITIONS):
        raise CausalFrontierError("ledger append-only trigger inventory differs")
    for name, expected in TRIGGER_DEFINITIONS.items():
        if _normalized_sql(triggers[name]) != _normalized_sql(expected):
            raise CausalFrontierError("ledger trigger definition mismatch: %s" % name)


def _event_digest(previous: str, timestamp: str, event_type: str, subject: str, payload_json: str) -> str:
    material = "\n".join([previous, timestamp, event_type, subject, payload_json])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _validate_event(timestamp: str, event_type: str, subject: str, payload: Dict[str, Any]) -> str:
    timestamp = require_utc_timestamp(timestamp, "ledger event timestamp")
    if event_type not in EVENT_SCHEMAS:
        raise CausalFrontierError("unsupported ledger event type: %s" % event_type)
    subject = require_id(subject, "ledger event subject")
    if not isinstance(payload, dict) or set(payload) != EVENT_SCHEMAS[event_type]:
        raise CausalFrontierError("ledger event %s payload schema mismatch" % event_type)
    canonical = canonical_bytes(payload)
    read_json_bytes(canonical, "ledger payload")
    for key in (
        "case_sha256",
        "analysis_sha256",
        "run_id",
        "manifest_sha256",
        "predecessor_run_id",
        "branch_plan_sha256",
        "successor_run_id",
    ):
        if key in payload:
            require_sha256(payload[key], "ledger payload %s" % key)
    if event_type == "COUNTERFACTUAL_REHEARSAL":
        require_id(payload["experiment_id"], "ledger experiment_id")
        require_id(payload["outcome_id"], "ledger outcome_id")
        require_id_list(payload["predecessor_active_world_ids"], "ledger predecessor_active_world_ids", False)
        require_id_list(payload["successor_active_world_ids"], "ledger successor_active_world_ids", False)
        case_states = {"DECLARED_PARTITION_ACTIVE", "PARTITION_INVALIDATED_REQUIRES_NEW_CASE"}
        if payload["predecessor_case_state"] not in case_states or payload["successor_case_state"] not in case_states:
            raise CausalFrontierError("ledger rehearsal case state is invalid")
        if payload["status"] != "COUNTERFACTUAL_REHEARSAL_NOT_AN_OBSERVATION":
            raise CausalFrontierError("ledger cannot record a rehearsal as an observation")
    return canonical.decode("utf-8")


def _open_readonly(path: Path) -> sqlite3.Connection:
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
        raise CausalFrontierError("ledger must be a single-link regular file")
    try:
        connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise CausalFrontierError("cannot open ledger: %s" % exc) from exc
    connection.row_factory = sqlite3.Row
    return connection


def create_ledger(
    path: Path,
    case_id: str,
    frozen_at: str,
    case_sha256: str,
    analysis_sha256: str,
    run_id: str,
) -> Dict[str, Any]:
    """Create a new no-clobber ledger with one deterministic compile event."""

    path.parent.mkdir(parents=True, exist_ok=True)
    require_id(case_id, "case_id")
    require_sha256(case_sha256, "case_sha256")
    require_sha256(analysis_sha256, "analysis_sha256")
    require_sha256(run_id, "run_id")
    frozen_at = require_utc_timestamp(frozen_at, "ledger frozen_at")
    created_inode = None
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            created_inode = os.fstat(descriptor).st_ino
        finally:
            os.close(descriptor)
        connection = sqlite3.connect(path)
        try:
            connection.executescript(
                """
                PRAGMA journal_mode=DELETE;
                PRAGMA synchronous=FULL;
                CREATE TABLE metadata (
                    key TEXT PRIMARY KEY NOT NULL,
                    value TEXT NOT NULL
                ) WITHOUT ROWID;
                CREATE TABLE events (
                    seq INTEGER PRIMARY KEY,
                    event_id TEXT NOT NULL UNIQUE,
                    ts TEXT NOT NULL,
                    type TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    prev_digest TEXT NOT NULL,
                    digest TEXT NOT NULL UNIQUE
                );
                CREATE TRIGGER events_no_update
                BEFORE UPDATE ON events
                BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
                CREATE TRIGGER events_no_delete
                BEFORE DELETE ON events
                BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
                CREATE TRIGGER metadata_no_update
                BEFORE UPDATE ON metadata
                BEGIN SELECT RAISE(ABORT, 'metadata is immutable'); END;
                CREATE TRIGGER metadata_no_delete
                BEFORE DELETE ON metadata
                BEGIN SELECT RAISE(ABORT, 'metadata is immutable'); END;
                """
            )
            connection.execute("PRAGMA application_id=%d" % APPLICATION_ID)
            connection.execute("PRAGMA user_version=%d" % USER_VERSION)
            metadata = {
                "schema_version": "causalfrontier.ledger.v1",
                "case_id": case_id,
                "case_sha256": case_sha256,
                "initial_run_id": run_id,
                "created_at": frozen_at,
            }
            connection.executemany("INSERT INTO metadata(key,value) VALUES (?,?)", sorted(metadata.items()))
            payload = {
                "case_sha256": case_sha256,
                "analysis_sha256": analysis_sha256,
                "run_id": run_id,
            }
            payload_json = _validate_event(frozen_at, "CAPSULE_COMPILED", case_id, payload)
            digest = _event_digest(GENESIS, frozen_at, "CAPSULE_COMPILED", case_id, payload_json)
            connection.execute(
                """INSERT INTO events(
                       seq,event_id,ts,type,subject,payload_json,prev_digest,digest
                   ) VALUES (1,?,?,?,?,?,?,?)""",
                (
                    digest[:16],
                    frozen_at,
                    "CAPSULE_COMPILED",
                    case_id,
                    payload_json,
                    GENESIS,
                    digest,
                ),
            )
            connection.commit()
        finally:
            connection.close()
    except FileExistsError as exc:
        raise CausalFrontierError("refusing to overwrite ledger: %s" % path.name) from exc
    except (CausalFrontierError, sqlite3.Error, OSError) as exc:
        if (
            created_inode is not None
            and path.exists()
            and path.is_file()
            and not path.is_symlink()
            and path.stat().st_ino == created_inode
        ):
            path.unlink()
        if isinstance(exc, CausalFrontierError):
            raise
        raise CausalFrontierError("cannot create ledger: %s" % exc) from exc
    return verify_ledger(path)


def append_event(
    path: Path,
    timestamp: str,
    event_type: str,
    subject: str,
    payload: Dict[str, Any],
    expected_head: str,
) -> Dict[str, Any]:
    """Append one validated event using a required external compare-and-swap checkpoint."""

    if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
        raise CausalFrontierError("ledger must be a single-link regular file")
    if event_type == "CAPSULE_COMPILED":
        raise CausalFrontierError("CAPSULE_COMPILED is reserved for ledger genesis")
    expected_head = require_sha256(expected_head, "expected ledger head")
    payload_json = _validate_event(timestamp, event_type, subject, payload)
    try:
        connection = sqlite3.connect(path)
        try:
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID:
                raise CausalFrontierError("ledger application_id mismatch")
            if connection.execute("PRAGMA user_version").fetchone()[0] != USER_VERSION:
                raise CausalFrontierError("ledger user_version mismatch")
            _verify_schema_definitions(connection)
            metadata_case = connection.execute("SELECT value FROM metadata WHERE key='case_id'").fetchone()
            if metadata_case is None or subject != metadata_case[0]:
                raise CausalFrontierError("ledger event subject differs from ledger case")
            row = connection.execute("SELECT seq,digest,ts FROM events ORDER BY seq DESC LIMIT 1").fetchone()
            if row is None:
                raise CausalFrontierError("ledger has no genesis compile event")
            previous = row[1]
            if previous != expected_head:
                raise CausalFrontierError("ledger head changed before append")
            if timestamp < row[2]:
                raise CausalFrontierError("ledger event timestamp precedes the current head")
            sequence = row[0] + 1
            digest = _event_digest(previous, timestamp, event_type, subject, payload_json)
            connection.execute(
                """INSERT INTO events(
                       seq,event_id,ts,type,subject,payload_json,prev_digest,digest
                   ) VALUES (?,?,?,?,?,?,?,?)""",
                (
                    sequence,
                    digest[:16],
                    timestamp,
                    event_type,
                    subject,
                    payload_json,
                    previous,
                    digest,
                ),
            )
            connection.commit()
        finally:
            connection.close()
    except CausalFrontierError:
        raise
    except sqlite3.Error as exc:
        raise CausalFrontierError("cannot append ledger event: %s" % exc) from exc
    return verify_ledger(path)


def verify_ledger(path: Path) -> Dict[str, Any]:
    """Verify schema, triggers, digest chain, event schemas, and replay projection."""

    result: Dict[str, Any] = {
        "schema_version": "causalfrontier.ledger-verification.v1",
        "state": "INVALID",
        "events": 0,
        "head_digest": GENESIS,
        "logical_state_sha256": None,
        "genesis_head_digest": None,
        "genesis_logical_state_sha256": None,
    }
    try:
        connection = _open_readonly(path)
        try:
            if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise CausalFrontierError("ledger integrity_check failed")
            if connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID:
                raise CausalFrontierError("ledger application_id mismatch")
            if connection.execute("PRAGMA user_version").fetchone()[0] != USER_VERSION:
                raise CausalFrontierError("ledger user_version mismatch")
            _verify_schema_definitions(connection)
            metadata = dict(connection.execute("SELECT key,value FROM metadata ORDER BY key"))
            required_metadata = {
                "schema_version",
                "case_id",
                "case_sha256",
                "initial_run_id",
                "created_at",
            }
            if set(metadata) != required_metadata:
                raise CausalFrontierError("ledger metadata schema mismatch")
            if metadata["schema_version"] != "causalfrontier.ledger.v1":
                raise CausalFrontierError("ledger schema version mismatch")
            require_id(metadata["case_id"], "ledger case_id")
            require_sha256(metadata["case_sha256"], "ledger case_sha256")
            require_sha256(metadata["initial_run_id"], "ledger initial_run_id")
            require_utc_timestamp(metadata["created_at"], "ledger created_at")
            previous = GENESIS
            previous_timestamp = None
            expected_sequence = 1
            genesis_head = None
            genesis_logical_state_sha256 = None
            replay = {
                "event_counts": {},
                "rehearsals": [],
                "verifications": [],
                "initial_compile": None,
            }
            for row in connection.execute("SELECT * FROM events ORDER BY seq"):
                if row["seq"] != expected_sequence:
                    raise CausalFrontierError("ledger sequence is not contiguous")
                payload = read_json_bytes(row["payload_json"].encode("utf-8"), "ledger payload")
                canonical = _validate_event(row["ts"], row["type"], row["subject"], payload)
                if canonical != row["payload_json"]:
                    raise CausalFrontierError("ledger payload is not canonical")
                digest = _event_digest(previous, row["ts"], row["type"], row["subject"], canonical)
                if row["prev_digest"] != previous or row["digest"] != digest:
                    raise CausalFrontierError("ledger digest chain is broken")
                if row["event_id"] != digest[:16]:
                    raise CausalFrontierError("ledger event_id is invalid")
                if row["subject"] != metadata["case_id"]:
                    raise CausalFrontierError("ledger event subject differs from ledger case")
                if previous_timestamp is not None and row["ts"] < previous_timestamp:
                    raise CausalFrontierError("ledger timestamps are not monotonic")
                if expected_sequence == 1:
                    if row["type"] != "CAPSULE_COMPILED":
                        raise CausalFrontierError("first ledger event is not CAPSULE_COMPILED")
                    if payload["case_sha256"] != metadata["case_sha256"]:
                        raise CausalFrontierError("compile event case digest differs from metadata")
                    if payload["run_id"] != metadata["initial_run_id"]:
                        raise CausalFrontierError("compile event run differs from metadata")
                    if row["ts"] != metadata["created_at"]:
                        raise CausalFrontierError("compile event timestamp differs from metadata")
                    replay["initial_compile"] = payload
                    genesis_head = digest
                    genesis_replay = {
                        "event_counts": {"CAPSULE_COMPILED": 1},
                        "rehearsals": [],
                        "verifications": [],
                        "initial_compile": payload,
                    }
                    genesis_logical_state = {
                        "metadata": metadata,
                        "replay": genesis_replay,
                        "head_digest": digest,
                    }
                    genesis_logical_state_sha256 = hashlib.sha256(canonical_bytes(genesis_logical_state)).hexdigest()
                elif row["type"] == "CAPSULE_COMPILED":
                    raise CausalFrontierError("CAPSULE_COMPILED may appear only at ledger genesis")
                replay["event_counts"][row["type"]] = replay["event_counts"].get(row["type"], 0) + 1
                if row["type"] == "COUNTERFACTUAL_REHEARSAL":
                    replay["rehearsals"].append(payload)
                elif row["type"] == "CAPSULE_VERIFIED":
                    replay["verifications"].append(payload)
                previous = digest
                previous_timestamp = row["ts"]
                expected_sequence += 1
            if expected_sequence == 1:
                raise CausalFrontierError("ledger is empty")
            replay["event_counts"] = dict(sorted(replay["event_counts"].items()))
            logical_state = {"metadata": metadata, "replay": replay, "head_digest": previous}
            result.update(
                {
                    "state": "VERIFIED",
                    "events": expected_sequence - 1,
                    "head_digest": previous,
                    "logical_state_sha256": hashlib.sha256(canonical_bytes(logical_state)).hexdigest(),
                    "genesis_head_digest": genesis_head,
                    "genesis_logical_state_sha256": genesis_logical_state_sha256,
                    "metadata": metadata,
                    "replay": replay,
                }
            )
        finally:
            connection.close()
    except (CausalFrontierError, sqlite3.Error, OSError, json.JSONDecodeError) as exc:
        result["error"] = str(exc)
    return result
