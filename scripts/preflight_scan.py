#!/usr/bin/env python3
"""Fail-closed, redacted local preflight scan for files intended for cloud upload."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import asdict, dataclass
from datetime import date
from pathlib import Path, PurePosixPath
from typing import Iterable


KNOWN_SECRET_PATTERNS = (
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("alibaba_access_key", re.compile(r"\bLTAI[A-Za-z0-9]{16,24}\b")),
    ("tencent_secret_id", re.compile(r"\bAKID[A-Za-z0-9]{30,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("stripe_secret", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("google_api_key", re.compile(r"\bAIza[A-Za-z0-9_-]{30,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("credential_url", re.compile(r"\b(?:https?|postgres(?:ql)?|mysql)://[^/\s:@]+:[^@\s/]+@", re.I)),
)

GENERIC_SECRET = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?key|secret(?:[_-]?key)?|token|password|passwd|pwd|auth[_-]?code|smtp[_-]?(?:code|password))\b"
    r"\s*[:=]\s*[\"']?([^\s\"'`,;}{]{8,})"
)
EMAIL = re.compile(r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![A-Za-z0-9._%+-])")
PHONE_CN = re.compile(r"(?<![A-Za-z0-9])1[3-9]\d{9}(?![A-Za-z0-9])")
ID_CN = re.compile(r"(?<!\d)(\d{17}[\dXx])(?!\d)")
WINDOWS_USER_PATH = re.compile(r"(?i)\b[A-Z]:\\Users\\([^\\/\r\n]+)")
BUSINESS_DATA = re.compile(
    r"(?i)(?:cost|quantity|shares|costPrice|cost_price|stopLoss|stop_loss|targetPrice|target_price|takeProfit|take_profit|"
    r"持仓成本|成本价|止损价|目标价)\s*[:=]\s*[\"']?\d+(?:\.\d+)?"
)

PROVINCE_PREFIXES = {
    "11", "12", "13", "14", "15", "21", "22", "23", "31", "32", "33", "34", "35", "36",
    "37", "41", "42", "43", "44", "45", "46", "50", "51", "52", "53", "54", "61", "62", "63",
    "64", "65", "71", "81", "82", "91",
}
ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
ID_CHECK = "10X98765432"

SENSITIVE_EXACT = {
    ".env", ".npmrc", ".pypirc", ".netrc", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "credentials.json", "service-account.json", "login data", "cookies.sqlite",
}
SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".sqlite", ".db", ".bak", ".backup", ".dump")
OPAQUE_SUFFIXES = {
    ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".tiff", ".bmp", ".heic", ".mp3", ".wav",
    ".mp4", ".mov", ".avi", ".sqlite", ".db", ".parquet", ".exe", ".dll", ".so", ".class",
}
PLACEHOLDER_MARKERS = (
    "example", "placeholder", "changeme", "change_me", "your_", "replace_me", "redacted", "dummy",
    "not-a-real", "not_real", "xxxxx", "*****", "${", "{{", "process.env", "os.getenv", "secrets.",
)


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    path: str
    location: str
    fingerprint: str


class ScanState:
    def __init__(self, max_file_bytes: int, max_archive_bytes: int, max_files: int) -> None:
        self.max_file_bytes = max_file_bytes
        self.max_archive_bytes = max_archive_bytes
        self.max_files = max_files
        self.file_count = 0
        self.total_bytes = 0
        self.findings: list[Finding] = []
        self._seen: set[tuple[str, str, str, str]] = set()
        self.coverage_notes = ["Git object databases are excluded; inspect all reachable history separately when applicable."]

    def add(self, rule: str, severity: str, path: str, location: str, matched: str | bytes) -> None:
        raw = matched.encode("utf-8", "surrogatepass") if isinstance(matched, str) else matched
        fingerprint = "sha256:" + hashlib.sha256(raw).hexdigest()[:12]
        key = (rule, path, location, fingerprint)
        if key not in self._seen:
            self._seen.add(key)
            self.findings.append(Finding(rule, severity, path, location, fingerprint))


def is_placeholder(value: str) -> bool:
    lowered = value.strip().strip("\"'").lower()
    return not lowered or any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def valid_chinese_id(value: str) -> bool:
    value = value.upper()
    if len(value) != 18 or value[:2] not in PROVINCE_PREFIXES or value[:6] == "000000":
        return False
    try:
        date(int(value[6:10]), int(value[10:12]), int(value[12:14]))
    except ValueError:
        return False
    expected = ID_CHECK[sum(int(n) * weight for n, weight in zip(value[:17], ID_WEIGHTS)) % 11]
    return value[-1] == expected


def line_location(text: str, offset: int) -> str:
    return f"line:{text.count(chr(10), 0, offset) + 1}"


def scan_text(text: str, logical_path: str, state: ScanState) -> None:
    for rule, pattern in KNOWN_SECRET_PATTERNS:
        for match in pattern.finditer(text):
            state.add(rule, "P0", logical_path, line_location(text, match.start()), match.group(0))

    for match in GENERIC_SECRET.finditer(text):
        value = match.group(2)
        if not is_placeholder(value):
            state.add("literal_credential", "P0", logical_path, line_location(text, match.start()), value)

    for match in EMAIL.finditer(text):
        state.add("email_address", "P2", logical_path, line_location(text, match.start()), match.group(1).lower())
    for match in PHONE_CN.finditer(text):
        state.add("china_mobile_number", "P1", logical_path, line_location(text, match.start()), match.group(0))
    for match in ID_CN.finditer(text):
        if valid_chinese_id(match.group(1)):
            state.add("valid_chinese_id", "P1", logical_path, line_location(text, match.start()), match.group(1).upper())
    for match in WINDOWS_USER_PATH.finditer(text):
        state.add("local_user_path", "P2", logical_path, line_location(text, match.start()), match.group(0))
    for match in BUSINESS_DATA.finditer(text):
        state.add("portfolio_or_strategy_data", "P1", logical_path, line_location(text, match.start()), match.group(0))


def sensitive_filename(name: str) -> bool:
    lowered = name.lower()
    if lowered in SENSITIVE_EXACT:
        return True
    if lowered.startswith(".env.") and lowered not in {".env.example", ".env.sample", ".env.template"}:
        return True
    if lowered.startswith("secret") or lowered.startswith("credential"):
        return True
    return lowered.endswith(SENSITIVE_SUFFIXES)


def unsafe_archive_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    pure = PurePosixPath(normalized)
    return pure.is_absolute() or ".." in pure.parts


def printable_strings(data: bytes) -> str:
    ascii_parts = re.findall(rb"[\x20-\x7e]{6,}", data)
    utf16_parts = re.findall(rb"(?:[\x20-\x7e]\x00){6,}", data)
    decoded = [part.decode("ascii", "ignore") for part in ascii_parts]
    decoded.extend(part.decode("utf-16le", "ignore") for part in utf16_parts)
    return "\n".join(decoded)


def scan_archive(data: bytes, logical_path: str, state: ScanState, depth: int) -> bool:
    if depth >= 4:
        state.add("coverage_gap_nested_archive", "P1", logical_path, "archive", logical_path)
        return True

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) > state.max_files:
                state.add("coverage_gap_archive_entry_limit", "P1", logical_path, "archive", str(len(infos)))
                return True
            total = sum(info.file_size for info in infos)
            if total > state.max_archive_bytes:
                state.add("coverage_gap_archive_size_limit", "P1", logical_path, "archive", str(total))
                return True
            for info in infos:
                member_path = f"{logical_path}!/{info.filename}"
                if info.is_dir():
                    continue
                if unsafe_archive_name(info.filename):
                    state.add("archive_path_traversal", "P1", member_path, "archive-member", info.filename)
                if info.flag_bits & 1:
                    state.add("coverage_gap_encrypted_archive", "P1", member_path, "archive-member", info.filename)
                    continue
                if info.file_size > 1_000_000 and info.file_size / max(info.compress_size, 1) > 200:
                    state.add("archive_decompression_bomb", "P1", member_path, "archive-member", str(info.file_size))
                    continue
                if sensitive_filename(PurePosixPath(info.filename).name):
                    state.add("sensitive_filename", "P1", member_path, "archive-member", info.filename)
                try:
                    member = archive.read(info)
                except (RuntimeError, OSError, zipfile.BadZipFile) as exc:
                    state.add("coverage_gap_unreadable_archive_member", "P1", member_path, "archive-member", type(exc).__name__)
                    continue
                scan_bytes(member, member_path, state, depth + 1)
            return True
    except zipfile.BadZipFile:
        pass

    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            members = archive.getmembers()
            if len(members) > state.max_files:
                state.add("coverage_gap_archive_entry_limit", "P1", logical_path, "archive", str(len(members)))
                return True
            total = sum(member.size for member in members if member.isfile())
            if total > state.max_archive_bytes:
                state.add("coverage_gap_archive_size_limit", "P1", logical_path, "archive", str(total))
                return True
            for member in members:
                member_path = f"{logical_path}!/{member.name}"
                if member.issym() or member.islnk() or unsafe_archive_name(member.name):
                    state.add("archive_link_or_path_traversal", "P1", member_path, "archive-member", member.name)
                if not member.isfile():
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    state.add("coverage_gap_unreadable_archive_member", "P1", member_path, "archive-member", member.name)
                    continue
                scan_bytes(handle.read(), member_path, state, depth + 1)
            return True
    except (tarfile.TarError, EOFError, OSError):
        return False


def scan_bytes(data: bytes, logical_path: str, state: ScanState, depth: int = 0) -> None:
    if scan_archive(data, logical_path, state, depth):
        return

    suffix = Path(logical_path.split("!/")[-1]).suffix.lower()
    sample = data[:8192]
    binary = b"\x00" in sample or (sample and sum(byte in b"\t\n\r" or 32 <= byte < 127 for byte in sample) / len(sample) < 0.55)
    if binary:
        extracted = printable_strings(data)
        if extracted:
            scan_text(extracted, logical_path, state)
        if suffix in OPAQUE_SUFFIXES or not extracted:
            state.add("coverage_gap_opaque_binary", "P1", logical_path, "binary", suffix or "unknown")
        return

    text = data.decode("utf-8-sig", "replace")
    if text and text.count("\ufffd") / len(text) > 0.02:
        state.add("coverage_gap_text_decoding", "P1", logical_path, "encoding", logical_path)
    scan_text(text, logical_path, state)


def iter_input_files(paths: Iterable[Path], state: ScanState) -> Iterable[tuple[Path, str]]:
    for root in paths:
        label = root.name or "."
        if not root.exists() and not root.is_symlink():
            state.add("coverage_gap_missing_input", "P1", label, "input", label)
            continue
        if root.is_symlink():
            state.add("symlink_requires_target_review", "P1", label, "input", label)
            continue
        if root.is_file():
            yield root, label
            continue
        for item in root.rglob("*"):
            try:
                relative = item.relative_to(root)
            except ValueError:
                relative = Path(item.name)
            if ".git" in relative.parts:
                continue
            logical = f"{label}/{relative.as_posix()}"
            if item.is_symlink():
                state.add("symlink_requires_target_review", "P1", logical, "filesystem", logical)
            elif item.is_file():
                yield item, logical


def scan(paths: list[Path], max_file_bytes: int, max_archive_bytes: int, max_files: int) -> tuple[dict, int]:
    state = ScanState(max_file_bytes, max_archive_bytes, max_files)
    for path, logical in iter_input_files(paths, state):
        state.file_count += 1
        if state.file_count > state.max_files:
            state.add("coverage_gap_file_count_limit", "P1", logical, "filesystem", str(state.file_count))
            break
        try:
            size = path.stat().st_size
        except OSError as exc:
            state.add("coverage_gap_unreadable_file", "P1", logical, "filesystem", type(exc).__name__)
            continue
        state.total_bytes += size
        if sensitive_filename(path.name):
            state.add("sensitive_filename", "P1", logical, "filename", path.name)
        if size > state.max_file_bytes:
            state.add("coverage_gap_file_size_limit", "P1", logical, "filesystem", str(size))
            continue
        try:
            scan_bytes(path.read_bytes(), logical, state)
        except OSError as exc:
            state.add("coverage_gap_unreadable_file", "P1", logical, "filesystem", type(exc).__name__)

    findings = sorted(state.findings, key=lambda f: (f.severity, f.path, f.location, f.rule, f.fingerprint))
    incomplete = any(f.rule.startswith("coverage_gap") for f in findings)
    code = 2 if incomplete else (1 if findings else 0)
    report = {
        "schema_version": 1,
        "verdict": "PASS" if code == 0 else "BLOCK",
        "exit_code": code,
        "coverage_complete": not incomplete,
        "files_scanned": state.file_count,
        "bytes_scanned": state.total_bytes,
        "findings_count": len(findings),
        "findings": [asdict(f) for f in findings],
        "coverage_notes": state.coverage_notes,
    }
    return report, code


def run_self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="cloud-upload-review-") as temp:
        base = Path(temp)
        safe = base / "safe"
        danger = base / "danger"
        opaque = base / "opaque"
        safe.mkdir()
        danger.mkdir()
        opaque.mkdir()
        (safe / "README.txt").write_text("Public documentation without credentials.\n", encoding="utf-8")

        fake_secret = "sk-" + ("A" * 32)
        email = "person" + "@" + "private.invalid"
        id_base = "110105" + "1949" + "1231" + "002"
        check = ID_CHECK[sum(int(n) * weight for n, weight in zip(id_base, ID_WEIGHTS)) % 11]
        fake_id = id_base + check
        (danger / ".env").write_text(f"API_KEY={fake_secret}\nOWNER={email}\nID={fake_id}\n", encoding="utf-8")
        with zipfile.ZipFile(danger / "nested.zip", "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("config.txt", f"token={fake_secret}")
        (opaque / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00opaque-test")

        safe_report, safe_code = scan([safe], 2_000_000, 10_000_000, 1000)
        danger_report, danger_code = scan([danger], 2_000_000, 10_000_000, 1000)
        opaque_report, opaque_code = scan([opaque], 2_000_000, 10_000_000, 1000)
        missing_report, missing_code = scan([base / "missing"], 2_000_000, 10_000_000, 1000)
        serialized = json.dumps(danger_report, ensure_ascii=False)
        assert safe_code == 0 and safe_report["verdict"] == "PASS"
        assert danger_code == 1 and danger_report["verdict"] == "BLOCK"
        assert opaque_code == 2 and not opaque_report["coverage_complete"]
        assert missing_code == 2 and not missing_report["coverage_complete"]
        assert {"openai_key", "email_address", "valid_chinese_id", "sensitive_filename"}.issubset(
            {finding["rule"] for finding in danger_report["findings"]}
        )
        assert fake_secret not in serialized and email not in serialized and fake_id not in serialized
    print("PASS: self-test covered safe, secret, PII, archive, redaction, opaque-binary, and missing-input cases")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Redacted, fail-closed preflight scan before cloud upload.")
    parser.add_argument("paths", nargs="*", type=Path, help="Files or directories in the exact upload manifest")
    parser.add_argument("--json", action="store_true", help="Emit structured JSON")
    parser.add_argument("--max-file-bytes", type=int, default=32 * 1024 * 1024)
    parser.add_argument("--max-archive-bytes", type=int, default=512 * 1024 * 1024)
    parser.add_argument("--max-files", type=int, default=50_000)
    parser.add_argument("--self-test", action="store_true", help="Run built-in deterministic tests")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        return run_self_test()
    if not args.paths:
        print("ERROR: at least one path is required", file=sys.stderr)
        return 2
    report, code = scan(args.paths, args.max_file_bytes, args.max_archive_bytes, args.max_files)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f"{report['verdict']}: files={report['files_scanned']} findings={report['findings_count']} coverage_complete={report['coverage_complete']}")
        for finding in report["findings"]:
            print(
                f"{finding['severity']} rule={finding['rule']} path={finding['path']} "
                f"location={finding['location']} fingerprint={finding['fingerprint']}"
            )
    return code


if __name__ == "__main__":
    raise SystemExit(main())
