#!/usr/bin/env python3
"""
Local-only Password Manager (MVP)
- Encrypted single-file vault (AES-GCM via cryptography)
- Key derived from master password using scrypt
- Folder-style organization via `folder` path strings (e.g., "Banks/Chase")
- Add, list, view, edit, duplicate, delete entries
- Notes + URL field
- No network usage; all data local

Usage examples:
  python passmgr.py init vault.pm
  python passmgr.py add vault.pm --folder "Games/Steam" --title Steam --username me --password "..." --url https://store.steampowered.com --note "2FA on"
  python passmgr.py list vault.pm --folder "Games"
  python passmgr.py view vault.pm --id <uuid>
  python passmgr.py edit vault.pm --id <uuid> --password NEWPASS
  python passmgr.py dup vault.pm --id <uuid> --folder "Games/Epic"
  python passmgr.py change-master vault.pm

Tip: use environment variable PASSMGR_PASS to avoid interactive prompts in scripts.
"""

from __future__ import annotations
import argparse
import getpass
import json
import os
import sys
import time
import uuid
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional

try:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception as e:
    print("This script requires the 'cryptography' package.\nInstall: pip install cryptography", file=sys.stderr)
    raise

VAULT_VERSION = 1
MAGIC = b"PMV1"  # file magic/version tag
SALT_LEN = 16
NONCE_LEN = 12

@dataclass
class Entry:
    id: str
    title: str
    username: str
    password: str
    note: str = ""
    url: str = ""
    folder: str = ""  # e.g., "Banks/Chase"
    created_at: float = 0.0
    updated_at: float = 0.0


def now_ts() -> float:
    return time.time()


def _kdf_scrypt(password: str, salt: bytes) -> bytes:
    # Parameters chosen for decent security on modern machines; tune to your hardware.
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))


def _derive_key(password: str, salt: bytes) -> bytes:
    return _kdf_scrypt(password, salt)


def _encrypt(password: str, plaintext: bytes) -> bytes:
    salt = os.urandom(SALT_LEN)
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    ct = aes.encrypt(nonce, plaintext, associated_data=MAGIC)
    return MAGIC + salt + nonce + ct


def _decrypt(password: str, blob: bytes) -> bytes:
    if not blob.startswith(MAGIC):
        raise ValueError("Invalid vault file (bad magic)")
    salt = blob[4:4+SALT_LEN]
    nonce = blob[4+SALT_LEN:4+SALT_LEN+NONCE_LEN]
    ct = blob[4+SALT_LEN+NONCE_LEN:]
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, associated_data=MAGIC)


def _prompt_password(prompt: str = "Master password: ") -> str:
    env = os.getenv("PASSMGR_PASS")
    if env:
        return env
    return getpass.getpass(prompt)


def load_vault(path: str, password: Optional[str] = None) -> Dict[str, Any]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Vault not found: {path}")
    if password is None:
        password = _prompt_password("Master password: ")
    with open(path, "rb") as f:
        blob = f.read()
    data = json.loads(_decrypt(password, blob).decode("utf-8"))
    if data.get("version") != VAULT_VERSION:
        raise ValueError("Unsupported vault version")
    data["_password"] = password  # keep in-memory for save
    return data


def save_vault(path: str, vault: Dict[str, Any]) -> None:
    password = vault.get("_password")
    if not password:
        raise ValueError("Vault missing in-memory password; can't save")
    payload = json.dumps({k: v for k, v in vault.items() if k != "_password"}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    blob = _encrypt(password, payload)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(blob)
    os.replace(tmp, path)


def init_vault(path: str, password: Optional[str]) -> None:
    if os.path.exists(path):
        raise FileExistsError(f"Refusing to overwrite existing file: {path}")
    if password is None:
        pw1 = _prompt_password("Create master password: ")
        pw2 = _prompt_password("Confirm master password: ")
        if pw1 != pw2:
            print("Passwords do not match", file=sys.stderr)
            sys.exit(1)
        password = pw1
    vault = {
        "version": VAULT_VERSION,
        "created_at": now_ts(),
        "updated_at": now_ts(),
        "entries": [],  # list[Entry as dict]
    }
    vault["_password"] = password
    save_vault(path, vault)
    print(f"Initialized vault at {path}")


def list_entries(vault: Dict[str, Any], folder_prefix: Optional[str]) -> List[Entry]:
    entries = [Entry(**e) for e in vault.get("entries", [])]
    if folder_prefix:
        folder_prefix = folder_prefix.strip("/")
        entries = [e for e in entries if e.folder.strip("/").startswith(folder_prefix)]
    return entries


def add_entry(vault: Dict[str, Any], **kwargs) -> Entry:
    e = Entry(
        id=str(uuid.uuid4()),
        title=kwargs.get("title", ""),
        username=kwargs.get("username", ""),
        password=kwargs.get("password", ""),
        note=kwargs.get("note", ""),
        url=kwargs.get("url", ""),
        folder=kwargs.get("folder", ""),
        created_at=now_ts(),
        updated_at=now_ts(),
    )
    vault.setdefault("entries", []).append(asdict(e))
    vault["updated_at"] = now_ts()
    return e


def get_entry(vault: Dict[str, Any], entry_id: str) -> Entry:
    for e in vault.get("entries", []):
        if e["id"] == entry_id:
            return Entry(**e)
    raise KeyError(f"Entry not found: {entry_id}")


def replace_entry(vault: Dict[str, Any], entry: Entry) -> None:
    for i, e in enumerate(vault.get("entries", [])):
        if e["id"] == entry.id:
            vault["entries"][i] = asdict(entry)
            vault["updated_at"] = now_ts()
            return
    raise KeyError(f"Entry not found: {entry.id}")


def delete_entry(vault: Dict[str, Any], entry_id: str) -> None:
    before = len(vault.get("entries", []))
    vault["entries"] = [e for e in vault.get("entries", []) if e["id"] != entry_id]
    if len(vault["entries"]) == before:
        raise KeyError(f"Entry not found: {entry_id}")
    vault["updated_at"] = now_ts()


def change_master_password(path: str, vault: Dict[str, Any]) -> None:
    pw1 = _prompt_password("New master password: ")
    pw2 = _prompt_password("Confirm new master password: ")
    if pw1 != pw2:
        print("Passwords do not match", file=sys.stderr)
        sys.exit(1)
    vault["_password"] = pw1
    save_vault(path, vault)
    print("Master password updated.")


def pretty_entry(e: Entry, show_secret: bool = False) -> str:
    # Avoid leaking passwords by default
    pwd = e.password if show_secret else "••••••••"
    return (
        f"id: {e.id}\n"
        f"title: {e.title}\n"
        f"folder: {e.folder}\n"
        f"username: {e.username}\n"
        f"password: {pwd}\n"
        f"url: {e.url}\n"
        f"note: {e.note}\n"
        f"created: {time.ctime(e.created_at)}\n"
        f"updated: {time.ctime(e.updated_at)}\n"
    )


def cmd_init(args):
    init_vault(args.vault, args.password)


def cmd_add(args):
    v = load_vault(args.vault, args.password)
    e = add_entry(v, title=args.title, username=args.username, password=args.password_entry or "", note=args.note or "", url=args.url or "", folder=args.folder or "")
    save_vault(args.vault, v)
    print("Added entry:\n" + pretty_entry(e))


def cmd_list(args):
    v = load_vault(args.vault, args.password)
    entries = list_entries(v, args.folder)
    if not entries:
        print("(no entries)")
        return
    for e in entries:
        print(f"[{e.folder}] {e.title}  id={e.id}")


def cmd_view(args):
    v = load_vault(args.vault, args.password)
    e = get_entry(v, args.id)
    print(pretty_entry(e, show_secret=args.show_password))


def cmd_edit(args):
    v = load_vault(args.vault, args.password)
    e = get_entry(v, args.id)
    # Only update provided fields
    if args.title is not None: e.title = args.title
    if args.username is not None: e.username = args.username
    if args.password_entry is not None: e.password = args.password_entry
    if args.note is not None: e.note = args.note
    if args.url is not None: e.url = args.url
    if args.folder is not None: e.folder = args.folder
    e.updated_at = now_ts()
    replace_entry(v, e)
    save_vault(args.vault, v)
    print("Updated entry:\n" + pretty_entry(e))


def cmd_dup(args):
    v = load_vault(args.vault, args.password)
    src = get_entry(v, args.id)
    folder = args.folder if args.folder is not None else src.folder
    e = add_entry(v, title=src.title, username=src.username, password=src.password, note=src.note, url=src.url, folder=folder)
    save_vault(args.vault, v)
    print("Duplicated entry as:\n" + pretty_entry(e))


def cmd_del(args):
    v = load_vault(args.vault, args.password)
    delete_entry(v, args.id)
    save_vault(args.vault, v)
    print("Deleted.")


def cmd_change_master(args):
    v = load_vault(args.vault, args.password)
    change_master_password(args.vault, v)


def cmd_export_json(args):
    v = load_vault(args.vault, args.password)
    # Strip in-memory password
    data = {k: v[k] for k in v.keys() if k != "_password"}
    if args.out == "-":
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"Exported to {args.out} (unencrypted!)")


def cmd_import_json(args):
    # Import into an existing vault file (replaces entries only)
    v = load_vault(args.vault, args.password)
    with open(args.src, "r", encoding="utf-8") as f:
        data = json.load(f)
    if data.get("version") != VAULT_VERSION:
        print("Mismatched version; aborting.", file=sys.stderr)
        sys.exit(1)
    v["entries"] = data.get("entries", [])
    v["updated_at"] = now_ts()
    save_vault(args.vault, v)
    print("Imported entries.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="passmgr", description="Local-only password manager (single-file, encrypted)")
    sub = p.add_subparsers(dest="cmd", required=True)

    # Common vault path arg helper
    def add_vault_arg(sp: argparse.ArgumentParser):
        sp.add_argument("vault", help="Path to vault file (e.g., my.vault)")
        sp.add_argument("--password", dest="password", help="Master password (discouraged; prefer prompt or PASSMGR_PASS)")

    # init
    sp = sub.add_parser("init", help="Create a new vault")
    add_vault_arg(sp)
    sp.set_defaults(func=cmd_init)

    # add
    sp = sub.add_parser("add", help="Add an entry")
    add_vault_arg(sp)
    sp.add_argument("--folder", default="", help="Folder path, e.g., 'Banks/Chase'")
    sp.add_argument("--title", required=True)
    sp.add_argument("--username", required=True)
    sp.add_argument("--password-entry", dest="password_entry", help="Password for the entry")
    sp.add_argument("--note")
    sp.add_argument("--url")
    sp.set_defaults(func=cmd_add)

    # list
    sp = sub.add_parser("list", help="List entries (optionally limit to folder prefix)")
    add_vault_arg(sp)
    sp.add_argument("--folder", help="Folder prefix to filter by")
    sp.set_defaults(func=cmd_list)

    # view
    sp = sub.add_parser("view", help="View one entry")
    add_vault_arg(sp)
    sp.add_argument("--id", required=True)
    sp.add_argument("--show-password", action="store_true")
    sp.set_defaults(func=cmd_view)

    # edit
    sp = sub.add_parser("edit", help="Edit fields on an entry")
    add_vault_arg(sp)
    sp.add_argument("--id", required=True)
    sp.add_argument("--folder")
    sp.add_argument("--title")
    sp.add_argument("--username")
    sp.add_argument("--password-entry", dest="password_entry")
    sp.add_argument("--note")
    sp.add_argument("--url")
    sp.set_defaults(func=cmd_edit)

    # duplicate
    sp = sub.add_parser("dup", help="Duplicate an entry (optionally to a new folder)")
    add_vault_arg(sp)
    sp.add_argument("--id", required=True)
    sp.add_argument("--folder", help="Override destination folder")
    sp.set_defaults(func=cmd_dup)

    # delete
    sp = sub.add_parser("del", help="Delete an entry")
    add_vault_arg(sp)
    sp.add_argument("--id", required=True)
    sp.set_defaults(func=cmd_del)

    # change-master
    sp = sub.add_parser("change-master", help="Change the master password")
    add_vault_arg(sp)
    sp.set_defaults(func=cmd_change_master)

    # export (plaintext JSON!)
    sp = sub.add_parser("export-json", help="Export decrypted JSON (for backup/migration). WARNING: plaintext file!")
    add_vault_arg(sp)
    sp.add_argument("--out", required=True, help="Output path or '-' for stdout")
    sp.set_defaults(func=cmd_export_json)

    # import (from plaintext JSON)
    sp = sub.add_parser("import-json", help="Replace entries from a JSON export")
    add_vault_arg(sp)
    sp.add_argument("--src", required=True, help="Path to exported JSON")
    sp.set_defaults(func=cmd_import_json)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
        return 0
    except KeyboardInterrupt:
        print("Aborted.", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
