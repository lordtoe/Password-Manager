#!/usr/bin/env python3
"""
passmgr_gui.py — Local Password Manager GUI (Tkinter)

Requirements:
  pip install cryptography

Usage:
  python passmgr_gui.py path/to/vault.pm

Notes:
- This GUI uses the CLI module 'passmgr.py' placed in the same folder.
- Tree on the left groups entries by folder path (e.g., Banks/Chase).
- Right pane edits/view details: title, username, password (toggle), URL, note.
- Buttons: New Entry, New Folder (virtual), Save, Duplicate, Delete, Copy U/P, Open URL, Change Master.
- 100% offline; same AES-GCM+scrypt vault as the CLI.

Tip: set PASSMGR_PASS env var to skip master password prompt at start.
"""
from __future__ import annotations
import os
import sys
import webbrowser
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from typing import Dict, List, Tuple

# --- import core vault logic from passmgr.py ---
try:
    import passmgr  # the CLI/core from the companion file
except Exception as e:
    raise SystemExit("Place passmgr.py next to this file. Original CLI/core is required.\n" + str(e))

Entry = passmgr.Entry

APP_TITLE = "Local Password Manager"

class VaultModel:
    def __init__(self, path: str, password: str | None = None):
        self.path = path
        self.vault = passmgr.load_vault(path, password)

    # basic adapters
    def save(self):
        passmgr.save_vault(self.path, self.vault)

    def entries(self) -> List[Entry]:
        return [Entry(**e) for e in self.vault.get("entries", [])]

    def add(self, e: Entry):
        self.vault.setdefault("entries", []).append(passmgr.asdict(e)) if hasattr(passmgr, 'asdict') else self.vault.setdefault("entries", []).append(vars(e))
        self.vault["updated_at"] = passmgr.now_ts()

    def replace(self, e: Entry):
        for i, d in enumerate(self.vault.get("entries", [])):
            if d["id"] == e.id:
                self.vault["entries"][i] = passmgr.asdict(e) if hasattr(passmgr, 'asdict') else vars(e)
                self.vault["updated_at"] = passmgr.now_ts()
                return
        raise KeyError("Entry not found")

    def remove(self, entry_id: str):
        before = len(self.vault.get("entries", []))
        self.vault["entries"] = [d for d in self.vault.get("entries", []) if d["id"] != entry_id]
        if len(self.vault["entries"]) == before:
            raise KeyError("Entry not found")
        self.vault["updated_at"] = passmgr.now_ts()

    def get(self, entry_id: str) -> Entry:
        for d in self.vault.get("entries", []):
            if d["id"] == entry_id:
                return Entry(**d)
        raise KeyError("Entry not found")

    def change_master(self):
        passmgr.change_master_password(self.path, self.vault)

# --- UI ---
class App(ttk.Frame):
    def __init__(self, master: tk.Tk, model: VaultModel):
        super().__init__(master)
        self.model = model
        self.pack(fill=tk.BOTH, expand=True)
        master.title(f"{APP_TITLE} — {os.path.basename(model.path)}")
        master.geometry("1000x640")

        self._build_ui()
        self._refresh_tree()

    # UI building
    def _build_ui(self):
        # Top toolbar
        toolbar = ttk.Frame(self)
        toolbar.pack(side=tk.TOP, fill=tk.X)

        self.search_var = tk.StringVar()
        ttk.Label(toolbar, text="Search:").pack(side=tk.LEFT, padx=(8, 4))
        search_entry = ttk.Entry(toolbar, textvariable=self.search_var, width=32)
        search_entry.pack(side=tk.LEFT, padx=4)
        search_entry.bind("<Return>", lambda e: self._refresh_tree())
        ttk.Button(toolbar, text="Clear", command=self._clear_search).pack(side=tk.LEFT, padx=(4,12))

        ttk.Button(toolbar, text="New Entry", command=self._new_entry).pack(side=tk.LEFT)
        ttk.Button(toolbar, text="Duplicate", command=self._duplicate_selected).pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar, text="Delete", command=self._delete_selected).pack(side=tk.LEFT)
        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=8)
        ttk.Button(toolbar, text="Copy User", command=lambda: self._copy_field("username")).pack(side=tk.LEFT)
        ttk.Button(toolbar, text="Copy Pass", command=lambda: self._copy_field("password")).pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar, text="Open URL", command=self._open_url).pack(side=tk.LEFT)
        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=8)
        ttk.Button(toolbar, text="Change Master", command=self._change_master).pack(side=tk.LEFT)

        # Split panes
        paned = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # Left: folder tree
        left = ttk.Frame(paned)
        self.tree = ttk.Treeview(left, show="tree")
        vsb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        paned.add(left, weight=1)

        # Right: details form
        right = ttk.Frame(paned)
        frm = ttk.Frame(right, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)

        self.var_title = tk.StringVar()
        self.var_folder = tk.StringVar()
        self.var_username = tk.StringVar()
        self.var_password = tk.StringVar()
        self.var_url = tk.StringVar()
        self.var_note = tk.Text(frm, height=10, wrap=tk.WORD)
        self.current_entry_id: str | None = None

        row = 0
        def add_row(label, widget):
            nonlocal row
            ttk.Label(frm, text=label, width=12, anchor=tk.E).grid(row=row, column=0, sticky="e", padx=(0,8), pady=4)
            widget.grid(row=row, column=1, sticky="ew", pady=4)
            row += 1

        frm.columnconfigure(1, weight=1)
        add_row("Title", ttk.Entry(frm, textvariable=self.var_title))
        add_row("Folder", ttk.Entry(frm, textvariable=self.var_folder))
        add_row("Username", ttk.Entry(frm, textvariable=self.var_username))

        pass_row = ttk.Frame(frm)
        ent_pass = ttk.Entry(pass_row, textvariable=self.var_password, show="•")
        ent_pass.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self._showing_pass = False
        ttk.Button(pass_row, text="Show", width=6, command=lambda: self._toggle_pass(ent_pass)).pack(side=tk.LEFT, padx=6)
        add_row("Password", pass_row)

        add_row("URL", ttk.Entry(frm, textvariable=self.var_url))
        ttk.Label(frm, text="Note").grid(row=row, column=0, sticky="ne", padx=(0,8), pady=(8,4))
        self.var_note.grid(row=row, column=1, sticky="nsew", pady=(8,4))
        frm.rowconfigure(row, weight=1)
        row += 1

        # action buttons
        actions = ttk.Frame(frm)
        actions.grid(row=row, column=1, sticky="e")
        ttk.Button(actions, text="Save", command=self._save_current).pack(side=tk.RIGHT)
        ttk.Button(actions, text="Revert", command=self._revert_current).pack(side=tk.RIGHT, padx=6)

        paned.add(right, weight=2)

    # Helpers
    def _clear_search(self):
        self.search_var.set("")
        self._refresh_tree()

    def _toggle_pass(self, entry_widget: ttk.Entry):
        self._showing_pass = not self._showing_pass
        entry_widget.config(show="" if self._showing_pass else "•")

    def _open_url(self):
        url = self.var_url.get().strip()
        if url:
            if not url.startswith("http://") and not url.startswith("https://"):
                url = "https://" + url
            webbrowser.open(url)
        else:
            messagebox.showinfo(APP_TITLE, "No URL set for this entry.")

    def _copy_field(self, field: str):
        if not self.current_entry_id:
            return
        try:
            e = self.model.get(self.current_entry_id)
        except KeyError:
            return
        value = getattr(e, field, "")
        if not value:
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        self.update()  # keep clipboard after window closes (on some platforms)
        messagebox.showinfo(APP_TITLE, f"Copied {field} to clipboard.")

    def _entry_matches_search(self, e: Entry, q: str) -> bool:
        if not q:
            return True
        q = q.lower()
        hay = " ".join([
            e.title, e.username, e.url, e.note, e.folder
        ]).lower()
        return q in hay

    def _folder_tree(self, entries: List[Entry]) -> Dict[str, List[Entry]]:
        buckets: Dict[str, List[Entry]] = {}
        for e in entries:
            buckets.setdefault(e.folder.strip("/"), []).append(e)
        return buckets

    def _refresh_tree(self):
        # Save pending edits? Ask the user.
        if self._maybe_save_prompt() is False:
            return

        # Clear tree
        for i in self.tree.get_children(""):
            self.tree.delete(i)

        q = self.search_var.get().strip()
        ents = [e for e in self.model.entries() if self._entry_matches_search(e, q)]

        # Build nested nodes from folder paths
        node_cache: Dict[str, str] = {"": ""}  # logical_path -> tree_id
        def ensure_node(path_parts: List[str]) -> str:
            path = "/".join(path_parts)
            if path in node_cache:
                return node_cache[path]
            parent = ensure_node(path_parts[:-1]) if path_parts[:-1] else ""
            label = path_parts[-1] if path_parts else "(root)"
            node_id = self.tree.insert(parent, "end", text=f"📁 {label}")
            node_cache[path] = node_id
            return node_id

        for e in ents:
            parts = [p for p in e.folder.strip("/").split("/") if p] if e.folder else []
            parent = ensure_node(parts) if parts else ""
            item_text = f"🔐 {e.title}  ({e.username})"
            iid = self.tree.insert(parent, "end", text=item_text, values=(e.id,))
            # store entry_id in iid tags map via columnless value
            self.tree.set(iid, column="#0", value=e.id)  # not visible; for retrieval

        self.current_entry_id = None
        self._clear_detail()
        self.tree.expand = getattr(self.tree, 'expand', lambda *a, **k: None)  # safe-guard
        # Expand top-level nodes by default
        for child in self.tree.get_children(""):
            self.tree.item(child, open=True)

    def _on_tree_select(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return
        iid = sel[0]
        # Extract stored id if this is an entry leaf (has an id mapped)
        entry_id = self.tree.set(iid, column="#0")
        if not entry_id:
            # clicked a folder; ignore
            return
        try:
            e = self.model.get(entry_id)
        except KeyError:
            return
        self._load_into_detail(e)

    # Detail form state
    def _clear_detail(self):
        self.var_title.set("")
        self.var_folder.set("")
        self.var_username.set("")
        self.var_password.set("")
        self.var_url.set("")
        self.var_note.delete("1.0", tk.END)
        self.current_entry_id = None

    def _load_into_detail(self, e: Entry):
        self.current_entry_id = e.id
        self.var_title.set(e.title)
        self.var_folder.set(e.folder)
        self.var_username.set(e.username)
        self.var_password.set(e.password)
        self.var_url.set(e.url)
        self.var_note.delete("1.0", tk.END)
        self.var_note.insert("1.0", e.note or "")

    def _collect_detail(self) -> Entry | None:
        if not self.current_entry_id:
            return None
        try:
            e = self.model.get(self.current_entry_id)
        except KeyError:
            return None
        e.title = self.var_title.get().strip()
        e.folder = self.var_folder.get().strip()
        e.username = self.var_username.get().strip()
        e.password = self.var_password.get()
        e.url = self.var_url.get().strip()
        e.note = self.var_note.get("1.0", tk.END).rstrip()
        e.updated_at = passmgr.now_ts()
        return e

    def _maybe_save_prompt(self) -> bool:
        # here we could detect dirty state; for MVP, we'll be gentle
        return True

    # Actions
    def _save_current(self):
        e = self._collect_detail()
        if not e:
            messagebox.showinfo(APP_TITLE, "Select an entry first.")
            return
        try:
            self.model.replace(e)
            self.model.save()
            self._refresh_tree()
            # reselect the saved entry
            self._select_entry_id(e.id)
            messagebox.showinfo(APP_TITLE, "Saved.")
        except Exception as ex:
            messagebox.showerror(APP_TITLE, f"Save failed: {ex}")

    def _revert_current(self):
        if not self.current_entry_id:
            return
        try:
            e = self.model.get(self.current_entry_id)
        except KeyError:
            return
        self._load_into_detail(e)

    def _select_entry_id(self, entry_id: str):
        # iterate nodes to find matching value
        for iid in self.tree.get_children(""):
            self._select_recursive(iid, entry_id)

    def _select_recursive(self, iid: str, entry_id: str) -> bool:
        val = self.tree.set(iid, column="#0")
        if val == entry_id:
            self.tree.selection_set(iid)
            self.tree.see(iid)
            return True
        for child in self.tree.get_children(iid):
            if self._select_recursive(child, entry_id):
                return True
        return False

    def _new_entry(self):
        # Default folder to currently highlighted folder (if any)
        folder_guess = ""
        sel = self.tree.selection()
        if sel:
            iid = sel[0]
            # If selected node is an entry leaf, use its folder; if folder node, build path from labels
            entry_id = self.tree.set(iid, column="#0")
            if entry_id:
                try:
                    e = self.model.get(entry_id)
                    folder_guess = e.folder
                except KeyError:
                    pass
            else:
                # build path up
                parts = []
                cur = iid
                while cur:
                    text = self.tree.item(cur, 'text')
                    label = text.replace("📁 ", "").strip()
                    parts.insert(0, label)
                    cur = self.tree.parent(cur)
                folder_guess = "/".join(parts)
        new = Entry(
            id=str(__import__('uuid').uuid4()),
            title="New Entry",
            username="",
            password="",
            note="",
            url="",
            folder=folder_guess,
            created_at=passmgr.now_ts(),
            updated_at=passmgr.now_ts(),
        )
        self.model.add(new)
        self.model.save()
        self._refresh_tree()
        self._select_entry_id(new.id)
        self._load_into_detail(new)

    def _duplicate_selected(self):
        if not self.current_entry_id:
            messagebox.showinfo(APP_TITLE, "Select an entry to duplicate.")
            return
        try:
            src = self.model.get(self.current_entry_id)
        except KeyError:
            return
        dup = Entry(
            id=str(__import__('uuid').uuid4()),
            title=src.title + " (Copy)",
            username=src.username,
            password=src.password,
            note=src.note,
            url=src.url,
            folder=src.folder,
            created_at=passmgr.now_ts(),
            updated_at=passmgr.now_ts(),
        )
        self.model.add(dup)
        self.model.save()
        self._refresh_tree()
        self._select_entry_id(dup.id)

    def _delete_selected(self):
        if not self.current_entry_id:
            return
        if not messagebox.askyesno(APP_TITLE, "Delete this entry? This cannot be undone."):
            return
        try:
            self.model.remove(self.current_entry_id)
            self.model.save()
        except Exception as ex:
            messagebox.showerror(APP_TITLE, f"Delete failed: {ex}")
            return
        self._refresh_tree()

    def _change_master(self):
        try:
            self.model.change_master()
        except Exception as ex:
            messagebox.showerror(APP_TITLE, f"Failed to change master password: {ex}")


def main(argv=None):
    argv = argv or sys.argv[1:]
    if not argv:
        print("Usage: python passmgr_gui.py <vault.pm>")
        return 1
    vault_path = argv[0]
    if not os.path.exists(vault_path):
        messagebox.showerror(APP_TITLE, f"Vault not found: {vault_path}\nCreate one with CLI: python passmgr.py init {vault_path}")
        return 2
    # optional second arg = master pass (discouraged), else prompt inside passmgr.load_vault
    password = argv[1] if len(argv) > 1 else None

    root = tk.Tk()
    try:
        model = VaultModel(vault_path, password)
    except Exception as ex:
        messagebox.showerror(APP_TITLE, f"Failed to open vault: {ex}")
        return 3
    # nicer ttk theme if available
    try:
        from tkinter import font  # noqa: F401
        root.call("source", os.path.join(os.path.dirname(__file__), "sun-valley.tcl"))
        root.call("set_theme", "dark")
    except Exception:
        pass
    App(root, model)
    root.mainloop()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
