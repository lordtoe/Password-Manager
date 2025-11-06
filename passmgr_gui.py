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
import json, secrets, string
from tkinter import ttk, messagebox, simpledialog, filedialog
from typing import Dict, List, Tuple

# --- import core vault logic from passmgr.py ---
try:
    import passmgr  # the CLI/core from the companion file
except Exception as e:
    raise SystemExit("Place passmgr.py next to this file. Original CLI/core is required.\n" + str(e))

# Give Windows a stable identity for taskbar pinning/grouping
try:
    import ctypes
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
        "Lordtoe.LocalPasswordManager"  # any unique string
    )
except Exception:
    pass

CONFIG_FILE = os.path.join(os.path.expanduser("~"), ".local_passmgr.cfg")
Entry = passmgr.Entry

APP_TITLE = "Local Password Manager"

class VaultModel:
    def __init__(self, path: str, password: str | None = None):
        self.path = path
        self.vault = passmgr.load_vault(path, password)
        # keep a virtual list of folders so we can create empty ones
        self.vault.setdefault("folders", [])

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

    def list_folders(self) -> list[str]:
        return list(self.vault.get("folders", []))

    def add_folder(self, path: str):
        path = path.strip("/").replace("\\", "/")
        if not path:
            return
        folders = self.vault.setdefault("folders", [])
        if path not in folders:
            folders.append(path)
            self.vault["updated_at"] = passmgr.now_ts()

    def remove_folder(self, path: str) -> bool:
        """Removes a folder if it has no entries inside (non-recursive).
        Returns True if removed."""
        path = path.strip("/").replace("\\", "/")
        if not path:
            return False
        # refuse if any entry lives in this exact folder or its subfolders
        for e in self.entries():
            f = (e.folder or "").strip("/")
            if f == path or f.startswith(path + "/"):
                return False
        try:
            self.vault["folders"].remove(path)
            self.vault["updated_at"] = passmgr.now_ts()
            return True
        except ValueError:
            return False

# --- UI ---
class App(ttk.Frame):
    def __init__(self, master: tk.Tk, model: VaultModel):
        super().__init__(master)
        self.model = model
        self._load_settings()  # initialize generator + app settings
        self.pack(fill=tk.BOTH, expand=True)
        master.title(f"{APP_TITLE} — {os.path.basename(model.path)}")
        master.geometry("1000x640")

        self._build_ui()
        self._refresh_tree()

    def _load_settings(self):
        """Initialize or load saved generator and app settings."""
        import json
        self.settings = {
            "gen_mode": "random",
            "gen_length": 16,
            "gen_uppercase": True,
            "gen_specials": "!@#$%^&*()-_=+[]{};:,<.>/?",
        }
        cfg = os.path.join(os.path.expanduser("~"), ".local_passmgr.cfg")
        if os.path.exists(cfg):
            try:
                with open(cfg, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        self.settings.update(data)
            except Exception:
                pass
        self.config_path = cfg
    
    def _open_generator(self):
        win = tk.Toplevel(self)
        win.title("Password Generator")
        win.geometry("400x250")
        win.transient(self)
        win.grab_set()

        ttk.Label(win, text="Mode:").pack(anchor="w", padx=12, pady=(10,0))
        mode = tk.StringVar(value=self.settings.get("gen_mode", "random"))
        ttk.Radiobutton(win, text="Secure random", variable=mode, value="random").pack(anchor="w", padx=20)
        ttk.Radiobutton(win, text="Phonetic token", variable=mode, value="phonetic").pack(anchor="w", padx=20)

        ttk.Label(win, text="Length:").pack(anchor="w", padx=12, pady=(10,0))
        length = tk.IntVar(value=self.settings.get("gen_length", 16))
        ttk.Spinbox(win, from_=6, to=64, textvariable=length, width=6).pack(anchor="w", padx=20)

        uppercase = tk.BooleanVar(value=self.settings.get("gen_uppercase", True))
        ttk.Checkbutton(win, text="Include uppercase letters", variable=uppercase).pack(anchor="w", padx=20, pady=4)

        specials_frame = ttk.Frame(win)
        specials_frame.pack(fill="x", padx=20, pady=(6,0))
        ttk.Label(specials_frame, text="Special characters:").pack(anchor="w")
        special_entry = ttk.Entry(specials_frame)
        special_entry.insert(0, self.settings.get("gen_specials", "!@#$%^&*"))
        special_entry.pack(fill="x")

        output_var = tk.StringVar()
        out = ttk.Entry(win, textvariable=output_var, width=40)
        out.pack(padx=20, pady=(10,6), fill="x")

        def generate():
            mode_val = mode.get()
            if mode_val == "random":
                chars = string.ascii_lowercase
                if uppercase.get():
                    chars += string.ascii_uppercase
                chars += string.digits
                chars += special_entry.get()
                result = "".join(secrets.choice(chars) for _ in range(length.get()))
            else:
                syllables = ["ba","be","bi","bo","bu","da","de","di","do","du","ka","ke","ki","ko","ku","ra","re","ri","ro","ru","ta","te","ti","to","tu"]
                result = "".join(secrets.choice(syllables).capitalize() if uppercase.get() else secrets.choice(syllables) for _ in range(max(2, length.get()//3)))
                if special_entry.get():
                    result += secrets.choice(special_entry.get())
                result += str(secrets.randbelow(100))
            output_var.set(result)

        def use_password():
            self.var_password.set(output_var.get())
            win.destroy()

        ttk.Button(win, text="Generate", command=generate).pack(pady=4)
        ttk.Button(win, text="Use Password", command=use_password).pack(pady=4)

        def save_and_close():
            self.settings["gen_mode"] = mode.get()
            self.settings["gen_length"] = length.get()
            self.settings["gen_uppercase"] = uppercase.get()
            self.settings["gen_specials"] = special_entry.get()
            self._save_settings()
            win.destroy()
        ttk.Button(win, text="Close", command=save_and_close).pack(pady=6)

    # UI building
    def _build_ui(self):
        # Top toolbar
        toolbar = ttk.Frame(self)
        toolbar.pack(side=tk.TOP, fill=tk.X)

        self.search_var = tk.StringVar()
        ttk.Label(toolbar, text="Search:").pack(side=tk.LEFT, padx=(8, 4))
        search_entry = ttk.Entry(toolbar, textvariable=self.search_var, width=32)
        search_entry.pack(side=tk.LEFT, padx=(0, 6))
        search_entry.bind("<Return>", lambda e: self._refresh_tree())
        ttk.Button(toolbar, text="Clear", command=self._clear_search).pack(side=tk.LEFT, padx=(0, 16))
        ttk.Button(toolbar, text="Options", command=self._open_options).pack(side=tk.LEFT, padx=3)

        # main actions
        for text, cmd in [
            ("New Entry", self._new_entry),
            ("New Folder", self._new_folder),
            ("Duplicate", self._duplicate_selected),
            ("Delete", self._delete_selected),
            ("Delete Folder", self._delete_folder),
        ]:
            ttk.Button(toolbar, text=text, command=cmd).pack(side=tk.LEFT, padx=3)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)

        # clipboard + url actions
        for text, cmd in [
            ("Copy User", lambda: self._copy_field("username")),
            ("Copy Pass", lambda: self._copy_field("password")),
            ("Open URL", self._open_url),
        ]:
            ttk.Button(toolbar, text=text, command=cmd).pack(side=tk.LEFT, padx=3)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)

        

        # Split panes
        paned = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # Left: folder tree
        left = ttk.Frame(paned)
        self.tree = ttk.Treeview(left, columns=("entry_id",), show="tree")
        self.tree.column("entry_id", width=0, stretch=False)
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

        # --- New Generate button ---
        ttk.Button(pass_row, text="Generate", width=8,
                command=lambda: self._generate_password(ent_pass)).pack(side=tk.LEFT, padx=(6, 2))
        # Existing Show button
        ttk.Button(pass_row, text="Show", width=6,
                command=lambda: self._toggle_pass(ent_pass)).pack(side=tk.LEFT, padx=(2, 6))

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
    def _open_options(self):
        win = tk.Toplevel(self)
        win.title("Options")
        win.geometry("300x200")
        win.transient(self)
        win.grab_set()

        auto_var = tk.BooleanVar(value=self.settings.get("autolock", False))
        ttk.Checkbutton(win, text="Enable auto-lock (15 min)", variable=auto_var).pack(anchor="w", padx=20, pady=10)

        ttk.Button(win, text="Change Master Password", command=self._change_master).pack(fill="x", padx=20, pady=6)
        ttk.Button(win, text="Create New Vault", command=self._new_vault).pack(fill="x", padx=20, pady=6)
        ttk.Button(win, text="Password Generator Settings", command=self._open_generator).pack(fill="x", padx=20, pady=6)

        def save_and_close():
            self.settings["autolock"] = auto_var.get()
            self._save_settings()
            win.destroy()
        ttk.Button(win, text="Close", command=save_and_close).pack(pady=10)

    def _load_settings(self):
        self.settings = {
            "gen_mode": "random",
            "gen_length": 16,
            "gen_uppercase": True,
            "gen_specials": "!@#$%^&*()-_=+[]{};:,<.>/?",
        }
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        self.settings.update(data)
            except Exception:
                pass

    def _save_settings(self):
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(self.settings, f, indent=2)
        except Exception:
            pass

    def _clear_search(self):
        self.search_var.set("")
        self._refresh_tree()

    def _toggle_pass(self, entry_widget: ttk.Entry):
        self._showing_pass = not self._showing_pass
        entry_widget.config(show="" if self._showing_pass else "•")

    def _generate_password(self, entry_widget):
        """Generate a password using saved preferences and fill the password field."""
        import secrets, string

        # Confirm overwrite if password field already has content
        current = self.var_password.get()
        if current.strip():
            if not messagebox.askyesno(APP_TITLE, "Replace existing password?"):
                return

        # Load preferences (defaults if not set)
        mode = self.settings.get("gen_mode", "random")
        length = int(self.settings.get("gen_length", 16))
        uppercase = self.settings.get("gen_uppercase", True)
        specials = self.settings.get("gen_specials", "!@#$%^&*()-_=+[]{};:,<.>/?")

        # Generate password
        if mode == "random":
            chars = string.ascii_lowercase + string.digits + specials
            if uppercase:
                chars += string.ascii_uppercase
            password = "".join(secrets.choice(chars) for _ in range(length))
        else:
            # simple phonetic/rememberable token mode
            syllables = ["ba","be","bi","bo","bu","da","de","di","do","du",
                        "ka","ke","ki","ko","ku","ra","re","ri","ro","ru",
                        "ta","te","ti","to","tu"]
            token = "".join(secrets.choice(syllables).capitalize() if uppercase
                            else secrets.choice(syllables)
                            for _ in range(max(2, length//3)))
            password = token + secrets.choice(specials) + str(secrets.randbelow(100))

        # Apply and update field
        self.var_password.set(password)
        entry_widget.icursor(tk.END)
        messagebox.showinfo(APP_TITLE, "New password generated and applied.")

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
        entry_id = self.tree.set(iid, "entry_id")
        if not entry_id:
            # clicked a folder; ignore
            return
        try:
            e = self.model.get(entry_id)
        except KeyError:
            return
        self._load_into_detail(e)

    def _current_folder_path(self) -> str:
        """Return the folder path represented by the selected tree node,
        or the folder of the selected entry, or '' if none."""
        sel = self.tree.selection()
        if not sel:
            return ""
        iid = sel[0]
        # If it’s an entry leaf we need its folder
        # (change this next line to use your fixed hidden column if you already patched it)
        try:
            entry_id = self.tree.set(iid, "entry_id")  # <-- if you haven’t added hidden column yet, see note below
        except Exception:
            entry_id = ""
        if entry_id:
            try:
                e = self.model.get(entry_id)
                return (e.folder or "").strip("/")
            except KeyError:
                return ""
        # Otherwise, climb labels to build folder path
        parts = []
        cur = iid
        while cur:
            text = self.tree.item(cur, "text")
            label = text.replace("📁 ", "").strip()
            if label:
                parts.insert(0, label)
            cur = self.tree.parent(cur)
        return "/".join(parts).strip("/")
    
    def _new_folder(self):
        base = self._current_folder_path()
        name = simpledialog.askstring(APP_TITLE, "New folder name (use A/B/C for nested):")
        if not name:
            return
        new_path = (base + "/" if base else "") + name.strip("/")
        # create a new entry inside that folder so it shows up immediately
        new = Entry(
            id=str(__import__('uuid').uuid4()),
            title="New Entry",
            username="",
            password="",
            note="",
            url="",
            folder=new_path,
            created_at=passmgr.now_ts(),
            updated_at=passmgr.now_ts(),
        )
        self.model.add(new)
        self.model.save()
        self._refresh_tree()
        self._select_entry_id(new.id)
        self._load_into_detail(new)

    def _delete_folder(self):
        folder = self._current_folder_path()
        if not folder:
            messagebox.showinfo(APP_TITLE, "Select a folder to delete.")
            return
        # Collect all entries whose folder is this folder or a descendant
        prefix = folder.strip("/")
        to_delete = []
        for e in self.model.entries():
            f = e.folder.strip("/")
            if f == prefix or f.startswith(prefix + "/"):
                to_delete.append(e)

        if not to_delete:
            messagebox.showinfo(APP_TITLE, f"No entries under '{folder}'.")
            return

        if not messagebox.askyesno(
            APP_TITLE,
            f"Delete folder '{folder}' and {len(to_delete)} entr"
            f"{'y' if len(to_delete)==1 else 'ies'} in it and its subfolders?\nThis cannot be undone."
        ):
            return

        try:
            for e in to_delete:
                self.model.remove(e.id)
            self.model.save()
            # If the detail pane was showing one of the removed entries, clear it
            if self.current_entry_id and any(e.id == self.current_entry_id for e in to_delete):
                self._clear_detail()
            self._refresh_tree()
        except Exception as ex:
            messagebox.showerror(APP_TITLE, f"Folder delete failed: {ex}")


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
    def _new_vault(self):
        """Create a brand new vault file from the running GUI."""
        from tkinter import simpledialog, filedialog, messagebox
        import passmgr, os

        path = filedialog.asksaveasfilename(
            title="Create New Vault",
            defaultextension=".pm",
            filetypes=[("Password Manager Vault", "*.pm"), ("All Files", "*.*")]
        )
        if not path:
            return

        pw1 = simpledialog.askstring(APP_TITLE, "Create master password:", show="*")
        pw2 = simpledialog.askstring(APP_TITLE, "Confirm master password:", show="*")
        if not pw1 or pw1 != pw2:
            messagebox.showerror(APP_TITLE, "Passwords did not match or were empty.")
            return

        try:
            passmgr.init_vault(path, pw1)
        except Exception as ex:
            messagebox.showerror(APP_TITLE, f"Failed to create vault: {ex}")
            return

        messagebox.showinfo(APP_TITLE, f"New vault created:\n{path}\n\nRestart to open it.")

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
        val = self.tree.set(iid, "entry_id")
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
            entry_id = self.tree.set(iid, "entry_id")
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

    def resource_path(rel):
        base = getattr(sys, "_MEIPASS", os.path.dirname(__file__))
        return os.path.join(base, rel)

    root = tk.Tk()

    # .ico for window/taskbar
    try:
        root.iconbitmap(resource_path("app.ico"))
    except Exception:
        pass

    # (Optional but helps on some setups): also set a PNG taskbar icon
    # Include app.png beside app.ico and add it with --add-data
    try:
        img = tk.PhotoImage(file=resource_path("app.png"))
        root.iconphoto(False, img)
    except Exception:
        pass
    root.withdraw()  # hide until a vault is ready

    vault_path = None
    master_password = None

    # Try to load last used vault
    last_vault = None
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                last_vault = f.read().strip()
        except Exception:
            pass

    def prompt_open_or_create():
        """Return (vault_path, master_password) or (None, None) if user cancels."""
        # Open existing?
        if messagebox.askyesno(APP_TITLE, "Open an existing vault? (No = Create new)"):
            path = filedialog.askopenfilename(
                title="Open Vault",
                filetypes=[("Password Manager Vault", "*.pm"), ("All Files", "*.*")]
            )
            if not path:
                return None, None
            mpw = simpledialog.askstring(APP_TITLE, "Master password:", show="*")
            if not mpw:
                return None, None
            return path, mpw
        # Create new
        path = filedialog.asksaveasfilename(
            title="Create New Vault",
            defaultextension=".pm",
            filetypes=[("Password Manager Vault", "*.pm"), ("All Files", "*.*")]
        )
        if not path:
            return None, None
        pw1 = simpledialog.askstring(APP_TITLE, "Create master password:", show="*")
        pw2 = simpledialog.askstring(APP_TITLE, "Confirm master password:", show="*")
        if not pw1 or pw1 != pw2:
            messagebox.showerror(APP_TITLE, "Passwords did not match or were empty.")
            return None, None
        try:
            passmgr.init_vault(path, pw1)
        except Exception as ex:
            messagebox.showerror(APP_TITLE, f"Failed to create vault: {ex}")
            return None, None
        return path, pw1

    # 1) If a CLI path was provided, use it.
    if argv:
        candidate = argv[0]
        if not os.path.exists(candidate):
            if not messagebox.askyesno(APP_TITLE, f"Vault not found:\n{candidate}\nCreate it now?"):
                return 0
            pw1 = simpledialog.askstring(APP_TITLE, "Create master password:", show="*")
            pw2 = simpledialog.askstring(APP_TITLE, "Confirm master password:", show="*")
            if not pw1 or pw1 != pw2:
                messagebox.showerror(APP_TITLE, "Passwords did not match or were empty.")
                return 0
            try:
                passmgr.init_vault(candidate, pw1)
            except Exception as ex:
                messagebox.showerror(APP_TITLE, f"Failed to create vault: {ex}")
                return 1
            vault_path, master_password = candidate, pw1
        else:
            mpw = simpledialog.askstring(APP_TITLE, f"Master password for:\n{os.path.basename(candidate)}", show="*")
            if not mpw:
                return 0
            vault_path, master_password = candidate, mpw

    # 2) No CLI: offer to reopen last vault if present.
    elif last_vault and os.path.exists(last_vault):
        if messagebox.askyesno(APP_TITLE, f"Reopen last vault?\n\n{last_vault}"):
            mpw = simpledialog.askstring(APP_TITLE, f"Master password for:\n{os.path.basename(last_vault)}", show="*")
            if not mpw:
                return 0
            vault_path, master_password = last_vault, mpw
        else:
            vault_path, master_password = prompt_open_or_create()
            if not vault_path:
                return 0

    # 3) No CLI, no last vault: prompt open/create.
    else:
        vault_path, master_password = prompt_open_or_create()
        if not vault_path:
            return 0

    # Show window and load model
    root.deiconify()
    try:
        model = VaultModel(vault_path, master_password)
        # Remember last vault path
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                f.write(vault_path)
        except Exception:
            pass
    except Exception as ex:
        messagebox.showerror(APP_TITLE, f"Failed to open vault: {ex}")
        return 1

    # Optional theme (safe if missing)
    def resource_path(rel):
        base = getattr(sys, "_MEIPASS", os.path.dirname(__file__))
        return os.path.join(base, rel)
    try:
        root.call("source", resource_path("sun-valley.tcl"))
        root.call("set_theme", "dark")
    except Exception:
        pass

    App(root, model)
    root.mainloop()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

