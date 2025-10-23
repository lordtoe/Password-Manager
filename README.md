==============================================================================
 Local Password Manager v1.0.0 - README
==============================================================================

  Overview:
  ---------
  Local Password Manager is a secure, offline credential vault designed for
  quick access and simple organization. It uses AES-GCM encryption and an
  scrypt-derived master key to protect your data — with no cloud sync, no
  telemetry, and no online dependencies.

  Entries can be organized into nested folders (e.g., “Game Accounts/Steam”)
  and each entry stores a username, password, URL, and note.  The GUI is built
  in pure Tkinter and includes search, duplication, copy-to-clipboard, and
  folder management features.

  How It Works:
  -------------
  - Create a new vault or open an existing one (.pm file)
  - Set or enter your master password (used for encryption)
  - Browse or search entries from the left-hand folder tree
  - View and edit details on the right-hand form
  - Click “Save” to update the selected entry
  - Add, duplicate, or delete entries and folders as needed

  Features:
  ---------
  ✓ 100% offline — data never leaves your machine
  ✓ AES-GCM encryption with scrypt key derivation
  ✓ Nested folder organization (e.g., Work/Servers/DB01)
  ✓ Add, edit, duplicate, and delete entries or folders
  ✓ Copy username or password to clipboard (one-click)
  ✓ Per-entry URL field with “Open URL” shortcut
  ✓ Master password change and automatic vault re-encryption
  ✓ Search bar filters across all entry fields
  ✓ Clean, responsive Tkinter interface (light/dark theme compatible)

  Example Workflow:
  -----------------
  1. Launch Local Password Manager
  2. Choose “No” to create a new vault → name it “myvault.pm”
  3. Set your master password (twice for confirmation)
  4. Add folders:
         Game Accounts → Smol Games → New Entry
  5. Enter credentials, URL, and optional note
  6. Click “Save” to encrypt and store the entry
  7. Use “Copy Pass” or “Copy User” when logging into sites
  8. Exit — the vault auto-saves and remains encrypted on disk

  Usage Instructions:
  -------------------
  1. Launch the compiled EXE or run with Python 3.11+:
       python passmgr_gui.py myvault.pm
     or simply double-click the EXE and follow the prompts.
  2. Toolbar Buttons:
       • Search / Clear — quick filter for entries
       • New Entry — create a blank credential
       • New Folder — create nested folder paths
       • Duplicate — clone selected entry
       • Delete / Delete Folder — remove entries or entire branches
       • Copy User / Copy Pass — send field to clipboard
       • Open URL — launch default browser to entry URL
       • Change Master — reset master password securely
  3. The right-hand form shows the selected entry’s details.
  4. “Show” toggles visibility of the password field.

  Security Notes:
  ---------------
  • Vaults are encrypted using AES-GCM with 256-bit keys.
  • Keys are derived from your master password via scrypt
       (N=32768, r=8, p=1) for strong brute-force resistance.
  • No plaintext data is ever written to disk.
  • Clipboard copies are cleared automatically by the OS after paste.
  • No internet or background services are used — truly local storage.

  Packaging:
  ----------
  • Build EXE (Windows):
       pyinstaller passmgr_gui.py --windowed --onefile ^
         --name "LocalPasswordManager" ^
         --collect-submodules cryptography ^
         --icon app.ico ^
         --add-data "sun-valley.tcl;."
  • Output EXE:  dist\\LocalPasswordManager.exe
  • Optional flags:
       --version-file version_info.txt  → custom version metadata
       --noconsole                      → hide console window (default)
  • Built EXE runs standalone on any Windows system with no installs.

  Troubleshooting:
  ----------------
  • “Failed to import cryptography” → reinstall package or rebuild EXE with
        --collect-submodules cryptography
  • “Vault not found” → create a new vault using the prompt
  • “Save failed: Display column #0 cannot be set” → update to v1.0.0 or later
  • “Unhandled exception: filedialog not defined” → ensure Tkinter imports:
        from tkinter import filedialog

  Known Issues:
  -------------
  • Clipboard auto-clear depends on OS focus timing (Windows limitation)
  • No built-in password generator (planned for future release)

  Author: Lordtoe
  -------
  Secure. Simple. Offline by design.

==============================================================================
