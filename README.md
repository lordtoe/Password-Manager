==============================================================================
 Local Password Manager v1.2.0 - README
==============================================================================

 Overview:
  ---------
  Local Password Manager is a secure, offline credential vault designed for
  quick access and simple organization. It uses AES-GCM encryption and an
  scrypt-derived master key to protect your data — with no cloud sync, no
  telemetry, and no online dependencies.

  Entries can be organized into nested folders (e.g., “Game Accounts/Steam”)
  and each entry stores a username, password, URL, and note.  The GUI is built
  in pure Tkinter and includes live password strength analysis, auto-locking,
  password generation, and a flexible options menu for user preferences.

  How It Works:
  -------------
  - Create or open a vault (.pm file)
  - Enter your master password to unlock
  - Browse or search entries from the left-hand folder tree
  - View and edit details on the right-hand form
  - Click “Save” to update or add entries
  - Auto-lock hides all data after user-defined inactivity
  - “Options” allows configuration of auto-lock and generator settings

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
  ✓ Auto-lock timer with configurable duration (default 15 min)  
  ✓ Password generator with phonetic or secure-random modes  
  ✓ Live password strength gauge with color feedback  
  ✓ Options window for managing vault and security settings  
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
  8. Idle for X minutes → app auto-locks until master password is re-entered  

  Usage Instructions:
  -------------------
  1. Launch the compiled EXE or run with Python 3.11+:
       python passmgr_gui.py myvault.pm
     or simply double-click the EXE and follow the prompts.

  2. Toolbar Buttons:
       • Search / Clear — quick filter for entries  
       • New Entry — create a blank credential  
       • Duplicate — clone selected entry  
       • Delete / Delete Folder — remove entries or branches  
       • Copy User / Copy Pass — send field to clipboard  
       • Open URL — launch default browser to entry URL  
       • Change Master — reset master password securely  
       • Options — open settings window (auto-lock, generator, vault tools)

  3. Options Window:
       • Enable or disable auto-lock  
       • Adjust lock timeout (1–60 minutes)  
       • Open existing vault or create a new one  
       • Access password generator preferences

  4. Password Field:
       • “Generate” — instantly fills a random or phonetic password  
       • “Show” — toggles visibility  
       • Strength bar displays color and rating:
           No Password = Black  
           Weak = Red  
           Risky = Orange  
           Okay = Yellow  
           Good = Green  
           Great = Blue (#3B82F6)

  Security Notes:
  ---------------
  • Vaults use AES-GCM 256-bit encryption.  
  • Keys are derived from your master password via scrypt
       (N = 32768, r = 8, p = 1).  
  • No plaintext data or temporary files are written to disk.  
  • Clipboard copies are cleared automatically by the OS after paste.  
  • No network access, telemetry, or cloud sync — entirely local.

Troubleshooting:
  ----------------
  • “Failed to import cryptography” → rebuild with hidden-import flags  
  • “Vault not found” → create or open an existing .pm file via Options  
  • “Incorrect master password” → re-enter carefully (case-sensitive)  
  • “Lock timer not updating” → delete ~/.local_passmgr_settings.json  
        to reset configuration  

  Known Issues:
  -------------
  • Clipboard auto-clear depends on OS focus timing (Windows limitation)  
  • Password generator UI does not auto-resize on some high-DPI setups  

Icon Credit: <a href="https://www.flaticon.com/free-icons/security" title="security icons">Security icons created by Freepik - Flaticon</a>
