#!/usr/bin/env bash
# investigate.sh — NT334 Screen Locker Forensic Investigation
# Run on Kali with evidence disk mounted read-only.
#
# Usage:
#   chmod +x tools/investigate.sh
#   sudo ./tools/investigate.sh /mnt/evidence
#
# This script searches for all known Reveton screen locker artifacts:
#   - File artifacts: .dll, .pad, .js, .lnk, _guard.exe in Startup/AppData/Temp
#   - Registry artifacts: DisableTaskMgr, DisableRegistryTools, NoRun, Defender policies
#   - Persistence mechanisms: Startup folder shortcuts
#
# Prerequisites:
#   - Evidence disk mounted (e.g., /mnt/evidence)
#   - chntpw package installed (for 'reged' offline registry export)
#   - regripper installed (optional, for automated registry analysis)

set -euo pipefail

# --- Config ---
MOUNT="${1:-/mnt/evidence}"
OUTDIR="${2:-./investigation_output}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT="$OUTDIR/investigation_report_$TIMESTAMP.txt"

if [ ! -d "$MOUNT" ]; then
    echo "[!] Mount point not found: $MOUNT"
    echo "    Mount the evidence disk first:"
    echo "    sudo mount -o ro,noexec /dev/sdb1 /mnt/evidence"
    exit 1
fi

mkdir -p "$OUTDIR"

log() {
    echo "$1" | tee -a "$REPORT"
}

separator() {
    log ""
    log "================================================================"
    log "$1"
    log "================================================================"
}

log "NT334 Screen Locker — Forensic Investigation Report"
log "Date: $(date -Iseconds)"
log "Evidence mount: $MOUNT"
log "Investigator: $(whoami)@$(hostname)"

# --- Locate Windows user profiles ---
separator "PHASE 1: Locating user profiles"

USERS_DIR=""
for candidate in \
    "$MOUNT/Users" \
    "$MOUNT/Documents and Settings" \
; do
    if [ -d "$candidate" ]; then
        USERS_DIR="$candidate"
        break
    fi
done

if [ -z "$USERS_DIR" ]; then
    log "[!] No Windows user profiles found under $MOUNT"
    exit 1
fi

log "[+] Users directory: $USERS_DIR"

# List user profiles (skip system accounts)
for profile in "$USERS_DIR"/*/; do
    username=$(basename "$profile")
    case "$username" in
        Default|"Default User"|Public|"All Users") continue ;;
    esac
    log "    User profile: $username"
done

# --- File artifact search ---
separator "PHASE 2: File artifacts — Startup folder"

for profile in "$USERS_DIR"/*/; do
    username=$(basename "$profile")
    case "$username" in
        Default|"Default User"|Public|"All Users") continue ;;
    esac

    startup="$profile/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
    if [ -d "$startup" ]; then
        log ""
        log "[*] Startup folder for $username:"
        find "$startup" -type f 2>/dev/null | while read -r f; do
            fname=$(basename "$f")
            fsize=$(stat -c%s "$f" 2>/dev/null || echo "?")
            log "    [FOUND] $fname ($fsize bytes)"
            log "            Path: $f"
            # Check if it's a .lnk file
            if [[ "$fname" == *.lnk ]]; then
                log "            Type: Windows Shortcut (persistence mechanism)"
                # Extract readable strings from .lnk
                strings "$f" 2>/dev/null | grep -iE '(rundll32|guard|dll|exe|temp|appdata)' | while read -r s; do
                    log "            String: $s"
                done
            fi
        done
    fi
done

separator "PHASE 3: File artifacts — AppData (config, loader)"

for profile in "$USERS_DIR"/*/; do
    username=$(basename "$profile")
    case "$username" in
        Default|"Default User"|Public|"All Users") continue ;;
    esac

    appdata="$profile/AppData/Roaming"
    if [ -d "$appdata" ]; then
        log ""
        log "[*] Suspicious files in AppData/Roaming for $username:"

        # Look for .pad files (Reveton config with RVTN header)
        find "$appdata" -maxdepth 1 -name "*.pad" -type f 2>/dev/null | while read -r f; do
            fname=$(basename "$f")
            fsize=$(stat -c%s "$f" 2>/dev/null || echo "?")
            magic=$(xxd -l 4 -p "$f" 2>/dev/null || echo "?")
            log "    [FOUND] $fname ($fsize bytes) — magic: $magic"
            if [ "$magic" = "5256544e" ]; then
                log "            ** RVTN header detected — Reveton config file **"
            fi
        done

        # Look for .js loader files
        find "$appdata" -maxdepth 1 -name "*.js" -type f 2>/dev/null | while read -r f; do
            fname=$(basename "$f")
            fsize=$(stat -c%s "$f" 2>/dev/null || echo "?")
            log "    [FOUND] $fname ($fsize bytes)"
            if grep -qi "rundll32" "$f" 2>/dev/null; then
                log "            ** Contains rundll32 reference — Reveton JS loader **"
                log "            Content:"
                cat "$f" 2>/dev/null | sed 's/^/            /' | tee -a "$REPORT"
            fi
        done
    fi
done

separator "PHASE 4: File artifacts — Temp (DLL payload, guard EXE)"

for profile in "$USERS_DIR"/*/; do
    username=$(basename "$profile")
    case "$username" in
        Default|"Default User"|Public|"All Users") continue ;;
    esac

    tempdir="$profile/AppData/Local/Temp"
    if [ -d "$tempdir" ]; then
        log ""
        log "[*] Suspicious files in Local/Temp for $username:"

        # Look for DLL files (payload)
        find "$tempdir" -maxdepth 1 -name "*.dll" -type f 2>/dev/null | while read -r f; do
            fname=$(basename "$f")
            fsize=$(stat -c%s "$f" 2>/dev/null || echo "?")
            sha256=$(sha256sum "$f" 2>/dev/null | awk '{print $1}' || echo "?")
            log "    [FOUND] $fname ($fsize bytes)"
            log "            SHA-256: $sha256"
        done

        # Look for _guard.exe files
        find "$tempdir" -maxdepth 1 -name "*_guard.exe" -type f 2>/dev/null | while read -r f; do
            fname=$(basename "$f")
            fsize=$(stat -c%s "$f" 2>/dev/null || echo "?")
            sha256=$(sha256sum "$f" 2>/dev/null | awk '{print $1}' || echo "?")
            log "    [FOUND] $fname ($fsize bytes) — LockerGuard watchdog"
            log "            SHA-256: $sha256"
        done
    fi
done

# --- Registry analysis ---
separator "PHASE 5: Registry artifacts — NTUSER.DAT (HKCU policies)"

for profile in "$USERS_DIR"/*/; do
    username=$(basename "$profile")
    case "$username" in
        Default|"Default User"|Public|"All Users") continue ;;
    esac

    ntuser="$profile/NTUSER.DAT"
    if [ ! -f "$ntuser" ]; then
        continue
    fi

    log ""
    log "[*] Registry analysis for $username (NTUSER.DAT)"

    # Export registry with reged (from chntpw)
    if command -v reged &>/dev/null; then
        regdump="$OUTDIR/${username}_ntuser_policies.reg"
        reged -x "$ntuser" 'HKCU' '\Software\Microsoft\Windows\CurrentVersion\Policies' "$regdump" 2>/dev/null || true

        if [ -f "$regdump" ] && [ -s "$regdump" ]; then
            log "    [FOUND] Policies key exists in NTUSER.DAT"
            log "    Exported to: $regdump"
            log "    Content:"
            cat "$regdump" 2>/dev/null | sed 's/^/    /' | tee -a "$REPORT"
        else
            log "    [NOTE] Policies key NOT found in NTUSER.DAT"
            log "           This is expected if the VM was hard-shutdown (registry not flushed to disk)"
            log "           The policies were active in memory but never written to the hive file"
        fi
    else
        log "    [WARN] 'reged' not found. Install chntpw: sudo apt install chntpw"
    fi

    # RegRipper analysis
    if command -v regripper &>/dev/null || [ -x /usr/share/regripper/regripper ]; then
        rr_cmd=$(command -v regripper 2>/dev/null || echo "/usr/share/regripper/regripper")
        rr_out="$OUTDIR/${username}_regripper.txt"
        log ""
        log "    Running RegRipper on NTUSER.DAT..."
        $rr_cmd -r "$ntuser" -f ntuser > "$rr_out" 2>/dev/null || true
        if [ -s "$rr_out" ]; then
            log "    RegRipper output: $rr_out"
            # Search for specific indicators
            for keyword in "DisableTaskMgr" "DisableRegistryTools" "NoRun" "runctf" "ctfmon32"; do
                match=$(grep -i "$keyword" "$rr_out" 2>/dev/null || true)
                if [ -n "$match" ]; then
                    log "    [HIT] RegRipper found '$keyword':"
                    echo "$match" | sed 's/^/        /' | tee -a "$REPORT"
                fi
            done
        fi
    fi
done

separator "PHASE 6: Registry artifacts — HKLM (Defender policies)"

# SOFTWARE hive is in Windows/System32/config/
software_hive="$MOUNT/Windows/System32/config/SOFTWARE"
if [ -f "$software_hive" ]; then
    log "[*] Checking HKLM\\SOFTWARE for Defender policy modifications..."

    if command -v reged &>/dev/null; then
        defender_dump="$OUTDIR/hklm_defender_policies.reg"
        reged -x "$software_hive" 'HKLM\SOFTWARE' '\Policies\Microsoft\Windows Defender' "$defender_dump" 2>/dev/null || true

        if [ -f "$defender_dump" ] && [ -s "$defender_dump" ]; then
            log "    [FOUND] Windows Defender policies in SOFTWARE hive"
            log "    Exported to: $defender_dump"
            log "    Content:"
            cat "$defender_dump" 2>/dev/null | sed 's/^/    /' | tee -a "$REPORT"
        else
            log "    [NOTE] Defender policy key not found in SOFTWARE hive"
        fi
    fi

    if command -v regripper &>/dev/null || [ -x /usr/share/regripper/regripper ]; then
        rr_cmd=$(command -v regripper 2>/dev/null || echo "/usr/share/regripper/regripper")
        rr_software="$OUTDIR/hklm_software_regripper.txt"
        log ""
        log "    Running RegRipper on SOFTWARE hive..."
        $rr_cmd -r "$software_hive" -f software > "$rr_software" 2>/dev/null || true
        if [ -s "$rr_software" ]; then
            log "    RegRipper output: $rr_software"
            for keyword in "DisableAntiSpyware" "DisableRealtimeMonitoring" "DisableBehaviorMonitoring"; do
                match=$(grep -i "$keyword" "$rr_software" 2>/dev/null || true)
                if [ -n "$match" ]; then
                    log "    [HIT] '$keyword':"
                    echo "$match" | sed 's/^/        /' | tee -a "$REPORT"
                fi
            done
        fi
    fi
else
    log "[!] SOFTWARE hive not found at: $software_hive"
fi

# --- Summary ---
separator "SUMMARY"

log ""
log "Expected Reveton Screen Locker artifacts:"
log ""
log "  File artifacts (6 files):"
log "    1. {id}.dll        — DLL payload in %TEMP%"
log "    2. {id}.pad        — Config file with RVTN header in %APPDATA%"
log "    3. {id}.js         — JS loader script in %APPDATA%"
log "    4. runctf.lnk      — Startup shortcut (runs DLL via rundll32)"
log "    5. ctfmon32.lnk    — Startup shortcut (runs LockerGuard)"
log "    6. {id}_guard.exe  — LockerGuard watchdog in %TEMP%"
log ""
log "  Registry artifacts (4 keys):"
log "    1. HKCU\\...\\Policies\\System\\DisableTaskMgr = 1"
log "    2. HKCU\\...\\Policies\\System\\DisableRegistryTools = 1"
log "    3. HKCU\\...\\Policies\\Explorer\\NoRun = 1"
log "    4. HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware = 1"
log ""
log "  Note: HKCU registry artifacts may not appear on disk if the VM was"
log "  hard-shutdown (power cut). The LockerGuard process re-enforces these"
log "  policies every 800ms in memory, but a hard shutdown prevents the"
log "  registry hive from being flushed to NTUSER.DAT. This is a legitimate"
log "  forensic limitation — the evidence exists only in volatile memory."
log ""
log "Full report: $REPORT"
