import { spawn } from "node:child_process";

/**
 * Windows shows Hello and smart card PIN prompts from a separate system process
 * (CredentialUIBroker). For a console program it tends to open minimized or behind the
 * terminal. While `job` runs, a helper keeps restoring such a window and bringing it to the
 * front once (the same workaround KeePassXC uses). It only shows the window, never clicks.
 */
const HELPER = String.raw`
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
public static class DialogFront {
  delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr l);
  [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] static extern bool IsIconic(IntPtr h);
  [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr h, int cmd);
  [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] static extern void SwitchToThisWindow(IntPtr h, bool altTab);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  static readonly HashSet<IntPtr> raised = new HashSet<IntPtr>();
  public static int Tick() {
    var pids = new HashSet<uint>();
    foreach (var p in Process.GetProcessesByName("CredentialUIBroker")) pids.Add((uint)p.Id);
    int found = 0;
    EnumWindows((h, l) => {
      uint pid; GetWindowThreadProcessId(h, out pid);
      var cls = new StringBuilder(256); GetClassName(h, cls, cls.Capacity);
      bool dialog = pids.Contains(pid) || cls.ToString() == "Credential Dialog Xaml Host";
      if (!dialog || !(IsWindowVisible(h) || IsIconic(h))) return true;
      found++;
      if (IsIconic(h)) { ShowWindow(h, 9 /* SW_RESTORE */); raised.Remove(h); }
      if (raised.Add(h)) { SwitchToThisWindow(h, true); SetForegroundWindow(h); }
      return true;
    }, IntPtr.Zero);
    return found;
  }
}
'@
$deadline = (Get-Date).AddSeconds(__SECONDS__)
while ((Get-Date) -lt $deadline) { [void][DialogFront]::Tick(); Start-Sleep -Milliseconds 250 }
`;

export const helperScript = (seconds: number): string => HELPER.replace("__SECONDS__", String(seconds));

export async function withDialogInFront<T>(job: () => Promise<T>, seconds = 180): Promise<T> {
  if (process.platform !== "win32") return job();
  const helper = spawn(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", Buffer.from(helperScript(seconds), "utf16le").toString("base64")],
    { windowsHide: true, stdio: "ignore" },
  );
  helper.on("error", () => undefined); // best effort: the prompt still works without it
  try {
    return await job();
  } finally {
    helper.kill();
  }
}
