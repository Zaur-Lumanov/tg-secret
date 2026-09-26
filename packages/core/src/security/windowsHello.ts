/**
 * Windows Hello (PIN, fingerprint, face) as an unlock method, through the WinRT
 * KeyCredentialManager API: Windows Hello holds an RSA key (in the TPM when there is one)
 * and signs a stored challenge only after the user verifies. RSA PKCS#1 v1.5 signatures are
 * deterministic, so the same challenge always yields the same signature → the same KEK.
 * This is how KeePassXC implements its Windows Hello quick unlock.
 */
import { createHash, randomBytes } from "node:crypto";
import { withDialogInFront } from "./foreground.js";
import { PowerShellError, runPowerShell } from "./powershell.js";

// Windows PowerShell 5.1 can't pass a WinRT-created IBuffer (a __ComObject) to WinRT methods,
// so buffers going in are made by .NET (AsBuffer) and buffers coming out are read via
// reflection, which does the COM interface cast PowerShell's binder refuses to do.
const PRELUDE = String.raw`
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$methods = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 }
$asTaskOp = $methods | Where-Object { $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation` + "`" + String.raw`1' } | Select-Object -First 1
$asTaskAction = $methods | Where-Object { $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncAction' } | Select-Object -First 1
function Await($op, [Type]$type) { $t = $asTaskOp.MakeGenericMethod($type).Invoke($null, @($op)); $t.Wait(-1) | Out-Null; $t.Result }
function AwaitAction($op) { $t = $asTaskAction.Invoke($null, @($op)); $t.Wait(-1) | Out-Null }
$null = [Windows.Security.Credentials.KeyCredentialManager, Windows.Security.Credentials, ContentType = WindowsRuntime]
$null = [Windows.Security.Cryptography.CryptographicBuffer, Windows.Security.Cryptography, ContentType = WindowsRuntime]
$KCM = [Windows.Security.Credentials.KeyCredentialManager]
function ToBuffer([string]$b64) { [System.Runtime.InteropServices.WindowsRuntime.WindowsRuntimeBufferExtensions]::AsBuffer([Convert]::FromBase64String($b64)) }
function FromBuffer($buf) { [Windows.Security.Cryptography.CryptographicBuffer].GetMethod('EncodeToBase64String').Invoke($null, @($buf)) }
function Check($status) { if ($status -ne 'Success') { [Console]::Error.WriteLine("HELLO_" + $status.ToString().ToUpper() + ": " + $status); exit 2 } }
`;

const STATUS_TEXT: Record<string, string> = {
  HELLO_USERCANCELED: "Windows Hello confirmation was cancelled",
  HELLO_NOTFOUND: "the Windows Hello key for this account was not found (deleted, or created under another Windows user)",
  HELLO_USERPREFERSPASSWORD: "password sign-in was chosen in the Windows Hello dialog",
  HELLO_SECURITYDEVICELOCKED: "the security device is locked, try again later",
  HELLO_UNKNOWNERROR: "unknown Windows Hello error",
};

export async function runHelloScript(script: string, stdin = ""): Promise<string> {
  try {
    return await runPowerShell(PRELUDE + script, stdin);
  } catch (e) {
    if (e instanceof PowerShellError && STATUS_TEXT[e.code]) throw new Error(STATUS_TEXT[e.code]);
    throw e;
  }
}

export const helloAvailable = (): boolean => process.platform === "win32";

export async function isHelloSupported(): Promise<boolean> {
  if (!helloAvailable()) return false;
  return (await runHelloScript(`Await ($KCM::IsSupportedAsync()) ([bool])`)) === "True";
}

const kekFromSignature = (signatureB64: string): Buffer => createHash("sha256").update(Buffer.from(signatureB64, "base64")).digest();

const SIGN = String.raw`
$open = Await ($KCM::OpenAsync($name)) ([Windows.Security.Credentials.KeyCredentialRetrievalResult]); Check $open.Status
$res = Await ($open.Credential.RequestSignAsync((ToBuffer $challenge))) ([Windows.Security.Credentials.KeyCredentialOperationResult]); Check $res.Status
[Console]::Out.Write((FromBuffer $res.Result))`;

async function sign(credentialName: string, challenge: string): Promise<Buffer> {
  const sig = await withDialogInFront(() =>
    runHelloScript(`$name = [Console]::In.ReadLine(); $challenge = [Console]::In.ReadLine()\n${SIGN}`, `${credentialName}\n${challenge}\n`),
  );
  return kekFromSignature(sig);
}

/**
 * Creates a Windows Hello key and signs the new slot's challenge with it: two confirmations.
 * If anything fails after the key was created, the key is deleted again.
 */
export async function enrollHello(credentialName: string): Promise<{ challenge: string; kek: Buffer }> {
  await withDialogInFront(() =>
    runHelloScript(
      String.raw`
$name = [Console]::In.ReadLine()
$res = Await ($KCM::RequestCreateAsync($name, [Windows.Security.Credentials.KeyCredentialCreationOption]::ReplaceExisting)) ([Windows.Security.Credentials.KeyCredentialRetrievalResult]); Check $res.Status`,
      `${credentialName}\n`,
    ),
  );
  const challenge = randomBytes(32).toString("base64");
  try {
    return { challenge, kek: await sign(credentialName, challenge) };
  } catch (e) {
    await deleteHello(credentialName).catch(() => undefined);
    throw e;
  }
}

export const helloKek = (credentialName: string, challenge: string): Promise<Buffer> => sign(credentialName, challenge);

export async function deleteHello(credentialName: string): Promise<void> {
  await runHelloScript(String.raw`$name = [Console]::In.ReadLine(); AwaitAction ($KCM::DeleteAsync($name))`, `${credentialName}\n`);
}
