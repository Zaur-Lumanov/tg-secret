// Touch ID helper for tg-secret-core (macOS). Built by scripts/build-touchid.mjs into
// native/tg-secret-touchid; the core runs it as a child process.
//
// It holds no secrets itself: a P-256 key is created inside the Secure Enclave with an
// access control that requires Touch ID for every use. The core keeps only the key's
// dataRepresentation, an encrypted blob that only this Mac's Secure Enclave can use.
//
// Commands (argv[1]); inputs are lines on stdin, outputs lines on stdout. A failure is one
// stderr line "CODE: message" and exit code 2.
//   check   → "ok" if the Secure Enclave and Touch ID are available
//   create  → key blob (base64), public key (base64, X9.63)
//   derive  ← reason for the Touch ID dialog, key blob (base64), peer public key (base64, X9.63)
//           → ECDH shared secret (base64); asks for Touch ID

import CryptoKit
import Foundation
import LocalAuthentication

func fail(_ code: String, _ message: String) -> Never {
    FileHandle.standardError.write("\(code): \(message)\n".data(using: .utf8)!)
    exit(2)
}

func inputLine() -> String {
    guard let line = readLine() else { fail("BAD_INPUT", "unexpected end of input") }
    return line
}

func inputBase64() -> Data {
    guard let data = Data(base64Encoded: inputLine()) else { fail("BAD_INPUT", "expected a base64 line") }
    return data
}

func biometryProblem() -> (String, String)? {
    guard SecureEnclave.isAvailable else { return ("NO_SECURE_ENCLAVE", "this Mac has no Secure Enclave") }
    var error: NSError?
    if LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) { return nil }
    switch error.flatMap({ LAError.Code(rawValue: $0.code) }) {
    case .biometryNotEnrolled: return ("NOT_ENROLLED", "no fingerprints are enrolled in Touch ID")
    case .biometryLockout: return ("LOCKOUT", "Touch ID is locked after failed attempts: unlock the Mac with its password first")
    default: return ("NO_BIOMETRY", error?.localizedDescription ?? "Touch ID is not available")
    }
}

func fail(_ error: Error) -> Never {
    let ns = error as NSError
    if ns.domain == LAErrorDomain, let code = LAError.Code(rawValue: ns.code) {
        switch code {
        case .userCancel, .systemCancel, .appCancel: fail("CANCELED", "Touch ID confirmation was cancelled")
        case .authenticationFailed: fail("FAILED", "the fingerprint was not recognized")
        case .biometryLockout: fail("LOCKOUT", "Touch ID is locked after failed attempts: unlock the Mac with its password first")
        case .biometryNotAvailable: fail("NO_BIOMETRY", "Touch ID is not available (is the lid closed?)")
        default: break
        }
    }
    fail("ERROR", "\(ns.localizedDescription) (\(ns.domain) \(ns.code))")
}

switch CommandLine.arguments.dropFirst().first {
case "check":
    if let problem = biometryProblem() { fail(problem.0, problem.1) }
    print("ok")

case "create":
    if let problem = biometryProblem() { fail(problem.0, problem.1) }
    var cfError: Unmanaged<CFError>?
    // biometryCurrentSet: enrolling another fingerprint makes the key unusable,
    // so whoever learns the Mac's password can't add their own finger to get in
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &cfError
    ) else { fail(cfError!.takeRetainedValue() as Error) }
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        print(key.dataRepresentation.base64EncodedString())
        print(key.publicKey.x963Representation.base64EncodedString())
    } catch { fail(error) }

case "derive":
    let context = LAContext()
    context.localizedReason = inputLine()
    let blob = inputBase64()
    let peer = inputBase64()
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob, authenticationContext: context)
        let shared = try key.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: peer))
        print(shared.withUnsafeBytes { Data($0) }.base64EncodedString())
    } catch { fail(error) }

default:
    fail("USAGE", "usage: tg-secret-touchid check | create | derive")
}
