import Crypto
import Foundation

/// The `sandvault-chrome` script in the shared workspace (D49). Chrome on macOS ignores `SSL_CERT_FILE` and reads
/// trust from the keychain of the user it runs as; the sandbox user cannot confirm a keychain trust change, and
/// system-wide trust would extend to the host's own browsers. The script instead starts Chrome with
/// `--ignore-certificate-errors-spki-list` set to the CA's public key, which only that Chrome instance honours and
/// only together with `--user-data-dir`. netd sends the CA with every leaf, so the key is in each chain it presents.
public enum ChromeLauncher {
    /// Base64 of SHA-256 over the DER SubjectPublicKeyInfo, the format Chrome expects in the SPKI list.
    public static func spkiHash(der: Data) -> String {
        Data(SHA256.hash(data: der)).base64EncodedString()
    }

    public static func script(for ca: InspectionCA) -> String {
        let spki = ca.spkiHash
        return """
        #!/bin/sh
        # Managed by Sandvault Config and rewritten whenever the inspection CA is published.
        # Starts Chrome in its own profile, through the sandbox proxy, accepting the Sandvault Config inspection CA
        # (matched by its public key). Arguments are passed on; a repeated flag overrides the one set here.
        spki='\(spki)'
        profile="${SANDVAULT_CHROME_PROFILE:-$HOME/.cache/sandvault-chrome}"
        binary="$SANDVAULT_CHROME_BINARY"
        if [ -z "$binary" ]; then
          for candidate in \\
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \\
            "$HOME/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \\
            "/Applications/Chromium.app/Contents/MacOS/Chromium"; do
            if [ -x "$candidate" ]; then binary="$candidate"; break; fi
          done
        fi
        if [ -z "$binary" ]; then
          echo "sandvault-chrome: no Chrome found; set SANDVAULT_CHROME_BINARY" >&2
          exit 127
        fi
        mkdir -p "$profile" || exit 1
        proxy="${HTTPS_PROXY:-$https_proxy}"
        if [ -n "$proxy" ]; then set -- "--proxy-server=$proxy" "$@"; fi
        exec "$binary" "--user-data-dir=$profile" "--ignore-certificate-errors-spki-list=$spki" \\
          --no-first-run --no-default-browser-check "$@"

        """
    }
}

extension InspectionCA {
    /// The CA's key as Chrome's `--ignore-certificate-errors-spki-list` names it.
    public var spkiHash: String { ChromeLauncher.spkiHash(der: privateKey.publicKey.derRepresentation) }
}
