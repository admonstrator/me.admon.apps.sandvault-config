# SandvaultNetTests fixtures

| File | Source | Command that produces it |
|---|---|---|
| `clienthello-sni-example.com.bin` | real (OpenSSL 3.0.13 on Linux) | `openssl s_client -connect 127.0.0.1:28090 -servername example.com </dev/null` against a listener that saves the first bytes it receives |
| `clienthello-no-sni.bin` | real (OpenSSL 3.0.13 on Linux) | `openssl s_client -connect 127.0.0.1:28090 -noservername </dev/null` against the same listener |
| `dns-response-www.github.com.hex` | synthetic | wire bytes (hex) of an answer to `dig www.github.com A` with a CNAME and compression pointers; on a Mac capture one with `sudo tcpdump -i en0 -w dns.pcap udp port 53` while running `dig www.github.com` |
| `launchctl-print-netd-running.txt` | synthetic | `launchctl print gui/$(id -u)/me.admon.apps.sandvault-config.netd` while the agent runs |
| `launchctl-print-netd-exited.txt` | synthetic | the same command after the agent exited with status 1 |
| `launchctl-print-netd-missing.txt` | real (macOS 27.0.1, host uid 501) | the same command while the agent is not installed (stdout and stderr; exit code not captured, the test assumes 113) |
| `root-bundle.pem` | synthetic | stands in for `security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain` (two self-signed test certificates) |
| `ip2asn-v4-sample.tsv` | synthetic | lines in the format of iptoasn.com's `ip2asn-v4.tsv` (tab separated, unrouted AS 0 lines included); the real table comes from `svctl net database update` |
| `rdap-arin-8.8.8.8.json` | synthetic | stands in for `curl -sL https://rdap.org/ip/8.8.8.8` (ARIN layout with the `arin_originas0` extension); written from RFC 9083 and ARIN's response layout, not captured |
| `rdap-ripe-185.142.236.41.json` | synthetic | stands in for `curl -sL https://rdap.org/ip/185.142.236.41` (RIPE layout: `country`, no registrant, no AS number); not captured |
| `codesign-apple-mdnsresponder.txt` | synthetic | stderr of `codesign -dv --verbose=2 /usr/sbin/mDNSResponder` (platform binary); on a Mac: `codesign -dv --verbose=2 /usr/sbin/mDNSResponder 2>&1` |
| `codesign-developer-id.txt` | synthetic | stderr of the same command for an app signed with a Developer ID (made-up name and team) |
| `codesign-adhoc-node.txt` | synthetic | stderr for a Homebrew binary that only has the linker's ad hoc signature |
| `codesign-unsigned.txt` | synthetic | stderr for an unsigned file (`codesign` exits 1) |
