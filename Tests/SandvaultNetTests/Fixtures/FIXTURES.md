# SandvaultNetTests fixtures

| File | Source | Command that produces it |
|---|---|---|
| `clienthello-sni-example.com.bin` | real (OpenSSL 3.0.13 on Linux) | `openssl s_client -connect 127.0.0.1:28090 -servername example.com </dev/null` against a listener that saves the first bytes it receives |
| `clienthello-no-sni.bin` | real (OpenSSL 3.0.13 on Linux) | `openssl s_client -connect 127.0.0.1:28090 -noservername </dev/null` against the same listener |
| `dns-response-www.github.com.hex` | synthetic | wire bytes (hex) of an answer to `dig www.github.com A` with a CNAME and compression pointers; on a Mac capture one with `sudo tcpdump -i en0 -w dns.pcap udp port 53` while running `dig www.github.com` |
| `launchctl-print-netd-running.txt` | synthetic | `launchctl print gui/$(id -u)/me.admon.apps.sandvault-config.netd` while the agent runs |
| `launchctl-print-netd-exited.txt` | synthetic | the same command after the agent exited with status 1 |
| `root-bundle.pem` | synthetic | stands in for `security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain` (two self-signed test certificates) |
