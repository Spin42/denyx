# Should be REJECTED at runtime by CIDR-aware deny_ips.
#
# The dev policy inherits secure-defaults, which lists 169.254.0.0/16
# in [network].deny_ips. The agent attempts to read AWS instance
# metadata at 169.254.169.254 — a classic SSRF target. The URL parses
# to a literal IP, and the IP falls inside 169.254.0.0/16, so the
# policy rejects before any HTTP traffic leaves the process.

body = net.http_get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
print("if you see this, the policy did not stop the SSRF read")
print(body)
