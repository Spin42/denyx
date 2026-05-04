# Should be REJECTED at runtime:
# subprocess.exec is allowed by capability, but `rm` is in
# [subprocess].deny_commands (and not in allow_commands either). The
# per-command check rejects the call before it runs.

subprocess.exec(["rm", "-rf", "/tmp/aegis_demo"])
print("if you see this, the policy did not stop the rm")
