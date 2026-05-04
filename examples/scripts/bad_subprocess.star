# Should be REJECTED PRE-EXECUTION:
# subprocess_exec is in [functions].deny (and not in allow). The verifier
# rejects this script before any code runs.

subprocess_exec(["rm", "-rf", "/tmp/aegis_demo"])
print("if you see this, the verifier did not catch the call")
