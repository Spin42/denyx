# Should be REJECTED at runtime:
# git is in allow_commands and the basename check passes, but
# `push --force` matches [subprocess.deny_args].git so the
# second-tier argument check rejects the call before it runs.
#
# This is the protection that prevents an agent from rewriting
# shared history under a misunderstanding of the user's intent.

subprocess.exec(["git", "push", "--force", "origin", "main"])
print("if you see this, the policy did not stop the force-push")
