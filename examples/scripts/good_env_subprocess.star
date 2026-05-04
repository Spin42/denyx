# Mixed pipeline: read an allowed env var, run an allowed command.
#
# - env.read("USER")     — USER is in [environment].allow_vars.
# - subprocess.exec(git) — git is in [subprocess].allow_commands.
#                          subprocess.exec is in confirm_per_call, so
#                          pass --yes to auto-allow in CI.

user = env.read("USER")
print("running as:", user)

version = subprocess.exec(["git", "--version"])
print("git:", version.strip())
