# Allowed pipeline: fetch GitHub API, store result locally.
# - net_http_get to api.github.com (in http_get_allow)
# - fs_write to /tmp/aegis_demo/zen.txt (in write_allow; fs_write triggers
#   confirm-per-call — pass --yes to auto-allow in CI)

zen = net_http_get("https://api.github.com/zen")
fs_write("/tmp/aegis_demo/zen.txt", zen)
print("wrote", len(zen), "bytes to /tmp/aegis_demo/zen.txt")
print("zen:", zen)
