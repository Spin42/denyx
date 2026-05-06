# Allowed pipeline: fetch GitHub API, store result locally.
# - net.http_get to api.github.com (in http_get_allow)
# - fs.write to /tmp/denyx_demo/zen.txt (in write_allow; fs.write is in
#   confirm_per_call, so pass --yes to auto-allow in CI)

zen = net.http_get("https://api.github.com/zen")
fs.write("/tmp/denyx_demo/zen.txt", zen)
print("wrote", len(zen), "bytes to /tmp/denyx_demo/zen.txt")
print("zen:", zen)
