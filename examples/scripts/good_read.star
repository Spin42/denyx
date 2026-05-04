# Allowed: read /etc/hostname (which is in fs.read_allow).

hostname = fs.read("/etc/hostname")
print("hostname:", hostname.strip())
