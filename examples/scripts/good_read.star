# Allowed: read /etc/hostname (which is in fs.read_allow).

hostname = fs_read("/etc/hostname")
print("hostname:", hostname.strip())
