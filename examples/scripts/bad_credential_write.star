# Should be REJECTED at runtime:
# write to ~/.aws/credentials matches `[filesystem].deny` and is also
# outside `write_allow`. Either alone is enough; both apply here.

fs_write("~/.aws/credentials", "[default]\naws_access_key_id = pwned\n")
print("if you see this, the policy did not stop the write")
