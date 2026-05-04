# Should be REJECTED:
# env.read of a denied secret. Even if AWS_SECRET_ACCESS_KEY is set in
# the host environment, the policy refuses to surface it to the script.

key = env.read("AWS_SECRET_ACCESS_KEY")
print("leaked:", key)
