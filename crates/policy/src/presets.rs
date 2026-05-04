//! Built-in policy presets. A user file referencing
//! `inherits = "<name>"` gets that preset merged in as the base, with
//! the user's fields concatenated/overridden on top.
//!
//! Adding a preset is intentionally a code change, not a runtime
//! lookup against the filesystem — presets are part of the trust
//! boundary. Anything resolvable by a path or a network fetch could be
//! tampered with.

/// Universal-deny baseline. Every project, regardless of stack, wants
/// these denies. Capabilities not mentioned here are inherited
/// allow-empty (meaning the user file is the sole source of project
/// permissions).
pub const SECURE_DEFAULTS: &str = r#"
# Aegis built-in preset: secure-defaults.
#
# Universal denies that apply to any agent run, regardless of project
# stack. Inherits well-known credential paths, dangerous shell commands,
# secret env var names, and the cloud metadata IP. User files extend
# (concat) these lists; they cannot remove preset entries.

confirm_per_call = [
    "fs.delete",
    "subprocess.exec",
    "database.write",
]

[filesystem]
deny = [
    # User credentials, in every form they show up
    "~/.aws/**",
    "~/.ssh/**",
    "~/.config/gh/**",
    "~/.config/gcloud/**",
    "~/.netrc",
    "~/.docker/config.json",
    "~/.gem/credentials",
    "~/.kube/config",
    # Generic secret / dotenv conventions
    ".env",
    ".env.*",
    "**/.env",
    "**/.env.*",
    "**/secrets/**",
    "**/secrets.*",
    "**/credentials/**",
    "**/credentials.*",
    # System paths
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/sudoers.d/**",
]

[network]
# CIDR-aware. Blocks SSRF-style targets at the IP level: cloud
# metadata services, RFC 1918 internal ranges, loopback. Hostnames
# in HTTP requests are DNS-resolved at call time and each resolved
# IP is checked against this list, so a hostname that resolves to
# 192.168.1.1 is rejected the same way a literal 192.168.1.1 URL is.
deny_ips = [
    "169.254.0.0/16",   # link-local + cloud metadata (IMDSv1/2 lives at 169.254.169.254)
    "10.0.0.0/8",       # RFC 1918 private
    "172.16.0.0/12",    # RFC 1918 private
    "192.168.0.0/16",   # RFC 1918 private
    "127.0.0.0/8",      # IPv4 loopback
    "::1/128",          # IPv6 loopback
    "fc00::/7",         # IPv6 unique local
    "fe80::/10",        # IPv6 link-local
]

[environment]
deny_vars = [
    # Cloud / IaC
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_CLIENT_SECRET",
    # AI providers
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    # Source forge tokens
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITLAB_TOKEN",
    # Generic third-party SaaS
    "STRIPE_SECRET_KEY",
    "SENDGRID_API_KEY",
    "TWILIO_AUTH_TOKEN",
    "SLACK_TOKEN",
    "DOCKER_AUTH_CONFIG",
    # Database creds
    "DATABASE_URL",
    "DATABASE_PASSWORD",
]

[subprocess]
deny_commands = [
    # Filesystem destruction
    "rm",
    "dd",
    "mkfs",
    "shred",
    # Privilege escalation
    "sudo",
    "doas",
    "su",
    # Out-of-band network access (the agent should use net.* capabilities)
    "curl",
    "wget",
    "nc",
    # Remote shell
    "ssh",
    "scp",
    # Direct DB clients (force agents through database.* capability)
    "psql",
    "mysql",
    "redis-cli",
    "mongosh",
    # Deployment tools (force agents through deployment.* capability)
    "kubectl",
    "helm",
    "aws",
    "gcloud",
    "az",
    "flyctl",
    "heroku",
    "terraform",
    "pulumi",
]
"#;

/// Look up a preset by name. Returns the raw TOML source.
pub fn lookup(name: &str) -> Option<&'static str> {
    match name {
        "secure-defaults" => Some(SECURE_DEFAULTS),
        _ => None,
    }
}

/// All known preset names. Used in error messages.
pub fn names() -> Vec<&'static str> {
    vec!["secure-defaults"]
}
