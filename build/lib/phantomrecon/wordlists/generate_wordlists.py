"""Helper to generate wordlist files by expanding micro list."""
import random
import os

micro_entries = []
with open("micro.txt") as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith("#"):
            micro_entries.append(line)

extra_small = [
    "about-us", "about_us", "contact-us", "contact_us", "sitemap",
    "feeds", "feed", "rss", "atom", "newsletter", "subscribe", "unsubscribe",
    "privacy", "terms", "tos", "eula", "legal", "copyright",
    "404", "500", "403", "maintenance", "coming-soon", "offline",
    "ajax", "callback", "webhook", "webhooks", "event", "events",
    "notification", "notifications", "alert", "alerts",
    "download", "downloads", "upload-file", "export", "import",
    "print", "share", "embed", "iframe",
    "payment", "payments", "checkout", "cart", "order", "orders",
    "invoice", "invoices", "billing", "subscription", "subscriptions",
    "plan", "plans", "pricing", "upgrade", "downgrade",
    "invite", "invitation", "referral", "affiliate",
    "verify", "verification", "confirm", "confirmation",
    "activate", "deactivate", "enable", "disable", "block", "unblock",
    "ban", "unban", "suspend", "unsuspend",
    "bulk", "batch", "import", "export", "migrate", "migration",
    "backup-restore", "restore", "recover", "recovery",
    "config.bak", "config.old", "config.orig", "config.save",
    "web.config.bak", ".env~", "settings.bak",
    "access", "token", "api-key", "apikey", "key", "keys",
    "secret.txt", "secret.json", "secrets.json", "config.json",
    "config.yml", "config.yaml", "app.config", "app.json",
    "application.properties", "application.yml", "application.yaml",
    "appsettings.json", "appsettings.Development.json",
    "database.yml", "database.json", "db.json", "db.yml",
    "redis.conf", "nginx.conf", "apache.conf", "httpd.conf",
    "php.ini", "php.ini.bak", "my.cnf", "postgresql.conf",
    "id_rsa", "id_rsa.pub", "id_dsa", "authorized_keys", "known_hosts",
    ".bash_history", ".zsh_history", ".mysql_history", ".psql_history",
    "wp-config.php.bak", "wp-config.php.old", "wp-config.bak",
    "old", "new", "copy", "bak", "backup2", "backup3",
    "test2", "test3", "dev", "development", "staging", "production", "prod",
    "uat", "qa", "sandbox", "demo", "preview", "beta", "alpha",
    "v1", "v2", "v3", "v4", "v5", "version1", "version2",
    "2020", "2021", "2022", "2023", "2024",
    "jan", "feb", "mar", "apr", "may", "jun",
    "jul", "aug", "sep", "oct", "nov", "dec",
]

all_small = list(set(micro_entries + extra_small))
random.shuffle(all_small)

with open("small.txt", "w") as f:
    f.write("# PhantomRecon small wordlist\n")
    for w in all_small[:5000]:
        f.write(w + "\n")

with open("medium.txt", "w") as f:
    f.write("# PhantomRecon medium wordlist\n")
    for w in all_small:
        f.write(w + "\n")
    for w in all_small:
        for suffix in ["_1", "_2", "_test", "_dev", "_backup", "_old", "_bak", "-test", "-dev", "-backup"]:
            f.write(w + suffix + "\n")

print("Generated wordlists.")
