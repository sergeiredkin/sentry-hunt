# Security and privacy

This tool reads sensitive parts of your system in order to do its job. This page explains what it reads and where that data goes.

## What Sentry reads

- The file that stores password hashes (`/etc/shadow`)
- The list of running programs on your computer, including other users' programs if it has permission to see them
- Network connections that are open on your computer
- Login log entries (successful and failed logins)
- System files like `/etc/passwd`, `/etc/hosts`, and SSH settings

Sentry only **reads** this data. It never changes, deletes, or writes to any of these files.

## Where your data stays

Everything Sentry collects is stored in one local database file on your own computer (by default under `~/.local/share/sentry/`). Nothing is sent over the network. There is no cloud service involved.

## Permissions

You can run Sentry as a normal user. It will still work, but it will see less (for example, it cannot read other users' process details or the password hash file). If you want full visibility, run it with `sudo`. This is your choice each time you run it — Sentry does not require elevated permission to start.

## Reporting a problem

If you find a security problem in the code itself (not a false alarm from a scan), please open a GitHub issue or email sergei.redkin@gmail.com.
