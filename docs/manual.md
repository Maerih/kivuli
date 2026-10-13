Kivuli runs on any Linux server the same way it runs here: copy the folder, run `./ctl.sh start`, then put TLS in front of the console. I haven't deployed it to a remote server myself, so treat this as the procedure rather than something I've tested end to end.

## What the server needs

- **OS:** 64-bit Linux (x86_64) with systemd and user namespaces enabled. Debian 12 or Ubuntu 22.04+ are fine.
- **Size:** at least 4 CPU cores, 8 GB RAM and 40 GB disk. The search node alone takes about 1.5 GB.
- **Packages:** `python3`, `curl`, `uidmap` and `slirp4netns` (the last two are what rootless Docker needs).
- **Outbound network:** Tor (ports 9001/443) and HTTPS must be allowed out. No inbound port is needed except the one you choose for the console.
- **A normal user account,** not root. Nothing is installed system-wide.

## Steps

1. **Take a backup here first** if you want to keep what has been collected:

```bash
./ctl.sh backup
```

2. **Copy the project to the server,** leaving out the local Docker runtime and build caches (they are rebuilt there):

```bash
rsync -a --exclude .runtime --exclude node_modules --exclude .next --exclude backups /home/kali/Projects/theHPA/kivuli/ user@your-server:~/kivuli/
```

3. **On the server, decide about `.env`.** The rsync copies your current `.env`, which keeps the same secrets, so a restored backup will work. For a clean install with new secrets, delete it and `ctl.sh` will generate a fresh one.

4. **Let the service survive logout and reboot** (run once on the server, as your user):

```bash
loginctl enable-linger $USER
```

5. **Start it.** The first start downloads Docker into the folder and builds four images, so allow 15–30 minutes:

```bash
cd ~/kivuli && ./ctl.sh start
```

6. **Restore your data** if you took the backup (copy the backup folder across first):

```bash
./ctl.sh restore backups/kivuli-<date>
```

## Reaching the console

The console listens on `127.0.0.1:3000` only, on purpose. Two ways to reach it:

- **SSH tunnel (simplest, nothing exposed):** run this on your own machine, then open http://localhost:3000.

```bash
ssh -L 3000:127.0.0.1:3000 user@your-server
```

- **Reverse proxy with TLS (for the team):** put nginx or Caddy on the server, proxy `https://kivuli.yourdomain` to `127.0.0.1:3000`, and set these in `.env` before `./ctl.sh restart`:

```ini
PUBLIC_URL=https://kivuli.yourdomain
COOKIE_SECURE=true
REQUIRE_MFA=true
```

I'd recommend the tunnel, or the proxy restricted to your VPN or office IPs. This tool holds leaked-credential intelligence and should not sit on the open internet.

## Before the team uses it

- Change the admin password and turn on two-step sign-in for every account.
- Set real SMTP settings in `.env` and remove the `mailpit` service; otherwise alert email goes to the test inbox.
- Check the hosting provider's terms: some forbid Tor traffic, even client-only.
- The docker daemon does not restart by itself after a reboot. Add a systemd user unit or a cron `@reboot` line that runs `./ctl.sh start`.

Tell me the server's OS and how you plan to reach it (tunnel, VPN or public domain), and I can write the exact proxy config and the reboot unit for it.

Run this from the project folder:

```bash
cd /home/kali/Projects/theHPA/kivuli && ./ctl.sh start
```

Then open http://localhost:3000 and sign in:

- **Email:** `admin@kivuli.local`
- **Password:** the value of `BOOTSTRAP_ADMIN_PASSWORD` in the `.env` file in that folder

To see it:

```bash
grep BOOTSTRAP_ADMIN_PASSWORD /home/kali/Projects/theHPA/kivuli/.env
```

The other commands you'll use:

| Command | Does |
|---|---|
| `./ctl.sh status` | Shows whether the 13 containers are up |
| `./ctl.sh stop` | Stops everything (data is kept) |
| `./ctl.sh restart` | Stop, then start |
| `./ctl.sh logs api` | Follows the logs of one service (`api`, `crawler`, `tor`, `web`, …) |

Things to know:

- **After a reboot it does not start by itself.** Run `./ctl.sh start` again.
- **Starting takes a minute or two** when the images are already built, as they are on this machine. Tor needs about another minute before the command centre shows "Tor connection: Online".
- **Alert email goes to a test inbox** at http://localhost:8025 until you configure a real mail relay.

If `./ctl.sh start` prints an error, paste it here and I'll sort it out.
