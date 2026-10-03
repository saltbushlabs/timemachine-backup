# Time Machine Server

A Docker container that serves Time Machine backup destinations over SMB. A web
UI manages them.

- **Repository**: one SMB share and one folder under `/backups`, normally one per
  Mac. Each can have a quota, which is the disk size the Mac sees.
- **Login**: an SMB username and password scoped to one repository. A
  repository can have several logins.
- Repositories that have at least one enabled login are advertised over Bonjour,
  so they show up in System Settings → Time Machine without any extra setup.

Inside the container:

- `smbd` (Samba with `vfs_fruit`)
- `avahi-daemon`
- the Go web app, which supervises both daemons and regenerates their config on
  every change

## Host setup (Ubuntu + ZFS)

```sh
sudo zfs create -o xattr=sa -o atime=off -o compression=lz4 -o recordsize=1M tank/timemachine
```

- `xattr=sa` matters. Samba stores macOS metadata in extended attributes.
- The backup folder must be a local filesystem. Sparsebundles get corrupted on
  NFS or CIFS mounts.
- Optionally set `zfs set quota=…` on the dataset as a hard cap for all
  repositories together.

Edit the `/backups` volume path in `docker-compose.yml`, then:

```sh
docker compose up -d
```

The image is built by GitHub Actions and published to
`ghcr.io/samfaunt/timemachine-backup`:

- every push to `main` updates `:latest`
- `v*` tags also publish version tags (`:1.2.0`, `:1.2`)

To update, run `docker compose pull && docker compose up -d`. To build locally
instead, run `docker build -t ghcr.io/samfaunt/timemachine-backup:latest .`.

Open `http://<host>:8080`. On first visit it asks you to create the admin
account.

The container uses host networking. It needs these ports free on the host:

| Port | Use |
| --- | --- |
| 445/tcp | SMB |
| 5353/udp | mDNS |
| 8080/tcp | web UI (change with `LISTEN_ADDR`) |

Nothing else on the host may be using them: no host Samba and no host
`avahi-daemon`. If mDNS fails to start, check `ss -lunp | grep 5353`. On Ubuntu,
`systemd-resolved` can hold that port when `MulticastDNS=yes`.

## Adding a Mac

1. Web UI → **New repository**, for example `sams-macbook`.
2. Open it → **Create login**. Leave the password blank to generate one.
   Copy it right away; it is shown only once.
3. On the Mac: System Settings → General → Time Machine → **Add Backup Disk**.
   Pick the repository and sign in with the login.

Alternatively, run the `tmutil setdestination` command the UI shows.

Turn on **Encrypt backups** on the Mac. The backups are then encrypted before
they reach the server.

## Operations

- **Disabling or deleting** a login or repository drops its open connections
  immediately. Time Machine reconnects using whatever access remains.
- **Deleting a repository** keeps the data unless you tick
  "Also delete backup data". If you create a repository with the same name
  later, it picks up the existing folder.
- **Forgot the admin password:**
  `docker exec timemachine timemachine reset-admin`, then reload the UI.
- **What persists in `/config`:**
  - `state.json`: repositories, logins and the admin account
  - `samba/`: SMB password hashes

  Back these up. Unix accounts inside the container are rebuilt from them on
  every start.
- **Stats** (disk used and last backup time) refresh every 10 minutes. A
  repository is marked *stale* when it has had no backup for 7 days.
- **Backup data** is owned on the host by uid/gid 1000 (`tmbackup`).

## Security notes

- Keep ports 445 and 8080 on the LAN. Don't forward them from the internet.
- The web UI uses plain HTTP. For access beyond a trusted LAN, put it behind a
  TLS reverse proxy.
- SMB requires SMB3. Guest access is disabled. Each user sees only the shares
  they can open.
