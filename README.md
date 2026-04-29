# Campus Auto Login

This folder contains a PowerShell-first script set for UCAS/SRun campus portal auto login. Windows is the primary supported platform; Ubuntu can run the core login script with PowerShell 7, but needs different credential protection and startup service setup.

## First-time setup

Run PowerShell in this folder:

```powershell
.\setup.ps1
```

Enter your campus username and password. On Windows, the password is saved to `credential.xml` with Windows DPAPI encryption, so it can only be read by the same Windows user on the same computer. On Ubuntu/non-Windows PowerShell, `setup.ps1` will warn you because the same file is not protected by DPAPI.

## One-time check

From PowerShell:

```powershell
.\check-now.ps1
```

This checks internet status, checks portal status, and logs in if the campus portal reports offline. Some campus networks allow a few public sites before login, so portal status is treated as the source of truth.

## Repair current session

If VPN/remote software reports an error while the portal still says online, run:

```powershell
.\repair-now.ps1
```

This logs out of the campus portal and logs in again. It can briefly interrupt active network connections.

## Keep monitoring

```powershell
.\run-autologin.ps1
```

The default interval is 30 seconds. When remote/VPN-like software listed in `config.json` is running, the interval becomes 10 seconds.

The script uses a single-instance lock, so only one `auto-login.ps1` process can run from this folder at a time. If another copy is already running, a new `check-now.ps1`, `repair-now.ps1`, or `run-autologin.ps1` exits with a lock message.

Stop the monitor with Ctrl+C in its PowerShell window, or end the PowerShell process in Task Manager / Process Manager.

## Start automatically with Windows

```powershell
.\task.ps1 -Action Install
```

Check or remove it later with:

```powershell
.\task.ps1 -Action Status
.\task.ps1 -Action Uninstall
```

## Ubuntu notes

Install PowerShell 7 (`pwsh`) first. Then run the same entrypoints with `pwsh`, for example:

```bash
pwsh ./check-now.ps1
```

The portal HTTP/login code is PowerShell/.NET and should work, but these parts are Windows-oriented:

- `setup.ps1` uses `Export-Clixml`; on Ubuntu it is not protected by Windows DPAPI.
- `task.ps1` uses Windows Task Scheduler, not systemd.

For Ubuntu, prefer environment-specific hardening such as a protected user account, a root-owned service file, or PowerShell SecretManagement before storing the password long-term.

## Status and logs

- `status.html` auto-refreshes every 10 seconds.
- `status.json` contains the latest machine-readable status.
- `logs/auto-login-YYYYMMDD.log` contains check/login history.

## Config

On first run, `auto-login.ps1` creates `config.json` from `config.example.json` if needed. Edit `config.json` for local settings. The portal API host is `https://portal.ucas.ac.cn`, matching the saved login HTML. The campus auth IP `124.16.81.61` is kept in the config for reference.
