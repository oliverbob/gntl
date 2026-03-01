import os
import platform
import re
import stat
import subprocess
from typing import Dict
from pathlib import Path


PROJECT_ROOT = str(Path(__file__).resolve().parents[3])


def _safe_name(instance_id: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", instance_id).strip("-")
    return cleaned or "instance"


def _project_root() -> str:
    return PROJECT_ROOT


def _is_termux() -> bool:
    prefix = os.environ.get("PREFIX", "")
    return "com.termux" in prefix or bool(os.environ.get("TERMUX_VERSION"))


def _is_android() -> bool:
    return bool(os.environ.get("ANDROID_ROOT") or os.environ.get("ANDROID_DATA"))


def _arch() -> str:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "amd64"
    if "aarch64" in machine or machine == "arm64":
        return "arm64"
    if machine.startswith("arm"):
        return "arm"
    return machine or "unknown"


def _write_file(path: str, content: str, executable: bool = False):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    if executable:
        current = os.stat(path).st_mode
        os.chmod(path, current | stat.S_IXUSR)


def generate_service_bundle(instance_id: str, frpc_path: str, config_path: str) -> Dict:
    safe = _safe_name(instance_id)
    root = _project_root()
    services_root = os.path.join(root, "services")
    abs_frpc = os.path.abspath(frpc_path)
    abs_cfg = os.path.abspath(config_path)
    abs_root = os.path.abspath(root)

    systemd_dir = os.path.join(services_root, "systemd")
    launchd_dir = os.path.join(services_root, "launchd")
    windows_dir = os.path.join(services_root, "windows")
    termux_dir = os.path.join(services_root, "termux")
    os.makedirs(systemd_dir, exist_ok=True)
    os.makedirs(launchd_dir, exist_ok=True)
    os.makedirs(windows_dir, exist_ok=True)
    os.makedirs(termux_dir, exist_ok=True)

    unit_name = f"frpc-{safe}.service"
    systemd_unit_path = os.path.join(systemd_dir, unit_name)
    systemd_install_path = os.path.join(systemd_dir, f"install_{safe}.sh")
    systemd_unit = f"""[Unit]
Description=FRPC Tunnel {instance_id}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={abs_frpc} -c {abs_cfg}
Restart=always
RestartSec=3
WorkingDirectory={abs_root}

[Install]
WantedBy=default.target
"""
    systemd_install = f"""#!/usr/bin/env bash
set -euo pipefail
UNIT_NAME=\"{unit_name}\"
SRC=\"{systemd_unit_path}\"
TARGET_DIR=\"$HOME/.config/systemd/user\"
mkdir -p \"$TARGET_DIR\"
cp \"$SRC\" \"$TARGET_DIR/$UNIT_NAME\"
systemctl --user daemon-reload
systemctl --user enable --now \"$UNIT_NAME\"
echo \"Installed and enabled $UNIT_NAME\"
echo \"For reboot persistence on Linux, ensure linger is enabled:\"
echo \"  sudo loginctl enable-linger $USER\"
"""
    _write_file(systemd_unit_path, systemd_unit)
    _write_file(systemd_install_path, systemd_install, executable=True)

    launchd_label = f"com.gntl.frpc.{safe}"
    launchd_plist_path = os.path.join(launchd_dir, f"{launchd_label}.plist")
    launchd_install_path = os.path.join(launchd_dir, f"install_{safe}.sh")
    launchd_plist = f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
    <key>Label</key>
    <string>{launchd_label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{abs_frpc}</string>
        <string>-c</string>
        <string>{abs_cfg}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>{abs_root}</string>
    <key>StandardOutPath</key>
    <string>/tmp/{safe}.launchd.out.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/{safe}.launchd.err.log</string>
</dict>
</plist>
"""
    launchd_install = f"""#!/usr/bin/env bash
set -euo pipefail
LABEL=\"{launchd_label}\"
SRC=\"{launchd_plist_path}\"
TARGET=\"$HOME/Library/LaunchAgents/$LABEL.plist\"
mkdir -p \"$HOME/Library/LaunchAgents\"
cp \"$SRC\" \"$TARGET\"
launchctl unload \"$TARGET\" 2>/dev/null || true
launchctl load -w \"$TARGET\"
echo \"Installed and loaded $LABEL\"
"""
    _write_file(launchd_plist_path, launchd_plist)
    _write_file(launchd_install_path, launchd_install, executable=True)

    windows_task_name = f"gntl-frpc-{safe}"
    windows_install_path = os.path.join(windows_dir, f"install_{safe}.ps1")
    windows_install = f"""$TaskName = \"{windows_task_name}\"
$FrpcPath = \"{abs_frpc}\"
$ConfigPath = \"{abs_cfg}\"
$Action = New-ScheduledTaskAction -Execute $FrpcPath -Argument ('-c "' + $ConfigPath + '"')
$Triggers = @(
    New-ScheduledTaskTrigger -AtStartup,
    New-ScheduledTaskTrigger -AtLogOn
)
$Settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Triggers -Settings $Settings -Description \"FRPC tunnel {instance_id}\" -Force
Write-Output \"Installed scheduled task $TaskName\"
"""
    _write_file(windows_install_path, windows_install)

    termux_boot_script_path = os.path.join(termux_dir, f"start_{safe}.sh")
    termux_install_path = os.path.join(termux_dir, f"install_{safe}.sh")
    termux_boot_script = f"""#!/data/data/com.termux/files/usr/bin/bash
{abs_frpc} -c {abs_cfg}
"""
    termux_install = f"""#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
BOOT_DIR=\"$HOME/.termux/boot\"
mkdir -p \"$BOOT_DIR\"
cp \"{termux_boot_script_path}\" \"$BOOT_DIR/frpc-{safe}.sh\"
chmod +x \"$BOOT_DIR/frpc-{safe}.sh\"
echo \"Installed Termux boot script for {instance_id}\"
echo \"Install Termux:Boot app and allow boot execution.\"
"""
    _write_file(termux_boot_script_path, termux_boot_script, executable=True)
    _write_file(termux_install_path, termux_install, executable=True)

    return {
        "instanceId": instance_id,
        "serviceName": safe,
        "architecture": _arch(),
        "paths": {
            "systemdUnit": systemd_unit_path,
            "systemdInstall": systemd_install_path,
            "launchdPlist": launchd_plist_path,
            "launchdInstall": launchd_install_path,
            "windowsInstall": windows_install_path,
            "termuxBootScript": termux_boot_script_path,
            "termuxInstall": termux_install_path,
        },
        "installCommands": {
            "linux": f"bash {systemd_install_path}",
            "macos": f"bash {launchd_install_path}",
            "windows": f"powershell -ExecutionPolicy Bypass -File {windows_install_path}",
            "termux": f"bash {termux_install_path}",
            "android": "Termux recommended: install Termux + Termux:Boot and run the termux install command.",
            "ios": "Auto-start service install is not supported on iOS due platform restrictions.",
        },
    }


def generate_manager_service_bundle(run_script_path: str, write_files: bool = True) -> Dict:
    safe = "manager"
    root = _project_root()
    services_root = os.path.join(root, "services")
    abs_run_script = os.path.abspath(run_script_path)
    abs_root = os.path.abspath(root)

    systemd_dir = os.path.join(services_root, "systemd")
    launchd_dir = os.path.join(services_root, "launchd")
    windows_dir = os.path.join(services_root, "windows")
    termux_dir = os.path.join(services_root, "termux")
    os.makedirs(systemd_dir, exist_ok=True)
    os.makedirs(launchd_dir, exist_ok=True)
    os.makedirs(windows_dir, exist_ok=True)
    os.makedirs(termux_dir, exist_ok=True)

    unit_name = "gntl-manager.service"
    systemd_unit_path = os.path.join(systemd_dir, unit_name)
    systemd_install_path = os.path.join(systemd_dir, "install_manager.sh")
    systemd_unit = f"""[Unit]
Description=GNTL Manager Web Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/env bash {abs_run_script}
Restart=always
RestartSec=3
WorkingDirectory={abs_root}

[Install]
WantedBy=default.target
"""
    systemd_install = f"""#!/usr/bin/env bash
set -euo pipefail
UNIT_NAME=\"{unit_name}\"
SRC=\"{systemd_unit_path}\"
TARGET_DIR=\"$HOME/.config/systemd/user\"
mkdir -p \"$TARGET_DIR\"
cp \"$SRC\" \"$TARGET_DIR/$UNIT_NAME\"
systemctl --user daemon-reload
systemctl --user enable --now \"$UNIT_NAME\"
echo \"Installed and enabled $UNIT_NAME\"
echo \"For reboot persistence on Linux, ensure linger is enabled:\"
echo \"  sudo loginctl enable-linger $USER\"
"""
    if write_files:
        _write_file(systemd_unit_path, systemd_unit)
        _write_file(systemd_install_path, systemd_install, executable=True)

    launchd_label = "com.gntl.manager"
    launchd_plist_path = os.path.join(launchd_dir, f"{launchd_label}.plist")
    launchd_install_path = os.path.join(launchd_dir, "install_manager.sh")
    launchd_plist = f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
    <key>Label</key>
    <string>{launchd_label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/env</string>
        <string>bash</string>
        <string>{abs_run_script}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>{abs_root}</string>
    <key>StandardOutPath</key>
    <string>/tmp/gntl-manager.out.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/gntl-manager.err.log</string>
</dict>
</plist>
"""
    launchd_install = f"""#!/usr/bin/env bash
set -euo pipefail
LABEL=\"{launchd_label}\"
SRC=\"{launchd_plist_path}\"
TARGET=\"$HOME/Library/LaunchAgents/$LABEL.plist\"
mkdir -p \"$HOME/Library/LaunchAgents\"
cp \"$SRC\" \"$TARGET\"
launchctl unload \"$TARGET\" 2>/dev/null || true
launchctl load -w \"$TARGET\"
echo \"Installed and loaded $LABEL\"
"""
    if write_files:
        _write_file(launchd_plist_path, launchd_plist)
        _write_file(launchd_install_path, launchd_install, executable=True)

    windows_task_name = "gntl-manager"
    windows_install_path = os.path.join(windows_dir, "install_manager.ps1")
    windows_install = f"""$TaskName = \"{windows_task_name}\"
$RunScript = \"{abs_run_script}\"
$Action = New-ScheduledTaskAction -Execute \"powershell.exe\" -Argument ('-NoProfile -ExecutionPolicy Bypass -Command "& '' + $RunScript + ''"')
$Triggers = @(
    New-ScheduledTaskTrigger -AtStartup,
    New-ScheduledTaskTrigger -AtLogOn
)
$Settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Triggers -Settings $Settings -Description \"GNTL Manager Web Server\" -Force
Write-Output \"Installed scheduled task $TaskName\"
"""
    if write_files:
        _write_file(windows_install_path, windows_install)

    termux_boot_script_path = os.path.join(termux_dir, "start_manager.sh")
    termux_install_path = os.path.join(termux_dir, "install_manager.sh")
    termux_boot_script = f"""#!/data/data/com.termux/files/usr/bin/bash
bash {abs_run_script}
"""
    termux_install = f"""#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
BOOT_DIR=\"$HOME/.termux/boot\"
mkdir -p \"$BOOT_DIR\"
cp \"{termux_boot_script_path}\" \"$BOOT_DIR/gntl-manager.sh\"
chmod +x \"$BOOT_DIR/gntl-manager.sh\"
echo \"Installed Termux boot script for manager\"
echo \"Install Termux:Boot app and allow boot execution.\"
"""
    if write_files:
        _write_file(termux_boot_script_path, termux_boot_script, executable=True)
        _write_file(termux_install_path, termux_install, executable=True)

    return {
        "serviceName": safe,
        "architecture": _arch(),
        "paths": {
            "systemdUnit": systemd_unit_path,
            "systemdInstall": systemd_install_path,
            "launchdPlist": launchd_plist_path,
            "launchdInstall": launchd_install_path,
            "windowsInstall": windows_install_path,
            "termuxBootScript": termux_boot_script_path,
            "termuxInstall": termux_install_path,
        },
        "installCommands": {
            "linux": f"bash {systemd_install_path}",
            "macos": f"bash {launchd_install_path}",
            "windows": f"powershell -ExecutionPolicy Bypass -File {windows_install_path}",
            "termux": f"bash {termux_install_path}",
            "android": "Termux recommended: install Termux + Termux:Boot and run the termux install command.",
            "ios": "Auto-start service install is not supported on iOS due platform restrictions.",
        },
    }


def install_service_for_current_platform(bundle: Dict) -> Dict:
    if _is_termux():
        system = "termux"
    elif _is_android():
        system = "android"
    else:
        system = platform.system().lower()
    try:
        if system == "termux":
            cmd = ["bash", bundle["paths"]["termuxInstall"]]
        elif system == "linux":
            cmd = ["bash", bundle["paths"]["systemdInstall"]]
        elif system == "darwin":
            cmd = ["bash", bundle["paths"]["launchdInstall"]]
        elif system == "windows":
            cmd = [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                bundle["paths"]["windowsInstall"],
            ]
        elif system == "android":
            return {
                "attempted": False,
                "installed": False,
                "platform": system,
                "error": "Android direct service install is not supported; use Termux + Termux:Boot.",
            }
        elif system in ("ios",):
            return {
                "attempted": False,
                "installed": False,
                "platform": system,
                "error": "iOS service auto-install is not supported by platform restrictions.",
            }
        else:
            return {
                "attempted": False,
                "installed": False,
                "platform": system,
                "error": "unsupported platform",
            }

        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode == 0:
            return {
                "attempted": True,
                "installed": True,
                "platform": system,
                "output": (proc.stdout or "").strip(),
            }
        return {
            "attempted": True,
            "installed": False,
            "platform": system,
            "error": (proc.stderr or proc.stdout or "installation failed").strip(),
        }
    except Exception as e:
        return {
            "attempted": True,
            "installed": False,
            "platform": system,
            "error": str(e),
        }
