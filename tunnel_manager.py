import os
import json
import glob
import subprocess
import threading
import time
import signal
import re
import shutil
from collections import deque
from typing import Optional

class FrpcInstance:
    def __init__(self, id: str, config_path: str, cmd: Optional[list]=None, metadata: Optional[dict]=None):
        self.id = id
        self.config_path = config_path
        self.cmd = cmd or []
        self.metadata = metadata or {}
        self.enabled = bool(self.metadata.get('enabled', True))
        self.process: Optional[subprocess.Popen] = None
        self.external_pid: Optional[int] = None
        self.status = 'stopped'
        self.logs = deque(maxlen=1000)
        self._lock = threading.Lock()

    def _reader(self, stream):
        try:
            for line in iter(stream.readline, b''):
                decoded = line.decode(errors='ignore').rstrip()
                with self._lock:
                    self.logs.append(decoded)
            stream.close()
        except Exception:
            pass

    def start(self, executable_path: str):
        if self.process and self.process.poll() is None:
            self.status = 'running'
            return
        args = [executable_path, '-c', self.config_path]
        self.process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.external_pid = None
        t1 = threading.Thread(target=self._reader, args=(self.process.stdout,), daemon=True)
        t2 = threading.Thread(target=self._reader, args=(self.process.stderr,), daemon=True)
        t1.start(); t2.start()
        self.status = 'running'

    def stop(self):
        if not self.process:
            self.status = 'stopped'
            return
        try:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        except Exception:
            pass
        self.status = 'stopped'

    def restart(self, executable_path: str):
        self.stop()
        time.sleep(0.2)
        self.start(executable_path)

    def tail(self, lines=200):
        with self._lock:
            return list(self.logs)[-lines:]


class FrpcManager:
    def __init__(self):
        self.instances = {}
        self.base_dir = os.path.dirname(__file__)
        self.configs_dir = os.path.join(self.base_dir, 'configs')
        self.state_file = os.path.join(self.configs_dir, 'instances_state.json')
        self.pid_prefix = '.gntl-frpc-'

    def _normalize_config_path(self, config_path: str) -> str:
        if not isinstance(config_path, str):
            return ''
        if os.path.isabs(config_path):
            return os.path.realpath(config_path)
        return os.path.realpath(os.path.join(self.base_dir, config_path))

    def _safe_service_name(self, instance_id: str) -> str:
        cleaned = re.sub(r'[^A-Za-z0-9_.-]+', '-', str(instance_id or '')).strip('-')
        return cleaned or 'instance'

    def _safe_pid_name(self, instance_id: str) -> str:
        cleaned = re.sub(r'[^A-Za-z0-9_.-]+', '_', str(instance_id or '')).strip('_')
        return cleaned or 'instance'

    def _pid_file_path(self, instance_id: str) -> str:
        safe = self._safe_pid_name(instance_id)
        return os.path.join(self.configs_dir, f'{self.pid_prefix}{safe}.pid')

    def _sibling_instance_id(self, instance_id: str, target_protocol: str) -> Optional[str]:
        if not isinstance(instance_id, str):
            return None
        if instance_id.endswith('-http'):
            base = instance_id[:-5]
        elif instance_id.endswith('-https'):
            base = instance_id[:-6]
        else:
            return None
        if target_protocol == 'http':
            return base + '-http'
        if target_protocol == 'https':
            return base + '-https'
        return None

    def _is_instance_running(self, instance_id: str) -> bool:
        inst = self.instances.get(instance_id)
        if not inst:
            return False
        if inst.process and inst.process.poll() is None:
            return True
        pid_from_file = self._read_instance_pid_file(instance_id, inst.config_path)
        if isinstance(pid_from_file, int):
            inst.external_pid = pid_from_file
            inst.status = 'running'
            return True
        running_pids = self._find_running_pids_for_config(inst.config_path)
        if running_pids:
            inst.external_pid = running_pids[0]
            self._write_instance_pid_file(instance_id, inst.external_pid)
            inst.status = 'running'
            return True
        return False

    def _write_instance_pid_file(self, instance_id: str, pid: int):
        if not isinstance(pid, int) or pid <= 1:
            return
        os.makedirs(self.configs_dir, exist_ok=True)
        pid_path = self._pid_file_path(instance_id)
        try:
            with open(pid_path, 'w', encoding='utf-8') as f:
                f.write(str(pid))
        except Exception:
            pass

    def _remove_instance_pid_file(self, instance_id: str):
        pid_path = self._pid_file_path(instance_id)
        if os.path.exists(pid_path):
            try:
                os.remove(pid_path)
            except Exception:
                pass

    def _read_instance_pid_file(self, instance_id: str, expected_config_path: Optional[str] = None):
        pid_path = self._pid_file_path(instance_id)
        if not os.path.exists(pid_path):
            return None
        try:
            raw = (open(pid_path, 'r', encoding='utf-8').read() or '').strip()
        except Exception:
            self._remove_instance_pid_file(instance_id)
            return None

        if not raw.isdigit():
            self._remove_instance_pid_file(instance_id)
            return None

        pid = int(raw)
        if not self._is_pid_running(pid):
            self._remove_instance_pid_file(instance_id)
            return None

        if expected_config_path:
            cmd = self._read_proc_cmdline(pid)
            if not cmd:
                self._remove_instance_pid_file(instance_id)
                return None
            cfg_value = None
            for idx, arg in enumerate(cmd):
                if arg == '-c' and idx + 1 < len(cmd):
                    cfg_value = cmd[idx + 1]
                    break
                if arg.startswith('-c') and len(arg) > 2:
                    cfg_value = arg[2:]
                    break
            if not cfg_value:
                self._remove_instance_pid_file(instance_id)
                return None
            if self._normalize_config_path(cfg_value) != self._normalize_config_path(expected_config_path):
                self._remove_instance_pid_file(instance_id)
                return None

        return pid

    def _run_quiet(self, args):
        try:
            subprocess.run(args, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    def _cleanup_instance_services(self, instance_id: str):
        safe = self._safe_service_name(instance_id)
        services_root = os.path.join(self.base_dir, 'services')

        unit_name = f'frpc-{safe}.service'
        user_systemd_dir = os.path.expanduser('~/.config/systemd/user')
        user_unit_path = os.path.join(user_systemd_dir, unit_name)
        if shutil.which('systemctl'):
            self._run_quiet(['systemctl', '--user', 'stop', unit_name])
            self._run_quiet(['systemctl', '--user', 'disable', unit_name])
        if os.path.exists(user_unit_path):
            try:
                os.remove(user_unit_path)
            except Exception:
                pass
            if shutil.which('systemctl'):
                self._run_quiet(['systemctl', '--user', 'daemon-reload'])
                self._run_quiet(['systemctl', '--user', 'reset-failed', unit_name])

        launchd_label = f'com.gntl.frpc.{safe}'
        launchd_target = os.path.expanduser(f'~/Library/LaunchAgents/{launchd_label}.plist')
        if shutil.which('launchctl'):
            self._run_quiet(['launchctl', 'unload', launchd_target])
            self._run_quiet(['launchctl', 'remove', launchd_label])
        if os.path.exists(launchd_target):
            try:
                os.remove(launchd_target)
            except Exception:
                pass

        termux_boot = os.path.expanduser(f'~/.termux/boot/frpc-{safe}.sh')
        if os.path.exists(termux_boot):
            try:
                os.remove(termux_boot)
            except Exception:
                pass

        generated_paths = [
            os.path.join(services_root, 'systemd', unit_name),
            os.path.join(services_root, 'systemd', f'install_{safe}.sh'),
            os.path.join(services_root, 'launchd', f'{launchd_label}.plist'),
            os.path.join(services_root, 'launchd', f'install_{safe}.sh'),
            os.path.join(services_root, 'windows', f'install_{safe}.ps1'),
            os.path.join(services_root, 'termux', f'start_{safe}.sh'),
            os.path.join(services_root, 'termux', f'install_{safe}.sh'),
        ]
        for path in generated_paths:
            if os.path.exists(path):
                try:
                    os.remove(path)
                except Exception:
                    pass

    def _load_state(self):
        if not os.path.exists(self.state_file):
            return {}
        try:
            with open(self.state_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save_state(self):
        os.makedirs(self.configs_dir, exist_ok=True)
        payload = {
            id: {
                'config_path': inst.config_path,
                'metadata': inst.metadata or {}
            }
            for id, inst in self.instances.items()
        }
        for id, inst in self.instances.items():
            payload[id]['metadata']['enabled'] = bool(inst.enabled)
        with open(self.state_file, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=2)

    def _read_proc_cmdline(self, pid: int):
        proc_path = f'/proc/{pid}/cmdline'
        if not os.path.exists(proc_path):
            return []
        try:
            with open(proc_path, 'rb') as f:
                raw = f.read()
            if not raw:
                return []
            parts = [p.decode(errors='ignore') for p in raw.split(b'\x00') if p]
            return parts
        except Exception:
            return []

    def _is_pid_running(self, pid: int) -> bool:
        if not isinstance(pid, int) or pid <= 1:
            return False
        try:
            os.kill(pid, 0)
            return True
        except Exception:
            return False

    def _find_running_pids_for_config(self, config_path: str):
        target = self._normalize_config_path(config_path)
        pids = []

        proc_root = '/proc'
        if not os.path.isdir(proc_root):
            return pids

        for entry in os.listdir(proc_root):
            if not entry.isdigit():
                continue
            pid = int(entry)
            cmd = self._read_proc_cmdline(pid)
            if not cmd:
                continue

            exe = os.path.basename(cmd[0])
            if 'frpc' not in exe:
                continue

            cfg_value = None
            for idx, arg in enumerate(cmd):
                if arg == '-c' and idx + 1 < len(cmd):
                    cfg_value = cmd[idx + 1]
                    break
                if arg.startswith('-c') and len(arg) > 2:
                    cfg_value = arg[2:]
                    break

            if not cfg_value:
                continue

            if self._normalize_config_path(cfg_value) == target:
                pids.append(pid)

        return pids

    def _list_running_frpc_processes(self):
        processes = []
        proc_root = '/proc'
        if not os.path.isdir(proc_root):
            return processes

        for entry in os.listdir(proc_root):
            if not entry.isdigit():
                continue
            pid = int(entry)
            cmd = self._read_proc_cmdline(pid)
            if not cmd:
                continue
            exe = os.path.basename(cmd[0])
            if 'frpc' not in exe:
                continue

            cfg_value = None
            for idx, arg in enumerate(cmd):
                if arg == '-c' and idx + 1 < len(cmd):
                    cfg_value = cmd[idx + 1]
                    break
                if arg.startswith('-c') and len(arg) > 2:
                    cfg_value = arg[2:]
                    break

            if not cfg_value:
                continue

            processes.append({
                'pid': pid,
                'configPath': self._normalize_config_path(cfg_value),
            })

        return processes

    def _remove_generated_paths_for_safe(self, safe: str):
        if not safe or safe == 'manager':
            return 0
        services_root = os.path.join(self.base_dir, 'services')
        launchd_label = f'com.gntl.frpc.{safe}'
        candidate_paths = [
            os.path.join(services_root, 'systemd', f'frpc-{safe}.service'),
            os.path.join(services_root, 'systemd', f'install_{safe}.sh'),
            os.path.join(services_root, 'launchd', f'{launchd_label}.plist'),
            os.path.join(services_root, 'launchd', f'install_{safe}.sh'),
            os.path.join(services_root, 'windows', f'install_{safe}.ps1'),
            os.path.join(services_root, 'termux', f'start_{safe}.sh'),
            os.path.join(services_root, 'termux', f'install_{safe}.sh'),
        ]
        removed = 0
        for path in candidate_paths:
            if os.path.exists(path):
                try:
                    os.remove(path)
                    removed += 1
                except Exception:
                    pass
        return removed

    def cleanup_deleted_instances(self):
        valid_instance_ids = set(self.instances.keys())
        valid_safe_names = {self._safe_service_name(instance_id) for instance_id in valid_instance_ids}
        valid_pid_names = {self._safe_pid_name(instance_id) for instance_id in valid_instance_ids}
        configs_dir_real = os.path.realpath(self.configs_dir)

        killed_pids = []
        for process in self._list_running_frpc_processes():
            pid = process.get('pid')
            config_path = process.get('configPath') or ''
            if not isinstance(pid, int):
                continue

            should_kill = False
            if not config_path or not os.path.exists(config_path):
                should_kill = True
            else:
                if os.path.realpath(os.path.dirname(config_path)) == configs_dir_real:
                    instance_id = os.path.splitext(os.path.basename(config_path))[0]
                    if instance_id not in valid_instance_ids:
                        should_kill = True

            if should_kill:
                self._terminate_pid(pid)
                killed_pids.append(pid)

        orphan_safe_names = set()
        services_root = os.path.join(self.base_dir, 'services')

        removed_pid_files = 0
        for pid_path in glob.glob(os.path.join(self.configs_dir, f'{self.pid_prefix}*.pid')):
            base = os.path.basename(pid_path)
            if not base.startswith(self.pid_prefix) or not base.endswith('.pid'):
                continue
            safe_pid_name = base[len(self.pid_prefix):-len('.pid')]
            if safe_pid_name and safe_pid_name in valid_pid_names:
                continue

            pid_value = None
            try:
                raw = (open(pid_path, 'r', encoding='utf-8').read() or '').strip()
                if raw.isdigit():
                    pid_value = int(raw)
            except Exception:
                pass
            if isinstance(pid_value, int) and self._is_pid_running(pid_value):
                self._terminate_pid(pid_value)
                killed_pids.append(pid_value)
            try:
                os.remove(pid_path)
                removed_pid_files += 1
            except Exception:
                pass

        systemd_dir = os.path.join(services_root, 'systemd')
        for service_path in glob.glob(os.path.join(systemd_dir, 'frpc-*.service')):
            name = os.path.basename(service_path)
            safe = name[len('frpc-'):-len('.service')]
            if safe and safe not in valid_safe_names:
                orphan_safe_names.add(safe)

        launchd_dir = os.path.join(services_root, 'launchd')
        for plist_path in glob.glob(os.path.join(launchd_dir, 'com.gntl.frpc.*.plist')):
            name = os.path.basename(plist_path)
            safe = name[len('com.gntl.frpc.'):-len('.plist')]
            if safe and safe not in valid_safe_names:
                orphan_safe_names.add(safe)

        stopped_units = []
        removed_files = 0
        for safe in sorted(orphan_safe_names):
            unit_name = f'frpc-{safe}.service'
            if shutil.which('systemctl'):
                self._run_quiet(['systemctl', '--user', 'stop', unit_name])
                self._run_quiet(['systemctl', '--user', 'disable', unit_name])
                self._run_quiet(['systemctl', '--user', 'reset-failed', unit_name])
            user_unit_path = os.path.expanduser(f'~/.config/systemd/user/{unit_name}')
            if os.path.exists(user_unit_path):
                try:
                    os.remove(user_unit_path)
                    removed_files += 1
                except Exception:
                    pass
                if shutil.which('systemctl'):
                    self._run_quiet(['systemctl', '--user', 'daemon-reload'])

            launchd_label = f'com.gntl.frpc.{safe}'
            launchd_target = os.path.expanduser(f'~/Library/LaunchAgents/{launchd_label}.plist')
            if shutil.which('launchctl'):
                self._run_quiet(['launchctl', 'unload', launchd_target])
                self._run_quiet(['launchctl', 'remove', launchd_label])
            if os.path.exists(launchd_target):
                try:
                    os.remove(launchd_target)
                    removed_files += 1
                except Exception:
                    pass

            termux_boot = os.path.expanduser(f'~/.termux/boot/frpc-{safe}.sh')
            if os.path.exists(termux_boot):
                try:
                    os.remove(termux_boot)
                    removed_files += 1
                except Exception:
                    pass

            removed_files += self._remove_generated_paths_for_safe(safe)
            stopped_units.append(unit_name)

        return {
            'killedPids': killed_pids,
            'stoppedUnits': stopped_units,
            'removedFiles': removed_files,
            'removedPidFiles': removed_pid_files,
            'orphanServiceCount': len(orphan_safe_names),
        }

    def _terminate_pid(self, pid: int, timeout_seconds: float = 5.0):
        if not self._is_pid_running(pid):
            return

        try:
            os.kill(pid, signal.SIGTERM)
        except Exception:
            return

        deadline = time.time() + max(0.1, timeout_seconds)
        while time.time() < deadline:
            if not self._is_pid_running(pid):
                return
            time.sleep(0.1)

        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass

    def _kill_external_for_instance(self, inst: FrpcInstance):
        pid_from_file = self._read_instance_pid_file(inst.id, inst.config_path)
        if isinstance(pid_from_file, int):
            self._terminate_pid(pid_from_file)
        pids = self._find_running_pids_for_config(inst.config_path)
        for pid in pids:
            self._terminate_pid(pid)
        inst.external_pid = None

    def _metadata_from_config(self, config_path: str):
        try:
            import toml
            data = toml.load(config_path)
            proxies = data.get('proxies') or []
            proxy = proxies[0] if proxies else {}
            metadata = {
                'proxyName': proxy.get('name'),
                'subdomain': proxy.get('subdomain'),
                'serverAddr': data.get('serverAddr'),
                'serverPort': data.get('serverPort'),
                'localPort': proxy.get('localPort')
            }
            return metadata
        except Exception:
            return {}

    def _render_frpc_config(self, data: dict) -> str:
        def esc(value):
            return str(value).replace('\\', '\\\\').replace('"', '\\"')

        def b(value, default=False):
            return 'true' if bool(default if value is None else value) else 'false'

        def get_value(obj, dotted, default=None):
            if dotted in obj:
                return obj.get(dotted, default)
            current = obj
            for part in dotted.split('.'):
                if not isinstance(current, dict) or part not in current:
                    return default
                current = current.get(part)
            return current

        server_addr = data.get('serverAddr', 'ginto.ai')
        server_port = int(data.get('serverPort', 7000) or 7000)
        auth_token = get_value(data, 'auth.token', '')
        tls_enable = get_value(data, 'transport.tls.enable', True)
        tls_disable_first_byte = get_value(data, 'transport.tls.disableCustomTLSFirstByte', True)
        pool_count = int(get_value(data, 'transport.poolCount', 3) or 3)
        log_to = get_value(data, 'log.to', '/tmp/frpc-tunnel.log')
        log_level = get_value(data, 'log.level', 'info')
        log_max_days = int(get_value(data, 'log.maxDays', 3) or 3)
        proxies = data.get('proxies') or []

        lines = [
            f"serverAddr = \"{esc(server_addr)}\"",
            f"serverPort = {server_port}",
            "",
            "[auth]",
            "method = \"token\"",
            f"token = \"{esc(auth_token)}\"",
            "",
            "[transport]",
            f"poolCount = {pool_count}",
            "",
            "[transport.tls]",
            f"enable = {b(tls_enable, True)}",
            f"disableCustomTLSFirstByte = {b(tls_disable_first_byte, True)}",
            "",
            "[log]",
            f"to = \"{esc(log_to)}\"",
            f"level = \"{esc(log_level)}\"",
            f"maxDays = {log_max_days}",
            "",
        ]

        for proxy in proxies:
            if not isinstance(proxy, dict):
                continue
            lines.extend([
                "[[proxies]]",
                f"name = \"{esc(proxy.get('name', 'proxy'))}\"",
                f"type = \"{esc(proxy.get('type', 'http'))}\"",
                f"localIP = \"{esc(proxy.get('localIP', '127.0.0.1'))}\"",
                f"localPort = {int(proxy.get('localPort', 80) or 80)}",
            ])
            custom_domains = proxy.get('customDomains')
            if isinstance(custom_domains, list) and custom_domains:
                escaped_domains = [f'"{esc(item)}"' for item in custom_domains if str(item).strip() != '']
                if escaped_domains:
                    lines.append(f"customDomains = [{', '.join(escaped_domains)}]")
            elif proxy.get('subdomain') is not None:
                lines.append(f"subdomain = \"{esc(proxy.get('subdomain'))}\"")
            if proxy.get('hostHeaderRewrite') is not None:
                lines.append(f"hostHeaderRewrite = \"{esc(proxy.get('hostHeaderRewrite'))}\"")
            lines.append("")

        if not proxies:
            lines.extend([
                "[[proxies]]",
                "name = \"proxy\"",
                "type = \"http\"",
                "localIP = \"127.0.0.1\"",
                "localPort = 80",
                "subdomain = \"tunnel\"",
                "hostHeaderRewrite = \"127.0.0.1\"",
                "",
            ])

        return "\n".join(lines)

    def _normalize_config_shape(self, config_path: str):
        try:
            import toml
            data = toml.load(config_path)
            common = data.get('common')
            changed = False
            if not isinstance(common, dict):
                common = {}

            for key, value in common.items():
                if key not in data:
                    data[key] = value
                    changed = True

            if 'common' in data:
                del data['common']
                changed = True

            dotted_to_nested = {
                'auth.method': ('auth', 'method'),
                'auth.token': ('auth', 'token'),
                'transport.poolCount': ('transport', 'poolCount'),
                'transport.tls.enable': ('transport', 'tls', 'enable'),
                'transport.tls.disableCustomTLSFirstByte': ('transport', 'tls', 'disableCustomTLSFirstByte'),
                'log.to': ('log', 'to'),
                'log.level': ('log', 'level'),
                'log.maxDays': ('log', 'maxDays'),
            }
            for dotted, path in dotted_to_nested.items():
                if dotted in data:
                    value = data[dotted]
                    target = data
                    for part in path[:-1]:
                        if part not in target or not isinstance(target.get(part), dict):
                            target[part] = {}
                        target = target[part]
                    if path[-1] not in target:
                        target[path[-1]] = value
                    del data[dotted]
                    changed = True

            global_keys = [
                'serverAddr', 'serverPort', 'auth.method', 'auth.token',
                'transport.tls.enable', 'transport.tls.disableCustomTLSFirstByte',
                'transport.poolCount', 'log.to', 'log.level', 'log.maxDays'
            ]
            proxies = data.get('proxies') or []
            for proxy in proxies:
                if not isinstance(proxy, dict):
                    continue
                for key in global_keys:
                    if key in proxy:
                        if key.startswith('auth.'):
                            data.setdefault('auth', {})
                            nested_key = key.split('.', 1)[1]
                            if nested_key not in data['auth']:
                                data['auth'][nested_key] = proxy[key]
                        elif key.startswith('transport.tls.'):
                            data.setdefault('transport', {})
                            data['transport'].setdefault('tls', {})
                            nested_key = key.split('transport.tls.', 1)[1]
                            if nested_key not in data['transport']['tls']:
                                data['transport']['tls'][nested_key] = proxy[key]
                        elif key.startswith('transport.'):
                            data.setdefault('transport', {})
                            nested_key = key.split('transport.', 1)[1]
                            if nested_key not in data['transport']:
                                data['transport'][nested_key] = proxy[key]
                        elif key.startswith('log.'):
                            data.setdefault('log', {})
                            nested_key = key.split('log.', 1)[1]
                            if nested_key not in data['log']:
                                data['log'][nested_key] = proxy[key]
                        elif key not in data:
                            data[key] = proxy[key]
                        del proxy[key]
                        changed = True

            rewritten = self._render_frpc_config(data)
            with open(config_path, 'r', encoding='utf-8') as f:
                original = f.read()
            if changed or original.strip() != rewritten.strip():
                with open(config_path, 'w', encoding='utf-8') as f:
                    f.write(rewritten)
        except Exception:
            pass

    def load_from_disk(self):
        os.makedirs(self.configs_dir, exist_ok=True)
        state = self._load_state()

        for cfg in glob.glob(os.path.join(self.configs_dir, '*.toml')):
            cfg = self._normalize_config_path(cfg)
            self._normalize_config_shape(cfg)
            id = os.path.splitext(os.path.basename(cfg))[0]
            saved = state.get(id, {}) if isinstance(state, dict) else {}
            metadata = saved.get('metadata') or self._metadata_from_config(cfg)
            if 'enabled' not in metadata:
                metadata['enabled'] = True
            if id not in self.instances:
                self.instances[id] = FrpcInstance(id, cfg, metadata=metadata)

            inst = self.instances[id]
            pid_from_file = self._read_instance_pid_file(id, cfg)
            if isinstance(pid_from_file, int):
                inst.external_pid = pid_from_file
                inst.status = 'running'

        self._save_state()

    def create_instance(self, id: str, config_path: str, metadata: Optional[dict]=None):
        config_path = self._normalize_config_path(config_path)
        self._normalize_config_shape(config_path)
        metadata = metadata or {}
        metadata.setdefault('enabled', True)
        inst = FrpcInstance(id, config_path, metadata=metadata)
        self.instances[id] = inst
        self._save_state()
        return inst

    def delete_instance(self, id: str):
        inst = self.instances.get(id)
        if not inst:
            return False
        self._cleanup_instance_services(id)
        inst.stop()
        self._kill_external_for_instance(inst)
        self._remove_instance_pid_file(id)
        try:
            if os.path.exists(inst.config_path):
                os.remove(inst.config_path)
        except Exception:
            pass
        del self.instances[id]
        self._save_state()
        return True

    def start_instance(self, id: str, executable_path: str):
        inst = self.instances.get(id)
        if not inst:
            return False

        if id.endswith('-https'):
            sibling_http_id = self._sibling_instance_id(id, 'http')
            if sibling_http_id and sibling_http_id in self.instances and sibling_http_id != id:
                sibling_http = self.instances[sibling_http_id]
                if os.path.exists(sibling_http.config_path):
                    self.start_instance(sibling_http_id, executable_path)

        if not os.path.exists(inst.config_path):
            inst.status = 'error'
            self._remove_instance_pid_file(id)
            return False

        running_pids = self._find_running_pids_for_config(inst.config_path)
        if running_pids:
            inst.external_pid = running_pids[0]
            for duplicate_pid in running_pids[1:]:
                self._terminate_pid(duplicate_pid)
            self._write_instance_pid_file(id, inst.external_pid)
            inst.status = 'running'
            inst.enabled = True
            inst.metadata['enabled'] = True
            self._save_state()
            return True

        inst.enabled = True
        inst.metadata['enabled'] = True
        inst.external_pid = None
        inst.start(executable_path)
        if inst.process and inst.process.poll() is None:
            inst.external_pid = inst.process.pid
            self._write_instance_pid_file(id, inst.external_pid)
        self._save_state()
        return True

    def stop_instance(self, id: str):
        inst = self.instances.get(id)
        if not inst:
            return False

        if id.endswith('-http'):
            sibling_https_id = self._sibling_instance_id(id, 'https')
            if sibling_https_id and sibling_https_id in self.instances:
                sibling_https = self.instances[sibling_https_id]
                if sibling_https.enabled or self._is_instance_running(sibling_https_id):
                    inst.status = 'running' if self._is_instance_running(id) else inst.status
                    return False

        inst.stop()
        self._kill_external_for_instance(inst)
        self._remove_instance_pid_file(id)
        inst.enabled = False
        inst.metadata['enabled'] = False
        self._save_state()
        return True

    def restart_instance(self, id: str, executable_path: str):
        inst = self.instances.get(id)
        if not inst:
            return False
        inst.stop()
        self._kill_external_for_instance(inst)
        self._remove_instance_pid_file(id)
        time.sleep(0.2)
        inst.enabled = True
        inst.metadata['enabled'] = True
        inst.external_pid = None
        if not os.path.exists(inst.config_path):
            inst.status = 'error'
            self._save_state()
            return False
        inst.start(executable_path)
        if inst.process and inst.process.poll() is None:
            inst.external_pid = inst.process.pid
            self._write_instance_pid_file(id, inst.external_pid)
        self._save_state()
        return True

    def auto_start_enabled_instances(self, executable_path: str):
        if not os.path.exists(executable_path):
            return
        for inst in self.instances.values():
            if not inst.enabled:
                self._remove_instance_pid_file(inst.id)
                continue
            if not os.path.exists(inst.config_path):
                inst.status = 'error'
                self._remove_instance_pid_file(inst.id)
                continue
            running_pids = self._find_running_pids_for_config(inst.config_path)
            if running_pids:
                inst.external_pid = running_pids[0]
                for duplicate_pid in running_pids[1:]:
                    self._terminate_pid(duplicate_pid)
                self._write_instance_pid_file(inst.id, inst.external_pid)
                inst.status = 'running'
                continue
            inst.external_pid = None
            inst.start(executable_path)
            if inst.process and inst.process.poll() is None:
                inst.external_pid = inst.process.pid
                self._write_instance_pid_file(inst.id, inst.external_pid)

    def list_instances(self):
        return {k: {'status': v.status, 'config': v.config_path} for k,v in self.instances.items()}
