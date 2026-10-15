"""Deploy approved command rules through the pfSense Snort package API."""
import argparse
import json
import re
import shlex
import subprocess
import uuid
from pathlib import Path


class SSHRuleDeployer:
    def __init__(self, config):
        self.host = config["host"]
        self.user = config.get("user", "root")
        self.port = int(config.get("port", 22))
        self.interface = config.get("interface", "wan")
        self.mode = config["mode"]
        self.key = config.get("key")
        self.known_hosts = config.get("known_hosts")
        self.ssh_config = config.get("ssh_config")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", self.host) or self.host.startswith("-"):
            raise ValueError("Invalid SSH host")
        if not re.fullmatch(r"[A-Za-z0-9_-]+", self.user) or self.user.startswith("-"):
            raise ValueError("Invalid SSH user")
        if not 1 <= self.port <= 65535 or self.mode not in ("legacy", "inline"):
            raise ValueError("Invalid SSH port or IPS mode")
        if not re.fullmatch(r"[A-Za-z0-9_]+", self.interface):
            raise ValueError("Invalid interface")
        self.helper = Path(__file__).with_name("pfsense_snort_apply.php")

    def command(self, program):
        options = [program, "-p" if program == "ssh" else "-P", str(self.port),
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=5"]
        if self.ssh_config:
            options += ["-F", str(Path(self.ssh_config).expanduser())]
        if program == "scp":
            options.append("-O")  # pfSense commonly has SCP without an SFTP subsystem.
        if self.key:
            options += ["-i", str(Path(self.key).expanduser())]
        if self.known_hosts:
            options += ["-o", "UserKnownHostsFile=" + str(Path(self.known_hosts).expanduser())]
        return options

    def request(self, payload):
        target = f"{self.user}@{self.host}"
        remote = "/tmp/capstone-snort-" + uuid.uuid4().hex + ".php"
        try:
            subprocess.run(self.command("scp") + [str(self.helper), f"{target}:{remote}"],
                check=True, capture_output=True, text=True, timeout=15)
            invocation = "/usr/local/bin/php -f " + shlex.quote(remote)
            completed = subprocess.run(self.command("ssh") + [target, invocation],
                input=json.dumps(payload), check=True, capture_output=True, text=True, timeout=60)
            # Package functions may emit diagnostics before the final JSON line.
            result = json.loads(completed.stdout.strip().splitlines()[-1])
            if result.get("ok") is not True:
                raise RuntimeError("pfSense deployment failed: " + str(result))
            return result
        except subprocess.CalledProcessError as error:
            detail = (error.stdout or "") + (error.stderr or "")
            raise RuntimeError("pfSense SSH/helper failed: " + detail[-4000:]) from error
        finally:
            try:
                subprocess.run(self.command("ssh") + [target, "rm -f " + shlex.quote(remote)],
                    check=True, capture_output=True, text=True, timeout=10)
            except (subprocess.SubprocessError, OSError):
                pass

    def inspect(self):
        return self.request({"operation": "inspect", "interface": self.interface})

    def clear_managed(self):
        """Explicitly remove only the Capstone-managed Snort rules."""
        return self.request({"operation": "clear_managed", "interface": self.interface,
                             "mode": self.mode, "rules": []})

    def deploy(self, path):
        rules = [line.strip() for line in Path(path).read_text().splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
        action = "alert" if self.mode == "legacy" else "drop"
        pattern = (r'^' + action + r' tcp any any -> any 5020 \(msg:"Capstone Modbus write register [0-9]+ value [0-9]+"; '
                   r'flow:to_server,established; content:"\|06 [0-9A-F]{2} [0-9A-F]{2} [0-9A-F]{2} [0-9A-F]{2}\|"; '
                   r'offset:7; depth:5; sid:([0-9]+); rev:1;\)$')
        seen = set()
        for rule in rules:
            match = re.fullmatch(pattern, rule)
            if not match or match[1] in seen:
                raise ValueError("Only distinct generated command-specific rules in the configured mode may be deployed")
            seen.add(match[1])
        return self.request({"operation": "apply", "interface": self.interface,
                             "mode": self.mode, "rules": rules})


def configure_deployment(pipeline, config_file):
    if pipeline.snort_rule_manager is None:
        raise ValueError("--rules-file is required for deployment")
    deployer = SSHRuleDeployer(json.loads(Path(config_file).read_text()))
    status = deployer.inspect()
    if status.get("mode") != deployer.mode or not status.get("running") or not status.get("blocking"):
        raise ValueError("pfSense mode/running/blocking settings do not match deployment configuration")
    pipeline.snort_rule_manager.blocking = deployer.mode == "inline"
    pipeline.snort_rule_manager.deployer = deployer.deploy
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--inspect", action="store_true")
    action.add_argument("--rules", type=Path, help="Add generated rules without removing earlier managed rules")
    action.add_argument("--clear-managed", action="store_true",
                        help="Explicitly remove all Capstone-managed rules")
    args = parser.parse_args()
    deployer = SSHRuleDeployer(json.loads(Path(args.config).read_text()))
    result = (deployer.inspect() if args.inspect else
              deployer.clear_managed() if args.clear_managed else
              deployer.deploy(args.rules))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
