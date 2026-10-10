"""Curated security-relevant callables recognized by pickle analysis."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PickleCapabilityRule:
    rule_id: str
    capability: str


PICKLE_CAPABILITY_RULES: dict[str, PickleCapabilityRule] = {
    "builtins.eval": PickleCapabilityRule(
        rule_id="pickle.dynamic_code_execution",
        capability="dynamic code execution",
    ),
    "builtins.exec": PickleCapabilityRule(
        rule_id="pickle.dynamic_code_execution",
        capability="dynamic code execution",
    ),
    "os.system": PickleCapabilityRule(
        rule_id="pickle.command_execution", capability="command execution"
    ),
    "posix.system": PickleCapabilityRule(
        rule_id="pickle.command_execution", capability="command execution"
    ),
    "nt.system": PickleCapabilityRule(
        rule_id="pickle.command_execution", capability="command execution"
    ),
    "os.popen": PickleCapabilityRule(
        rule_id="pickle.command_execution", capability="command execution"
    ),
    "subprocess.Popen": PickleCapabilityRule(
        rule_id="pickle.command_execution", capability="process execution"
    ),
    "subprocess.call": PickleCapabilityRule(
        rule_id="pickle.command_execution", capability="process execution"
    ),
    "subprocess.check_call": PickleCapabilityRule(
        rule_id="pickle.command_execution", capability="process execution"
    ),
    "subprocess.check_output": PickleCapabilityRule(
        rule_id="pickle.command_execution", capability="process execution"
    ),
    "subprocess.run": PickleCapabilityRule(
        rule_id="pickle.command_execution", capability="process execution"
    ),
    "builtins.__import__": PickleCapabilityRule(
        rule_id="pickle.dynamic_loading", capability="dynamic import"
    ),
    "importlib.import_module": PickleCapabilityRule(
        rule_id="pickle.dynamic_loading", capability="dynamic import"
    ),
    "runpy.run_module": PickleCapabilityRule(
        rule_id="pickle.dynamic_loading", capability="dynamic module loading"
    ),
    "runpy.run_path": PickleCapabilityRule(
        rule_id="pickle.dynamic_loading", capability="dynamic code loading"
    ),
    "builtins.open": PickleCapabilityRule(
        rule_id="pickle.filesystem_access", capability="filesystem access"
    ),
    "io.open": PickleCapabilityRule(
        rule_id="pickle.filesystem_access", capability="filesystem access"
    ),
    "os.open": PickleCapabilityRule(
        rule_id="pickle.filesystem_access", capability="filesystem access"
    ),
    "os.remove": PickleCapabilityRule(
        rule_id="pickle.filesystem_access", capability="filesystem mutation"
    ),
    "os.unlink": PickleCapabilityRule(
        rule_id="pickle.filesystem_access", capability="filesystem mutation"
    ),
    "os.rename": PickleCapabilityRule(
        rule_id="pickle.filesystem_access", capability="filesystem mutation"
    ),
    "os.replace": PickleCapabilityRule(
        rule_id="pickle.filesystem_access", capability="filesystem mutation"
    ),
    "pathlib.Path.open": PickleCapabilityRule(
        rule_id="pickle.filesystem_access", capability="filesystem access"
    ),
    "pathlib.Path.read_bytes": PickleCapabilityRule(
        rule_id="pickle.filesystem_access", capability="filesystem access"
    ),
    "pathlib.Path.read_text": PickleCapabilityRule(
        rule_id="pickle.filesystem_access", capability="filesystem access"
    ),
    "pathlib.Path.write_bytes": PickleCapabilityRule(
        rule_id="pickle.filesystem_access", capability="filesystem mutation"
    ),
    "pathlib.Path.write_text": PickleCapabilityRule(
        rule_id="pickle.filesystem_access", capability="filesystem mutation"
    ),
    "pathlib.Path.unlink": PickleCapabilityRule(
        rule_id="pickle.filesystem_access", capability="filesystem mutation"
    ),
    "shutil.copy": PickleCapabilityRule(
        rule_id="pickle.filesystem_access", capability="filesystem mutation"
    ),
    "shutil.move": PickleCapabilityRule(
        rule_id="pickle.filesystem_access", capability="filesystem mutation"
    ),
    "shutil.rmtree": PickleCapabilityRule(
        rule_id="pickle.filesystem_access", capability="filesystem mutation"
    ),
    "socket.create_connection": PickleCapabilityRule(
        rule_id="pickle.network_access", capability="network access"
    ),
    "urllib.request.urlopen": PickleCapabilityRule(
        rule_id="pickle.network_access", capability="network access"
    ),
    "urllib.request.urlretrieve": PickleCapabilityRule(
        rule_id="pickle.network_access", capability="network access"
    ),
    "http.client.HTTPConnection.connect": PickleCapabilityRule(
        rule_id="pickle.network_access", capability="network access"
    ),
    "smtplib.SMTP.connect": PickleCapabilityRule(
        rule_id="pickle.network_access", capability="network access"
    ),
    "ftplib.FTP.connect": PickleCapabilityRule(
        rule_id="pickle.network_access", capability="network access"
    ),
}
