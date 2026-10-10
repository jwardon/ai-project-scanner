"""Curated security-relevant callables recognized by pickle analysis."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PickleCapabilityRule:
    rule_id: str
    capability: str


# Values are the stable rule identifier and the capability established by a call.
PICKLE_CAPABILITY_RULES: dict[str, PickleCapabilityRule] = {
    "builtins.eval": PickleCapabilityRule(
        "pickle.dynamic_code_execution", "dynamic code execution"
    ),
    "builtins.exec": PickleCapabilityRule(
        "pickle.dynamic_code_execution", "dynamic code execution"
    ),
    "os.system": PickleCapabilityRule("pickle.command_execution", "command execution"),
    "posix.system": PickleCapabilityRule(
        "pickle.command_execution", "command execution"
    ),
    "nt.system": PickleCapabilityRule("pickle.command_execution", "command execution"),
    "os.popen": PickleCapabilityRule("pickle.command_execution", "command execution"),
    "subprocess.Popen": PickleCapabilityRule(
        "pickle.command_execution", "process execution"
    ),
    "subprocess.call": PickleCapabilityRule(
        "pickle.command_execution", "process execution"
    ),
    "subprocess.check_call": PickleCapabilityRule(
        "pickle.command_execution", "process execution"
    ),
    "subprocess.check_output": PickleCapabilityRule(
        "pickle.command_execution", "process execution"
    ),
    "subprocess.run": PickleCapabilityRule(
        "pickle.command_execution", "process execution"
    ),
    "builtins.__import__": PickleCapabilityRule(
        "pickle.dynamic_loading", "dynamic import"
    ),
    "importlib.import_module": PickleCapabilityRule(
        "pickle.dynamic_loading", "dynamic import"
    ),
    "runpy.run_module": PickleCapabilityRule(
        "pickle.dynamic_loading", "dynamic module loading"
    ),
    "runpy.run_path": PickleCapabilityRule(
        "pickle.dynamic_loading", "dynamic code loading"
    ),
    "builtins.open": PickleCapabilityRule(
        "pickle.filesystem_access", "filesystem access"
    ),
    "io.open": PickleCapabilityRule("pickle.filesystem_access", "filesystem access"),
    "os.open": PickleCapabilityRule("pickle.filesystem_access", "filesystem access"),
    "os.remove": PickleCapabilityRule(
        "pickle.filesystem_access", "filesystem mutation"
    ),
    "os.unlink": PickleCapabilityRule(
        "pickle.filesystem_access", "filesystem mutation"
    ),
    "os.rename": PickleCapabilityRule(
        "pickle.filesystem_access", "filesystem mutation"
    ),
    "os.replace": PickleCapabilityRule(
        "pickle.filesystem_access", "filesystem mutation"
    ),
    "pathlib.Path.open": PickleCapabilityRule(
        "pickle.filesystem_access", "filesystem access"
    ),
    "pathlib.Path.read_bytes": PickleCapabilityRule(
        "pickle.filesystem_access", "filesystem access"
    ),
    "pathlib.Path.read_text": PickleCapabilityRule(
        "pickle.filesystem_access", "filesystem access"
    ),
    "pathlib.Path.write_bytes": PickleCapabilityRule(
        "pickle.filesystem_access", "filesystem mutation"
    ),
    "pathlib.Path.write_text": PickleCapabilityRule(
        "pickle.filesystem_access", "filesystem mutation"
    ),
    "pathlib.Path.unlink": PickleCapabilityRule(
        "pickle.filesystem_access", "filesystem mutation"
    ),
    "shutil.copy": PickleCapabilityRule(
        "pickle.filesystem_access", "filesystem mutation"
    ),
    "shutil.move": PickleCapabilityRule(
        "pickle.filesystem_access", "filesystem mutation"
    ),
    "shutil.rmtree": PickleCapabilityRule(
        "pickle.filesystem_access", "filesystem mutation"
    ),
    "socket.create_connection": PickleCapabilityRule(
        "pickle.network_access", "network access"
    ),
    "urllib.request.urlopen": PickleCapabilityRule(
        "pickle.network_access", "network access"
    ),
    "urllib.request.urlretrieve": PickleCapabilityRule(
        "pickle.network_access", "network access"
    ),
    "http.client.HTTPConnection.connect": PickleCapabilityRule(
        "pickle.network_access", "network access"
    ),
    "smtplib.SMTP.connect": PickleCapabilityRule(
        "pickle.network_access", "network access"
    ),
    "ftplib.FTP.connect": PickleCapabilityRule(
        "pickle.network_access", "network access"
    ),
}
