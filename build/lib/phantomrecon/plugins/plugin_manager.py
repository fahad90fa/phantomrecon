from __future__ import annotations

import importlib
import importlib.util
import inspect
import sys
from pathlib import Path
from typing import Any, Optional, Type

from ..http_client import HttpClient
from ..models import Finding, ScanConfig
from .base_plugin import BasePlugin


class PluginManager:
    def __init__(self, config: ScanConfig, client: Optional[HttpClient] = None) -> None:
        self.config = config
        self.client = client
        self._plugins: dict[str, BasePlugin] = {}

    def load_from_directory(self, directory: str) -> list[str]:
        loaded: list[str] = []
        plugin_dir = Path(directory)
        if not plugin_dir.exists():
            return loaded

        for py_file in plugin_dir.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            try:
                module_name = f"phantomrecon_plugin_{py_file.stem}"
                spec = importlib.util.spec_from_file_location(module_name, py_file)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)

                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if issubclass(obj, BasePlugin) and obj is not BasePlugin:
                            plugin_instance = obj(self.config, self.client)
                            self._plugins[plugin_instance.name] = plugin_instance
                            loaded.append(plugin_instance.name)
            except Exception as e:
                print(f"[PluginManager] Failed to load {py_file.name}: {e}")

        return loaded

    def load_plugin_class(self, plugin_class: Type[BasePlugin]) -> None:
        instance = plugin_class(self.config, self.client)
        self._plugins[instance.name] = instance

    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        return self._plugins.get(name)

    def list_plugins(self) -> list[dict[str, str]]:
        return [p.get_metadata() for p in self._plugins.values()]

    def enable(self, name: str) -> bool:
        if name in self._plugins:
            self._plugins[name].enable()
            return True
        return False

    def disable(self, name: str) -> bool:
        if name in self._plugins:
            self._plugins[name].disable()
            return True
        return False

    async def run_all(self, target: str, **kwargs: Any) -> list[Finding]:
        all_findings: list[Finding] = []
        for plugin in self._plugins.values():
            if plugin.enabled:
                try:
                    findings = await plugin.run(target, **kwargs)
                    all_findings.extend(findings)
                except Exception as e:
                    print(f"[PluginManager] Plugin '{plugin.name}' failed: {e}")
        return all_findings

    async def run_plugin(self, name: str, target: str, **kwargs: Any) -> list[Finding]:
        plugin = self._plugins.get(name)
        if not plugin or not plugin.enabled:
            return []
        try:
            return await plugin.run(target, **kwargs)
        except Exception as e:
            print(f"[PluginManager] Plugin '{name}' failed: {e}")
            return []
