import os, importlib, inspect, logging
from typing import Dict, Type, Optional
from bxp_secretsonar.core.models_v2 import PluginMeta, PluginType

class BasePlugin:
    meta: PluginMeta
    def run(self, *args, **kwargs):
        raise NotImplementedError

class ExploitPlugin(BasePlugin): pass
class PayloadPlugin(BasePlugin): pass
class PostExploitPlugin(BasePlugin): pass

def discover_plugins(directory: str) -> Dict[str, Type[BasePlugin]]:
    plugins = {}
    if not os.path.isdir(directory):
        return plugins
    for fname in os.listdir(directory):
        if fname.endswith('.py') and fname != '__init__.py':
            mod_name = fname[:-3]
            try:
                mod = importlib.import_module(f"bxp_secretsonar.plugins.{os.path.basename(directory)}.{mod_name}")
                for name, obj in inspect.getmembers(mod, inspect.isclass):
                    if issubclass(obj, BasePlugin) and obj is not BasePlugin:
                        plugins[name] = obj
            except Exception as e:
                logging.warning(f"Failed to load plugin {fname}: {e}")
    return plugins
