import importlib, inspect, pkgutil
from typing import Dict, Type, Any

def discover_plugins(package_path: str, base_class: Type[Any]) -> Dict[str, Type[Any]]:
    plugins: Dict[str, Type[Any]] = {}
    try:
        package = importlib.import_module(package_path)
    except ImportError:
        return plugins
    for importer, modname, ispkg in pkgutil.iter_modules(package.__path__, prefix=package.__name__ + "."):
        try:
            module = importlib.import_module(modname)
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, base_class) and obj is not base_class:
                    plugins[name] = obj
        except Exception:
            continue
    return plugins
