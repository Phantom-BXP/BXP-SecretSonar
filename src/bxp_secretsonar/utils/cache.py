import os, json, hashlib, time

CACHE_FILE = "scan_cache.json"

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE) as f:
            return json.load(f)
    return {}

def save_cache(cache):
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f)

def get_cached_result(url):
    cache = load_cache()
    key = hashlib.md5(url.encode()).hexdigest()
    entry = cache.get(key)
    if entry and time.time() - entry['timestamp'] < 86400:  # 24h
        return entry['data']
    return None

def set_cached_result(url, data):
    cache = load_cache()
    key = hashlib.md5(url.encode()).hexdigest()
    cache[key] = {'timestamp': time.time(), 'data': data}
    save_cache(cache)
