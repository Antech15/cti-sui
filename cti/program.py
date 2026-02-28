#!/usr/bin/env python3
import atexit
import base64
import hashlib
import json
import math
import os
import re
import signal
import subprocess
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import matplotlib.pyplot as plt
from tkinter import Tk, filedialog

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet


from concurrent.futures import ThreadPoolExecutor
import threading
import shutil
import tempfile
import requests
from collections import deque
from typing import Deque, Set


# ---------------------------- crypto helpers ----------------------------

def _hybrid_encrypt(public_key, payload: bytes) -> str:
    sym_key = Fernet.generate_key()
    ciphertext = Fernet(sym_key).encrypt(payload)

    enc_key = public_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return json.dumps({
        "enc_key": base64.b64encode(enc_key).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    })


def _hybrid_decrypt(private_key, encrypted_json: str) -> bytes:
    blob = json.loads(encrypted_json)
    enc_key = base64.b64decode(blob["enc_key"])
    ciphertext = base64.b64decode(blob["ciphertext"])

    sym_key = private_key.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return Fernet(sym_key).decrypt(ciphertext)


def encrypt_for_public_key(public_key, payload: bytes) -> str:
    return _hybrid_encrypt(public_key, payload)


class Account:
    def __init__(self, address: str):
        self.address = address
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        self.public_key = self._private_key.public_key()

    def encrypt_payload(self, payload: bytes) -> str:
        return _hybrid_encrypt(self.public_key, payload)

    def decrypt_payload(self, encrypted_json: str) -> bytes:
        return _hybrid_decrypt(self._private_key, encrypted_json)


# ---------------------------- unwrap helpers ----------------------------

def _unwrap_sui_value(x):
    """Sui CLI sometimes returns {'value': ...} wrappers."""
    if isinstance(x, dict) and "value" in x:
        return x["value"]
    return x


def _unwrap_option_id(x) -> Optional[str]:
    """
    Best-effort unwrap for Move Option<ID> returned by Sui JSON.
    Handles:
      - None / "" / {"None": true}
      - {"Some": {"value":"0x..."}} or {"Some":"0x..."} / {"some": ...}
      - direct string "0x..."
    """
    if x is None:
        return None
    if isinstance(x, str):
        return x if x.startswith("0x") else None
    if isinstance(x, dict) and "value" in x:
        v = x["value"]
        return v if isinstance(v, str) and v.startswith("0x") else None
    if isinstance(x, dict):
        for k in ("Some", "some"):
            if k in x:
                inner = _unwrap_sui_value(x[k])
                if isinstance(inner, str) and inner.startswith("0x"):
                    return inner
                if isinstance(inner, dict) and "value" in inner:
                    v = inner["value"]
                    return v if isinstance(v, str) and v.startswith("0x") else None
                return None
        if "None" in x or "none" in x:
            return None
    return None


def evaluate_acmp(acmp: str, credentials: str) -> bool:
    """
    Step 8 policy check.
    For now: allow if credentials == acmp OR credentials == "andres".
    Replace this with your real mapping later.
    """
    credentials = (credentials or "").strip()
    acmp = (acmp or "").strip()
    if not credentials:
        return False
    return credentials == acmp or credentials.lower() == "andres"

def _hash_to_hex(b: bytes) -> str:
    return b.hex()

def _print_hash_comparison(label: str, local_hash: bytes, on_chain_hash_list: List[int]):
    chain_bytes = bytes(on_chain_hash_list)
    print(f"\n🔎 Hash verification ({label})")
    print("Local  SHA-256(CTI|nonce):", _hash_to_hex(local_hash))
    print("On-chain CTI hash        :", _hash_to_hex(chain_bytes))
    print("Match?                  :", "✅ YES" if local_hash == chain_bytes else "❌ NO")


# ---------------------------- IPFS daemon ----------------------------

class IPFSDaemon:
    """Manage an IPFS (Kubo) daemon lifecycle."""
    def __init__(self):
        self.proc: Optional[subprocess.Popen] = None
        self.started_by_us: bool = False

    def _is_running(self) -> bool:
        try:
            subprocess.run(
                ["ipfs", "id"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
                timeout=2,
            )
            return True
        except Exception:
            return False

    def start(self) -> bool:
        try:
            subprocess.run(["ipfs", "version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        except Exception:
            print("IPFS not available: 'ipfs' command not found. Install Kubo to use IPFS pointers.\n")
            return False

        if self._is_running():
            print("IPFS daemon already running (reusing).\n")
            self.started_by_us = False
            return True

        print("Starting IPFS daemon...")
        try:
            self.proc = subprocess.Popen(
                ["ipfs", "daemon", "--migrate=true"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid,
                text=True,
            )
            self.started_by_us = True

            print("Waiting for IPFS daemon to initialize...")
            deadline = time.time() + 20
            while time.time() < deadline:
                if self._is_running():
                    print("IPFS daemon ready.\n")
                    return True
                time.sleep(0.25)

            print("IPFS daemon did not become ready in time.\n")
            return False
        except Exception as e:
            print(f"Error starting IPFS daemon: {e}\n")
            return False

    def stop(self):
        if not self.started_by_us or not self.proc:
            return
        print("\nStopping IPFS daemon...")
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            self.proc.wait(timeout=5)
            print("IPFS daemon stopped")
        except Exception:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
            except Exception:
                pass


# ---------------------------- benchmark helpers ----------------------------

@dataclass
class GasSummary:
    computation: int = 0
    storage: int = 0
    rebate: int = 0

    @property
    def net(self) -> int:
        return int(self.computation) + int(self.storage) - int(self.rebate)


def _parse_gas_summary(tx_json: dict) -> GasSummary:
    effects = tx_json.get("effects") or {}
    gas_used = effects.get("gasUsed") or effects.get("gas_used") or {}
    comp = gas_used.get("computationCost") or gas_used.get("computation_cost") or 0
    stor = gas_used.get("storageCost") or gas_used.get("storage_cost") or 0
    reb = gas_used.get("storageRebate") or gas_used.get("storage_rebate") or 0
    try:
        return GasSummary(int(comp), int(stor), int(reb))
    except Exception:
        return GasSummary()


def _mean_std(values: List[float]) -> Tuple[float, float]:
    if not values:
        return (0.0, 0.0)
    m = sum(values) / len(values)
    if len(values) == 1:
        return (m, 0.0)
    var = sum((v - m) ** 2 for v in values) / (len(values) - 1)
    return (m, math.sqrt(var))


def _linear_fit(x: List[float], y: List[float]) -> Tuple[float, float]:
    """Least squares fit y = a + b*x."""
    if len(x) < 2:
        return ((float(y[0]) if y else 0.0), 0.0)
    n = float(len(x))
    sx = sum(x)
    sy = sum(y)
    sxx = sum(v * v for v in x)
    sxy = sum(xi * yi for xi, yi in zip(x, y))
    denom = n * sxx - sx * sx
    if abs(denom) < 1e-12:
        return (sy / n, 0.0)
    b = (n * sxy - sx * sy) / denom
    a = (sy - b * sx) / n
    return (a, b)


# ---------------------------- main program ----------------------------

class CTISharingProgram:
    def __init__(self):
        # ---- Object read cache (Fix #3) ----
        self._gas_pool_lock = threading.Lock()

        # address -> queue of available gas coins
        self._gas_pool: Dict[str, Deque[str]] = {}

        # address -> coins currently handed out (in-flight)
        self._gas_in_use: Dict[str, Set[str]] = {}

        # address -> lock to prevent concurrent refills for the same owner
        self._gas_refill_lock: Dict[str, threading.Lock] = {}
        self._use_rpc_object_reads = True
        self._obj_cache_lock = threading.Lock()
        self._obj_cache: Dict[str, Tuple[float, dict]] = {}
        self._OBJ_CACHE_TTL_SEC = 0.50  # 500ms is enough to cut spam reads during benchmarks
        self._keytool_lock = threading.Lock()
        self._rpc_id_lock = threading.Lock()
        self._rpc_next_id = 1
        self.localnet_process: Optional[subprocess.Popen] = None
        self.accounts: Dict[str, Account] = {}
        self.package_id: Optional[str] = None
        self.registry_id: Optional[str] = None

        self.explorer_base = "https://explorer.polymedia.app"
        self.network_param = "?network=http%3A%2F%2F127.0.0.1%3A9000"

        self.ipfs = IPFSDaemon()
        self.ipfs_enabled = False

        # ---- Benchmark / CLI concurrency fixes ----
        # Base config dir the user already has (keystore + client.yaml)
        self._base_sui_config_dir = os.environ.get(
            "SUI_CONFIG_DIR",
            os.path.expanduser("~/.sui/sui_config"),
        )

        # Per-thread Sui config dirs so threads do NOT fight over "active address"
        self._thread_local = threading.local()
        self._tmp_config_dirs: List[str] = []

        # Used to serialize *initial* config bootstrap per thread
        self._config_bootstrap_lock = threading.Lock()

    # ---------------- localnet ----------------

    def start_localnet(self) -> bool:
        print("Starting Sui localnet...")

        env = os.environ.copy()
        env["RUST_LOG"] = "off,sui_node=info"

        try:
            self.localnet_process = subprocess.Popen(
                ["sui", "start", "--with-faucet", "--force-regenesis"],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid,
            )

            print("Waiting for localnet to initialize...")
            time.sleep(8)

            if self.localnet_process.poll() is None:
                print(f"Localnet ready (PID: {self.localnet_process.pid})\n")
                return True

            print("Localnet failed to start\n")
            return False
        except Exception as e:
            print(f"Error starting localnet: {e}\n")
            return False

    def stop_localnet(self):
        if not self.localnet_process:
            return
        print("\nStopping localnet...")
        try:
            os.killpg(os.getpgid(self.localnet_process.pid), signal.SIGTERM)
            self.localnet_process.wait(timeout=5)
            print("Localnet stopped")
        except Exception:
            try:
                os.killpg(os.getpgid(self.localnet_process.pid), signal.SIGKILL)
            except Exception:
                pass

    # ---------------- ipfs ----------------

    def start_ipfs(self) -> bool:
        ok = self.ipfs.start()
        self.ipfs_enabled = bool(ok)
        return self.ipfs_enabled

    def stop_ipfs(self):
        if self.ipfs_enabled:
            self.ipfs.stop()

    def ipfs_cat(self, cid_or_ref: str) -> str:
        cid = cid_or_ref.replace("ipfs://", "")
        return subprocess.check_output(["ipfs", "cat", cid], text=True)

    def _write_and_add_ipfs(self, out_dir: str, filename: str, content: str) -> str:
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

        if self.ipfs_enabled:
            try:
                cid = subprocess.check_output(["ipfs", "add", "-Q", path], text=True).strip()
                return f"ipfs://{cid}"
            except Exception as e:
                print(f"IPFS upload failed ({e}). Falling back to file:// pointer.\n")

        return "file://" + os.path.abspath(path)

    def upload_encrypted_payloads_to_ipfs(self, encrypted_json_strings: List[str], delegate_addrs: List[str]) -> List[str]:
        out_dir = "encrypted_payloads"
        refs: List[str] = []
        for i, payload_json in enumerate(encrypted_json_strings):
            addr = delegate_addrs[i].replace("0x", "")
            fname = f"enc_{addr[:8]}.json"
            refs.append(self._write_and_add_ipfs(out_dir, fname, payload_json))
        return refs

    def upload_response_to_ipfs(self, encrypted_response_json: str, request_object_id: str) -> str:
        short = request_object_id.replace("0x", "")[:10]
        return self._write_and_add_ipfs("encrypted_responses", f"resp_{short}.json", encrypted_response_json)

    def upload_blob_to_ipfs(self, encrypted_json: str, tag: str, obj_id: str) -> str:
        short = obj_id.replace("0x", "")[:10]
        return self._write_and_add_ipfs(f"encrypted_{tag}", f"{tag}_{short}.json", encrypted_json)

    # ---------------- sui helpers ----------------

    def explorer_link(self, object_or_tx: str, kind: str = "object") -> str:
        if kind == "txblock":
            return f"{self.explorer_base}/txblock/{object_or_tx}{self.network_param}"
        return f"{self.explorer_base}/object/{object_or_tx}{self.network_param}"

    def get_addresses(self) -> List[str]:
        r = subprocess.run(["sui", "client", "addresses", "--json"], capture_output=True, text=True)
        if r.returncode == 0:
            try:
                data = json.loads(r.stdout)
                if isinstance(data, list):
                    addrs = [x.get("address") for x in data if isinstance(x, dict) and x.get("address")]
                    if addrs:
                        return addrs
                if isinstance(data, dict):
                    for key in ("addresses", "result", "data"):
                        if key in data and isinstance(data[key], list):
                            addrs = [x.get("address") for x in data[key] if isinstance(x, dict) and x.get("address")]
                            if addrs:
                                return addrs
            except Exception:
                pass

        r2 = subprocess.run(["sui", "client", "addresses"], capture_output=True, text=True)
        if r2.returncode != 0:
            return []
        addrs = re.findall(r"0x[a-fA-F0-9]{64}", r2.stdout)
        seen, out = set(), []
        for a in addrs:
            if a not in seen:
                seen.add(a)
                out.append(a)
        return out

    def switch_account(self, address: str) -> bool:
        r = subprocess.run(
            ["sui", "client", "switch", "--address", address],
            capture_output=True,
            text=True,
        )
        return r.returncode == 0

    def request_gas(self, address: str) -> bool:
        r = subprocess.run(
            ["sui", "client", "faucet", "--address", address],
            capture_output=True,
            text=True,
        )
        return r.returncode == 0

    def _fetch_object_json(self, object_id: str) -> dict:
        r = subprocess.run(["sui", "client", "object", object_id, "--json"], capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(r.stderr or r.stdout)
        return json.loads(r.stdout)

    def _cache_invalidate(self, object_id: str) -> None:
        if not object_id:
            return
        with self._obj_cache_lock:
            self._obj_cache.pop(object_id, None)

    def fetch_object_fields(self, object_id: str) -> dict:
        # ---- cache check ----
        now = time.time()
        with self._obj_cache_lock:
            hit = self._obj_cache.get(object_id)
            if hit:
                ts, fields = hit
                if (now - ts) <= self._OBJ_CACHE_TTL_SEC:
                    return fields

        # ---- miss: fetch (RPC preferred) ----
        if getattr(self, "_use_rpc_object_reads", False):
            fields = self._rpc_get_object_fields(object_id)
        else:
            data = self._fetch_object_json(object_id)
            content = data.get("content") or {}
            fields = (content.get("fields") or {}) if isinstance(content, dict) else {}

        # ---- store ----
        with self._obj_cache_lock:
            self._obj_cache[object_id] = (now, fields)

        return fields

    def fetch_fields_any_object(self, object_id: str) -> dict:
        return self.fetch_object_fields(object_id)
    
    def _thread_config_dir(self) -> str:
        """
        Each worker thread gets its own SUI_CONFIG_DIR (a copy of base config),
        so 'sui client switch' in that thread doesn't race other threads.
        """
        cfg = getattr(self._thread_local, "sui_config_dir", None)
        if cfg:
            return cfg

        with self._config_bootstrap_lock:
            # Re-check after acquiring lock
            cfg = getattr(self._thread_local, "sui_config_dir", None)
            if cfg:
                return cfg

            # Create temp config dir and copy base config into it
            tmp = tempfile.mkdtemp(prefix="sui_cfg_")
            self._tmp_config_dirs.append(tmp)

            if os.path.isdir(self._base_sui_config_dir):
                shutil.copytree(self._base_sui_config_dir, tmp, dirs_exist_ok=True)
            else:
                # If base doesn't exist, still create dir so Sui can initialize if needed
                os.makedirs(tmp, exist_ok=True)

            self._thread_local.sui_config_dir = tmp
            return tmp


    def _sui_env(self) -> dict:
        env = os.environ.copy()
        env["SUI_CONFIG_DIR"] = self._thread_config_dir()
        return env


    def _sui_run(self, args: List[str]) -> subprocess.CompletedProcess:
        """
        Run sui CLI under this thread's isolated config dir.
        """
        return subprocess.run(args, capture_output=True, text=True, env=self._sui_env())


    def _sui_switch_in_thread(self, address: str) -> None:
        """
        One-time or occasional switch inside THIS thread only.
        (Because config dir is thread-local, this won't affect other threads.)
        """
        r = self._sui_run(["sui", "client", "switch", "--address", address])
        if r.returncode != 0:
            raise RuntimeError(r.stderr or r.stdout or "sui client switch failed")


    def cleanup_thread_configs(self):
        """
        Optional cleanup at program exit.
        """
        for d in self._tmp_config_dirs:
            try:
                shutil.rmtree(d, ignore_errors=True)
            except Exception:
                pass
        self._tmp_config_dirs.clear()

    # ---------------- setup accounts ----------------

    def setup_accounts_6(self) -> bool:
        addrs = self.get_addresses()
        if len(addrs) < 6:
            print("Need at least 6 Sui addresses in your keystore.\n")
            return False

        names = ["producer"] + [f"delegate_{i}" for i in range(4)] + ["consumer"]
        self.accounts = {name: Account(addrs[i]) for i, name in enumerate(names)}

        print("Setting up accounts (1 producer, 4 delegates, 1 consumer)...")
        print("Requesting gas for all accounts...")
        for name in names:
            addr = self.accounts[name].address
            self.request_gas(addr)
            print(f"  {name}: {addr[:10]}...")
        print("6 accounts ready\n")
        return True

    # ---------------- publish package ----------------

    @staticmethod
    def _extract_json_from_mixed_output(output: str) -> Optional[dict]:
        s = output.find("{")
        e = output.rfind("}")
        if s == -1 or e == -1 or e < s:
            return None
        try:
            return json.loads(output[s:e + 1])
        except Exception:
            return None

    def publish_package(self):
        print("📦 Publishing CTI sharing package...")

        self.switch_account(self.accounts["producer"].address)

        result = subprocess.run(
            ['sui', 'client', 'test-publish', '--build-env', 'local', '--json'],
            capture_output=True,
            text=True
        )

        output = (result.stdout or "") + (result.stderr or "")
        data = self._extract_json_from_mixed_output(output)

        if not data:
            print("❌ Could not parse JSON from test-publish output")
            print("stdout:", (result.stdout or "")[:500])
            print("stderr:", (result.stderr or "")[:500])
            return False

        for change in data.get("objectChanges", []):
            if change.get("type") == "published":
                self.package_id = change.get("packageId")
                if self.package_id:
                    print(f"✅ Package published: {self.package_id[:16]}...")
                    print(f"   🔗 {self.explorer_link(self.package_id)}\n")
            elif change.get("type") == "created" and "CTIRegistry" in (change.get("objectType", "") or ""):
                self.registry_id = change.get("objectId")
                if self.registry_id:
                    print(f"📋 Registry created: {self.registry_id[:16]}...")
                    print(f"   🔗 {self.explorer_link(self.registry_id)}\n")

        if self.package_id and self.registry_id:
            return True

        print("❌ Failed to extract package or registry ID")
        print("package_id:", self.package_id)
        print("registry_id:", self.registry_id)
        return False

    # ---------------- file picker ----------------

    def pick_file_path(self) -> Optional[str]:
        try:
            root = Tk()
            root.withdraw()
            root.wm_attributes("-topmost", 1)
            path = filedialog.askopenfilename()
            root.destroy()
            return path if path else None
        except Exception as e:
            print(f"File picker error: {e}")
            return None

    # ---------------- Step 1&2: Share CTI ----------------

    def share_cti(self):
        print("\nHow many delegates do you want? (0-4)")
        dn_raw = input("> ").strip()
        try:
            dn = int(dn_raw)
            if dn < 0 or dn > 4:
                raise ValueError
        except ValueError:
            print("Invalid delegate count. Choose 0, 1, 2, 3, or 4.\n")
            return

        delegate_names = [f"delegate_{i}" for i in range(dn)]
        delegate_addrs = [self.accounts[name].address for name in delegate_names]

        print("\nShare CTI")
        print("1) Pick a file")
        print("2) Paste CTI text")
        mode = input("> ").strip()

        if mode == "1":
            path = self.pick_file_path()
            if not path:
                print("No file selected.\n")
                return
            try:
                with open(path, "rb") as f:
                    cti_bytes = f.read()
            except Exception as e:
                print(f"Failed to read file: {e}\n")
                return
        elif mode == "2":
            cti_text = input("Paste CTI JSON/text: ").strip()
            if not cti_text:
                print("CTI content cannot be empty.\n")
                return
            cti_bytes = cti_text.encode("utf-8")
        else:
            print("Invalid selection.\n")
            return

        acmp_raw = input("ACMP (number, e.g., 2): ").strip()
        try:
            acmp_num = int(acmp_raw)
            if acmp_num < 0:
                raise ValueError
        except ValueError:
            print("ACMP must be a non-negative integer.\n")
            return

        nonce = os.urandom(16)
        cti_with_nonce = cti_bytes + b"|" + nonce
        cti_hash = hashlib.sha256(cti_with_nonce).digest()

        encrypted_ctis = [self.accounts[name].encrypt_payload(cti_with_nonce) for name in delegate_names]

        encrypted_refs: List[str] = []
        if self.ipfs_enabled:
            try:
                encrypted_refs = self.upload_encrypted_payloads_to_ipfs(encrypted_ctis, delegate_addrs)
            except Exception as e:
                print(f"IPFS upload failed ({e}). Falling back to file:// pointers.\n")
                self.ipfs_enabled = False
                encrypted_refs = []

        if not encrypted_refs:
            out_dir = "encrypted_payloads"
            os.makedirs(out_dir, exist_ok=True)
            for i, payload_json in enumerate(encrypted_ctis):
                addr = delegate_addrs[i].replace("0x", "")
                fname = f"enc_{addr[:8]}.json"
                path = os.path.join(out_dir, fname)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(payload_json)
                encrypted_refs.append("file://" + os.path.abspath(path))

        hash_arg = "[" + ",".join(str(b) for b in cti_hash) + "]"
        delegates_arg = "[" + ",".join(delegate_addrs) + "]" if delegate_addrs else "[]"
        acmp_arg = str(acmp_num)
        encrypted_refs_arg = "[" + ",".join(json.dumps(s) for s in encrypted_refs) + "]" if encrypted_refs else "[]"

        self.switch_account(self.accounts["producer"].address)

        result = subprocess.run(
            [
                "sui", "client", "call",
                "--package", self.package_id,
                "--module", "cti",
                "--function", "share_cti",
                "--args",
                self.registry_id,
                hash_arg,
                acmp_arg,
                delegates_arg,
                encrypted_refs_arg,
                "--json",
            ],
            capture_output=True,
            text=True,
        )

        try:
            data = json.loads(result.stdout)
        except Exception as e:
            print(f"Could not parse share_cti output JSON: {e}\n")
            return

        tx = data.get("digest", "")
        cti_id = None
        for change in data.get("objectChanges", []):
            if change.get("type") == "created" and (change.get("objectType") or "").endswith("::CTI"):
                cti_id = change.get("objectId")
                break

        print("share_cti succeeded.")
        if cti_id:
            print(f"CTI object: {cti_id}")
            print(f"Explorer:   {self.explorer_link(cti_id)}")
        if tx:
            print(f"Tx digest:  {tx}")
            print(f"Explorer:   {self.explorer_link(tx, 'txblock')}")
        print()

    # ---------------- Step 3: Retrieve CTI as Delegate ----------------

    def retrieve_cti_as_delegate(self):
        print("\nRetrieve CTI as Delegate")
        print("Choose delegate index (0-3):")
        idx_raw = input("> ").strip()
        try:
            idx = int(idx_raw)
            if idx < 0 or idx > 3:
                raise ValueError
        except ValueError:
            print("Invalid delegate index.\n")
            return

        cti_object_id = input("Paste CTI object id (0x...): ").strip()
        if not cti_object_id.startswith("0x"):
            print("Invalid object id.\n")
            return

        delegate_name = f"delegate_{idx}"
        delegate_addr = self.accounts[delegate_name].address
        self.switch_account(delegate_addr)

        try:
            fields = self.fetch_object_fields(cti_object_id)
        except Exception as e:
            print(f"Failed to read CTI object: {e}\n")
            return

        on_chain_hash = fields.get("cti_hash")
        delegates = fields.get("delegates") or []
        refs = fields.get("encrypted_cti_nft_ids") or []

        if not delegates or not refs or not on_chain_hash:
            print("CTI object missing expected fields (delegates/refs/hash).")
            print("Fields available:", list(fields.keys()))
            print()
            return

        delegates_norm = []
        for d in delegates:
            d = _unwrap_sui_value(d)
            if isinstance(d, str):
                delegates_norm.append(d)

        if delegate_addr not in delegates_norm:
            print("This delegate is not authorized for this CTI.\n")
            return

        d_i = delegates_norm.index(delegate_addr)
        nft_id = _unwrap_sui_value(refs[d_i])

        nft_fields = self.fetch_fields_any_object(nft_id)
        ref = _unwrap_sui_value(nft_fields.get("data"))

        if not isinstance(ref, str):
            print("Could not resolve payload ref from NFT. NFT fields:", nft_fields)
            return

        print(f"Resolved payload ref from NFT: {ref}")

        if ref.startswith("ipfs://"):
            try:
                encrypted_json = self.ipfs_cat(ref)
            except Exception as e:
                print(f"Failed to fetch from IPFS: {e}\n")
                return
        elif ref.startswith("file://"):
            path = ref.replace("file://", "")
            try:
                with open(path, "r", encoding="utf-8") as f:
                    encrypted_json = f.read()
            except Exception as e:
                print(f"Failed to read local file: {e}\n")
                return
        else:
            print("Unknown ref type (expected ipfs:// or file://)\n")
            return

        try:
            plaintext = self.accounts[delegate_name].decrypt_payload(encrypted_json)
        except Exception as e:
            print(f"Decrypt failed: {e}\n")
            return

        local_hash = hashlib.sha256(plaintext).digest()

        if not isinstance(on_chain_hash, list):
            print("Unexpected hash format:", type(on_chain_hash), on_chain_hash)
            print("Fields available:", list(fields.keys()))
            print()
            return

        _print_hash_comparison("delegate Step 3", local_hash, on_chain_hash)

        if local_hash != bytes(on_chain_hash):
            print("❌ Verification FAILED: hash mismatch.\n")
            return

        print("✅ Verification OK: decrypted CTI matches on-chain hash.")
        try:
            cti_bytes, nonce = plaintext.rsplit(b"|", 1)
        except ValueError:
            print("Decrypted payload did not contain delimiter '|'.\n")
            return

        print("Nonce (base64):", base64.b64encode(nonce).decode())
        try:
            cti_obj = json.loads(cti_bytes.decode("utf-8"))
            print("CTI JSON:")
            print(json.dumps(cti_obj, indent=2))
        except Exception:
            print("CTI (raw text):")
            print(cti_bytes.decode("utf-8", errors="replace"))
        print()

    # ---------------- Step 4&5: Request CTI as Consumer ----------------

    def request_cti_as_consumer(self):
        print("\nRequest CTI as Consumer (Step 4)")
        cti_object_id = input("Paste CTI object id (0x...): ").strip()
        if not cti_object_id.startswith("0x"):
            print("Invalid CTI object id.\n")
            return

        consumer_addr = self.accounts["consumer"].address
        if not self.switch_account(consumer_addr):
            print("Failed to switch to consumer account.\n")
            return

        result = subprocess.run(
            [
                "sui", "client", "call",
                "--package", self.package_id,
                "--module", "cti",
                "--function", "request_cti",
                "--args", cti_object_id,
                "--json",
            ],
            capture_output=True,
            text=True,
        )

        try:
            data = json.loads(result.stdout)
        except Exception as e:
            print(f"Could not parse request_cti output JSON: {e}\n")
            print("STDERR:", (result.stderr or "")[:800])
            print("STDOUT:", (result.stdout or "")[:800])
            return

        tx = data.get("digest", "")

        request_obj_id = None
        for change in data.get("objectChanges", []):
            if change.get("type") == "created" and (change.get("objectType") or "").endswith("::CTIRequest"):
                request_obj_id = change.get("objectId")
                break

        assigned_delegate = None
        request_id_from_event = None
        for ev in data.get("events", []):
            et = ev.get("type") or ev.get("eventType") or ""
            if et.endswith("::CTIRequested"):
                parsed = ev.get("parsedJson") or {}
                assigned_delegate = parsed.get("assigned_delegate")
                request_id_from_event = parsed.get("request_id")
                break

        if request_obj_id and assigned_delegate is None:
            try:
                req_fields = self.fetch_object_fields(request_obj_id)
                assigned_delegate = req_fields.get("assigned_delegate")
            except Exception:
                pass

        print("request_cti succeeded.")
        if request_obj_id:
            print(f"CTIRequest object: {request_obj_id}")
            print(f"Explorer:          {self.explorer_link(request_obj_id)}")
        if assigned_delegate:
            print(f"Assigned delegate: {assigned_delegate}")
        if request_id_from_event:
            print(f"Request ID (event): {request_id_from_event}")
        if tx:
            print(f"Tx digest:         {tx}")
            print(f"Explorer:          {self.explorer_link(tx, 'txblock')}")
        print()

    # ---------------- Step 6: Submit Credentials ----------------

    def submit_credentials_as_consumer(self):
        print("\nSubmit Credentials (consumer) (Step 6)")
        request_object_id = input("Paste CTIRequest object id (0x...): ").strip()
        if not request_object_id.startswith("0x"):
            print("Invalid request object id.\n")
            return

        consumer_addr = self.accounts["consumer"].address
        if not self.switch_account(consumer_addr):
            print("Failed to switch to consumer account.\n")
            return

        try:
            req_fields = self.fetch_object_fields(request_object_id)
        except Exception as e:
            print(f"Failed to read CTIRequest object: {e}\n")
            return

        assigned_delegate = _unwrap_sui_value(req_fields.get("assigned_delegate"))
        if not isinstance(assigned_delegate, str) or not assigned_delegate.startswith("0x"):
            print("Could not resolve assigned_delegate from request.")
            print("Fields available:", list(req_fields.keys()))
            print()
            return

        delegate_account = None
        delegate_name = None
        for name, acct in self.accounts.items():
            if name.startswith("delegate_") and acct.address == assigned_delegate:
                delegate_account = acct
                delegate_name = name
                break

        if delegate_account is None:
            print("Assigned delegate is not one of the 4 local delegate accounts.")
            print("Assigned delegate:", assigned_delegate)
            print()
            return

        credentials = input("Enter credentials text (e.g., username/token/etc): ").strip()
        if not credentials:
            print("Credentials cannot be empty.\n")
            return

        encrypted_credentials_json = encrypt_for_public_key(
            delegate_account.public_key,
            credentials.encode("utf-8"),
        )

        enc_arg = json.dumps(encrypted_credentials_json)

        result = subprocess.run(
            [
                "sui", "client", "call",
                "--package", self.package_id,
                "--module", "cti",
                "--function", "credentials_cti",
                "--args",
                request_object_id,
                enc_arg,
                "--json",
            ],
            capture_output=True,
            text=True,
        )

        try:
            data = json.loads(result.stdout)
        except Exception as e:
            print(f"Could not parse credentials_cti output JSON: {e}\n")
            print("STDERR:", (result.stderr or "")[:800])
            print("STDOUT:", (result.stdout or "")[:800])
            return

        tx = data.get("digest", "")
        print("credentials_cti succeeded.")
        print(f"Request:          {request_object_id}")
        print(f"Assigned delegate: {assigned_delegate} ({delegate_name})")
        if tx:
            print(f"Tx digest:        {tx}")
            print(f"Explorer:         {self.explorer_link(tx, 'txblock')}")
        print()

    # ---------------- delegate decrypt CTI helper ----------------

    def _decrypt_cti_for_delegate(self, cti_object_id: str, delegate_name: str) -> bytes:
        delegate_addr = self.accounts[delegate_name].address
        fields = self.fetch_object_fields(cti_object_id)

        delegates = fields.get("delegates") or []
        refs = fields.get("encrypted_cti_nft_ids") or []

        delegates_norm = []
        for d in delegates:
            d = _unwrap_sui_value(d)
            if isinstance(d, str):
                delegates_norm.append(d)

        if delegate_addr not in delegates_norm:
            raise RuntimeError("Delegate is not authorized for this CTI")

        d_i = delegates_norm.index(delegate_addr)
        nft_id = _unwrap_sui_value(refs[d_i])

        nft_fields = self.fetch_fields_any_object(nft_id)
        ref = _unwrap_sui_value(nft_fields.get("data"))
        if not isinstance(ref, str):
            raise RuntimeError("Could not resolve CTI ref from NFT")

        if ref.startswith("ipfs://"):
            encrypted_json = self.ipfs_cat(ref)
        elif ref.startswith("file://"):
            path = ref.replace("file://", "")
            with open(path, "r", encoding="utf-8") as f:
                encrypted_json = f.read()
        else:
            raise RuntimeError("Unknown ref type (expected ipfs:// or file://)")

        return self.accounts[delegate_name].decrypt_payload(encrypted_json)

    # ---------------- Steps 7-10: Delegate Control + Response ----------------

    def delegate_steps_7_8_9(self):
        print("\nDelegate Control + Response (Steps 7, 8, 9)")
        print("Choose delegate index (0-3):")
        idx_raw = input("> ").strip()
        try:
            idx = int(idx_raw)
            if idx < 0 or idx > 3:
                raise ValueError
        except ValueError:
            print("Invalid delegate index.\n")
            return

        request_object_id = input("Paste CTIRequest object id (0x...): ").strip()
        if not request_object_id.startswith("0x"):
            print("Invalid request object id.\n")
            return

        delegate_name = f"delegate_{idx}"
        delegate_addr = self.accounts[delegate_name].address

        if not self.switch_account(delegate_addr):
            print("Failed to switch to delegate account.\n")
            return

        try:
            req_fields = self.fetch_object_fields(request_object_id)
        except Exception as e:
            print(f"Failed to read CTIRequest object: {e}\n")
            return

        assigned_delegate = _unwrap_sui_value(req_fields.get("assigned_delegate"))
        consumer_addr = _unwrap_sui_value(req_fields.get("consumer"))
        cti_id = _unwrap_sui_value(req_fields.get("cti_id"))
        encrypted_credentials = _unwrap_sui_value(req_fields.get("encrypted_credentials"))
        response_provided = _unwrap_sui_value(req_fields.get("response_provided"))

        if assigned_delegate != delegate_addr:
            print("This request is NOT assigned to the chosen delegate.\n")
            print("Assigned delegate:", assigned_delegate)
            print("Chosen delegate:  ", delegate_addr)
            print()
            return

        if response_provided:
            print("Response already provided for this request.\n")
            return

        if not isinstance(encrypted_credentials, str) or not encrypted_credentials:
            print("Request has no encrypted_credentials yet (Step 6 not done).\n")
            return

        if not isinstance(cti_id, str) or not cti_id.startswith("0x"):
            print("Could not resolve cti_id from request.\n")
            return

        # Step 7: decrypt credentials
        try:
            creds_plain = self.accounts[delegate_name].decrypt_payload(encrypted_credentials).decode("utf-8", errors="replace")
        except Exception as e:
            print(f"Failed to decrypt credentials: {e}\n")
            return

        print("Decrypted credentials:", creds_plain)

        # Read CTI to get ACMP
        try:
            cti_fields = self.fetch_object_fields(cti_id)
        except Exception as e:
            print(f"Failed to read CTI object: {e}\n")
            return

        acmp = _unwrap_sui_value(cti_fields.get("acmp"))
        if not isinstance(acmp, str):
            print("Could not resolve CTI.acmp.\n")
            print("CTI fields available:", list(cti_fields.keys()))
            return

        # Step 8: policy check
        allowed = evaluate_acmp(acmp, creds_plain)
        print(f"ACMP: {acmp}")
        print("Policy result:", "✅ ALLOW" if allowed else "❌ DENY")

        if not allowed:
            print("\nNot allowed -> not providing CTI response.\n")
            return

        # Step 9: decrypt CTI for delegate, then encrypt for consumer
        try:
            cti_plaintext = self._decrypt_cti_for_delegate(cti_id, delegate_name)
        except Exception as e:
            print(f"Failed to decrypt CTI for delegate: {e}\n")
            return

        consumer_account = None
        for _, acct in self.accounts.items():
            if acct.address == consumer_addr:
                consumer_account = acct
                break
        if consumer_account is None:
            print("Consumer address is not one of the local accounts; cannot find public key.\n")
            print("Consumer:", consumer_addr)
            return

        encrypted_response_json = encrypt_for_public_key(consumer_account.public_key, cti_plaintext)

        response_ref = self.upload_response_to_ipfs(encrypted_response_json, request_object_id)
        ref_arg = json.dumps(response_ref)

        result = subprocess.run(
            [
                "sui", "client", "call",
                "--package", self.package_id,
                "--module", "cti",
                "--function", "response_cti",
                "--args",
                request_object_id,
                ref_arg,
                "--json",
            ],
            capture_output=True,
            text=True,
        )

        try:
            data = json.loads(result.stdout)
        except Exception as e:
            print(f"Could not parse response_cti output JSON: {e}\n")
            print("STDERR:", (result.stderr or "")[:800])
            print("STDOUT:", (result.stdout or "")[:800])
            return

        tx = data.get("digest", "")
        print("\n✅ response_cti succeeded.")
        print("Request:", request_object_id)
        print(f"Encrypted response stored off-chain at: {response_ref}")
        if tx:
            print("Tx digest:", tx)
            print("Explorer: ", self.explorer_link(tx, "txblock"))
        print()

    # ---------------- Steps 11 & 12: Consumer fetch + decrypt + verify ----------------

    def consumer_steps_11_12(self):
        print("\nConsumer fetch + decrypt + verify (Steps 11 & 12)")
        request_object_id = input("Paste CTIRequest object id (0x...): ").strip()
        if not request_object_id.startswith("0x"):
            print("Invalid request object id.\n")
            return

        consumer_addr = self.accounts["consumer"].address
        if not self.switch_account(consumer_addr):
            print("Failed to switch to consumer account.\n")
            return

        try:
            req_fields = self.fetch_object_fields(request_object_id)
        except Exception as e:
            print(f"Failed to read CTIRequest object: {e}\n")
            return

        response_provided = _unwrap_sui_value(req_fields.get("response_provided"))
        cti_id = _unwrap_sui_value(req_fields.get("cti_id"))

        if not response_provided:
            print("Response not provided yet (delegate Step 9/10 not done).\n")
            return

        if not isinstance(cti_id, str) or not cti_id.startswith("0x"):
            print("Could not resolve cti_id from request.\n")
            print("Fields available:", list(req_fields.keys()))
            print()
            return

        resp_nft_id = _unwrap_option_id(req_fields.get("encrypted_response_nft_id"))

        encrypted_json = None
        if resp_nft_id:
            try:
                nft_fields = self.fetch_fields_any_object(resp_nft_id)
            except Exception as e:
                print(f"Failed to read response NFT object: {e}\n")
                return

            ref = _unwrap_sui_value(nft_fields.get("data"))
            if not isinstance(ref, str):
                print("Could not resolve 'data' pointer from response NFT.\n")
                print("NFT fields available:", list(nft_fields.keys()))
                print()
                return

            print(f"Resolved response ref from NFT: {ref}")

            if ref.startswith("ipfs://"):
                try:
                    encrypted_json = self.ipfs_cat(ref)
                except Exception as e:
                    print(f"Failed to fetch response from IPFS: {e}\n")
                    return
            elif ref.startswith("file://"):
                path = ref.replace("file://", "")
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        encrypted_json = f.read()
                except Exception as e:
                    print(f"Failed to read response local file: {e}\n")
                    return
            else:
                print("Unknown response ref type (expected ipfs:// or file://)\n")
                return
        else:
            direct = _unwrap_sui_value(req_fields.get("encrypted_response"))
            if isinstance(direct, str) and direct.strip():
                encrypted_json = direct
                print("Using direct encrypted_response stored on request (legacy mode).")
            else:
                print("No response NFT pointer found, and no direct encrypted_response present.\n")
                print("Fields available:", list(req_fields.keys()))
                print()
                return

        try:
            plaintext = self.accounts["consumer"].decrypt_payload(encrypted_json)
        except Exception as e:
            print(f"Decrypt failed (consumer private key): {e}\n")
            return

        local_hash = hashlib.sha256(plaintext).digest()

        try:
            cti_fields = self.fetch_object_fields(cti_id)
        except Exception as e:
            print(f"Failed to read CTI object: {e}\n")
            return

        on_chain_hash = cti_fields.get("cti_hash")
        if not isinstance(on_chain_hash, list):
            print("Unexpected CTI hash format:", type(on_chain_hash), on_chain_hash)
            print("CTI fields available:", list(cti_fields.keys()))
            print()
            return

        _print_hash_comparison("consumer Steps 11/12", local_hash, on_chain_hash)

        if local_hash != bytes(on_chain_hash):
            print("❌ Verification FAILED: hash mismatch.\n")
            return

        print("✅ Verification OK: decrypted CTI matches on-chain hash.")

        try:
            cti_bytes, nonce = plaintext.rsplit(b"|", 1)
        except ValueError:
            print("Decrypted payload did not contain delimiter '|'.\n")
            return

        print("Nonce (base64):", base64.b64encode(nonce).decode())
        try:
            cti_obj = json.loads(cti_bytes.decode("utf-8"))
            print("CTI JSON:")
            print(json.dumps(cti_obj, indent=2))
        except Exception:
            print("CTI (raw text):")
            print(cti_bytes.decode("utf-8", errors="replace"))
        print()

    # ---------------- Step 13: Become Delegate (consumer) ----------------

    def consumer_step_13_become_delegate(self):
        print("\nBecome Delegate (consumer) (Step 13)")
        request_object_id = input("Paste CTIRequest object id (0x...) that already has a response: ").strip()
        if not request_object_id.startswith("0x"):
            print("Invalid request object id.\n")
            return

        consumer_addr = self.accounts["consumer"].address
        if not self.switch_account(consumer_addr):
            print("Failed to switch to consumer account.\n")
            return

        try:
            req_fields = self.fetch_object_fields(request_object_id)
        except Exception as e:
            print(f"Failed to read CTIRequest object: {e}\n")
            return

        response_provided = _unwrap_sui_value(req_fields.get("response_provided"))
        cti_id = _unwrap_sui_value(req_fields.get("cti_id"))

        if not response_provided:
            print("Response not provided yet for this request. Run Steps 7–10 first.\n")
            return

        if not isinstance(cti_id, str) or not cti_id.startswith("0x"):
            print("Could not resolve cti_id from request.\n")
            print("Fields available:", list(req_fields.keys()))
            print()
            return

        resp_nft_id = _unwrap_option_id(req_fields.get("encrypted_response_nft_id"))
        if not resp_nft_id:
            print("No encrypted_response_nft_id found on request.\n")
            print("Fields available:", list(req_fields.keys()))
            print()
            return

        try:
            nft_fields = self.fetch_fields_any_object(resp_nft_id)
        except Exception as e:
            print(f"Failed to read response NFT object: {e}\n")
            return

        ref = _unwrap_sui_value(nft_fields.get("data"))
        if not isinstance(ref, str):
            print("Could not resolve 'data' pointer from response NFT.\n")
            print("NFT fields available:", list(nft_fields.keys()))
            print()
            return

        if ref.startswith("ipfs://"):
            try:
                encrypted_json = self.ipfs_cat(ref)
            except Exception as e:
                print(f"Failed to fetch response from IPFS: {e}\n")
                return
        elif ref.startswith("file://"):
            path = ref.replace("file://", "")
            try:
                with open(path, "r", encoding="utf-8") as f:
                    encrypted_json = f.read()
            except Exception as e:
                print(f"Failed to read response local file: {e}\n")
                return
        else:
            print("Unknown response ref type (expected ipfs:// or file://)\n")
            return

        try:
            plaintext_cti_with_nonce = self.accounts["consumer"].decrypt_payload(encrypted_json)
        except Exception as e:
            print(f"Decrypt failed (consumer private key): {e}\n")
            return

        encrypted_for_consumer_delegate = encrypt_for_public_key(
            self.accounts["consumer"].public_key,
            plaintext_cti_with_nonce,
        )

        new_delegate_ref = self.upload_blob_to_ipfs(
            encrypted_for_consumer_delegate,
            tag="delegate_payload",
            obj_id=request_object_id,
        )

        ref_arg = json.dumps(new_delegate_ref)

        result = subprocess.run(
            [
                "sui", "client", "call",
                "--package", self.package_id,
                "--module", "cti",
                "--function", "add_delegate",
                "--args",
                cti_id,
                consumer_addr,
                ref_arg,
                "--json",
            ],
            capture_output=True,
            text=True,
        )

        try:
            data = json.loads(result.stdout)
        except Exception as e:
            print(f"Could not parse add_delegate output JSON: {e}\n")
            print("STDERR:", (result.stderr or "")[:800])
            print("STDOUT:", (result.stdout or "")[:800])
            return

        tx = data.get("digest", "")
        print("✅ add_delegate succeeded.")
        print("CTI:        ", cti_id)
        print("New delegate:", consumer_addr)
        print("Payload ref: ", new_delegate_ref)
        if tx:
            print("Tx digest:   ", tx)
            print("Explorer:    ", self.explorer_link(tx, "txblock"))
        print()

    # ---------------- benchmark: low-level json call + gas ----------------

    def _sui_call_json(self, args_list: List[str], *, address: Optional[str] = None) -> Tuple[Optional[dict], GasSummary, str]:
        """
        Run a sui command that returns JSON.
        If address is provided, we switch in THIS THREAD only (thread-local config dir).
        """
        if address:
            self._sui_switch_in_thread(address)

        r = self._sui_run(args_list)
        out = (r.stdout or "") + (r.stderr or "")

        # Try direct JSON parse
        try:
            data = json.loads(r.stdout)
            return data, _parse_gas_summary(data), out
        except Exception:
            pass

        # Try extract JSON from mixed output
        data = self._extract_json_from_mixed_output(out)
        if data:
            return data, _parse_gas_summary(data), out

        return None, GasSummary(), out

    # ---------------- benchmark: noninteractive primitives ----------------

    def _create_cti_noninteractive(self, delegate_count: int, payload_bytes: bytes, acmp_num: int = 2) -> Tuple[str, GasSummary]:
        delegate_count = max(0, min(4, int(delegate_count)))
        delegate_names = [f"delegate_{i}" for i in range(delegate_count)]
        delegate_addrs = [self.accounts[n].address for n in delegate_names]

        nonce = os.urandom(16)
        cti_with_nonce = payload_bytes + b"|" + nonce
        cti_hash = hashlib.sha256(cti_with_nonce).digest()

        encrypted_ctis = [self.accounts[n].encrypt_payload(cti_with_nonce) for n in delegate_names]

        # stable: local file pointers
        encrypted_refs: List[str] = []
        out_dir = "encrypted_payloads"
        os.makedirs(out_dir, exist_ok=True)
        for i, payload_json in enumerate(encrypted_ctis):
            addr = delegate_addrs[i].replace("0x", "")
            fname = f"enc_{addr[:8]}_bench.json"
            path = os.path.join(out_dir, fname)
            with open(path, "w", encoding="utf-8") as f:
                f.write(payload_json)
            encrypted_refs.append("file://" + os.path.abspath(path))

        hash_arg = "[" + ",".join(str(b) for b in cti_hash) + "]"
        delegates_arg = "[" + ",".join(delegate_addrs) + "]" if delegate_addrs else "[]"
        acmp_arg = str(int(acmp_num))
        encrypted_refs_arg = "[" + ",".join(json.dumps(s) for s in encrypted_refs) + "]" if encrypted_refs else "[]"

        producer_addr = self.accounts["producer"].address

        data, gas, raw = self._sui_call_json([
            "sui", "client", "call",
            "--package", self.package_id,
            "--module", "cti",
            "--function", "share_cti",
            "--args",
            self.registry_id,
            hash_arg,
            acmp_arg,
            delegates_arg,
            encrypted_refs_arg,
            "--json",
        ], address=producer_addr)

        if not data:
            raise RuntimeError("share_cti did not return JSON:\n" + raw[:1200])

        cti_id = None
        for change in data.get("objectChanges", []):
            if change.get("type") == "created" and (change.get("objectType") or "").endswith("::CTI"):
                cti_id = change.get("objectId")
                break
        if not cti_id:
            raise RuntimeError("Could not extract CTI objectId from share_cti")

        return cti_id, gas

    def _request_and_credentials(self, cti_id: str, credentials_text: str = "andres") -> Tuple[str, str, GasSummary, GasSummary]:
        consumer_addr = self.accounts["consumer"].address

        # -------- Step 4: request_cti (RPC) --------
        data4, gas4 = self._rpc_move_call_commit(
            signer=consumer_addr,
            package_id=self.package_id,
            module="cti",
            function="request_cti",
            args=[cti_id],
            gas_budget="100000000",
        )

        request_obj_id = None
        for change in data4.get("objectChanges", []) or []:
            if change.get("type") == "created" and (change.get("objectType") or "").endswith("::CTIRequest"):
                request_obj_id = change.get("objectId")
                break
        if not request_obj_id:
            raise RuntimeError("Could not extract CTIRequest objectId from RPC request_cti")

        assigned_delegate = None
        for ev in data4.get("events", []) or []:
            et = ev.get("type") or ev.get("eventType") or ""
            if et.endswith("::CTIRequested"):
                parsed = ev.get("parsedJson") or {}
                assigned_delegate = parsed.get("assigned_delegate")
                break

        if not assigned_delegate:
            # Benchmark mode: require event to avoid CLI object read in hot path
            raise RuntimeError("assigned_delegate missing from CTIRequested event")

        if not isinstance(assigned_delegate, str) or not assigned_delegate.startswith("0x"):
            raise RuntimeError("Could not resolve assigned_delegate")

        delegate_acct = None
        for name, acct in self.accounts.items():
            if name.startswith("delegate_") and acct.address == assigned_delegate:
                delegate_acct = acct
                break
        if delegate_acct is None:
            raise RuntimeError("Assigned delegate not one of local delegate accounts")

        enc_cred_json = encrypt_for_public_key(delegate_acct.public_key, credentials_text.encode("utf-8"))
        enc_arg = enc_cred_json

        # -------- Step 6: credentials_cti (RPC) --------
        data6, gas6 = self._rpc_move_call_commit(
            signer=consumer_addr,
            package_id=self.package_id,
            module="cti",
            function="credentials_cti",
            args=[request_obj_id, enc_arg],
            gas_budget="100000000",
        )

        if not isinstance(data6, dict) or not data6.get("effects"):
            raise RuntimeError("credentials_cti RPC execution returned unexpected response")

        return request_obj_id, assigned_delegate, gas4, gas6
    
    def _rpc_get_object_fields(self, object_id: str) -> dict:
        # Sui JSON-RPC: sui_getObject
        result = self._rpc_call("sui_getObject", [
            object_id,
            {"showContent": True}
        ])
        data = result.get("data") or {}
        content = data.get("content") or {}
        if isinstance(content, dict):
            return content.get("fields") or {}
        return {}
    
    def _rpc_get_gas_coins(self, owner: str, limit: int = 200) -> List[str]:
        """
        Return ALL SUI coinObjectIds for owner by paging suix_getAllCoins,
        then filtering to coinType == 0x2::sui::SUI.

        This is more reliable than suix_getCoins on some localnet builds.
        """
        out: List[str] = []
        cursor = None
        seen: Set[str] = set()

        while True:
            # suix_getAllCoins(owner, cursor, limit)
            res = self._rpc_call("suix_getAllCoins", [owner, cursor, int(limit)])
            data = res.get("data") or []

            for c in data:
                cid = c.get("coinObjectId")
                ctype = c.get("coinType")
                if ctype != "0x2::sui::SUI":
                    continue
                if isinstance(cid, str) and cid.startswith("0x") and cid not in seen:
                    seen.add(cid)
                    out.append(cid)

            has_next = bool(res.get("hasNextPage"))
            next_cursor = res.get("nextCursor")

            if not data:
                break
            if not has_next:
                break
            if not next_cursor:
                break
            if next_cursor == cursor:
                break

            cursor = next_cursor

        return out
    
    def _gas_refill(self, owner: str, limit: int = 500) -> None:
        """
        Fetch owner's SUI coins and add any that are NOT already:
        - in the available pool
        - currently in use
        This prevents duplicates across concurrent refills.
        """
        coins = self._rpc_get_gas_coins(owner, limit=limit)
        if not coins:
            return

        with self._gas_pool_lock:
            pool = self._gas_pool.setdefault(owner, deque())
            in_use = self._gas_in_use.setdefault(owner, set())

            # Build a fast "already known" set
            known = set(pool) | set(in_use)

            for c in coins:
                if c not in known:
                    pool.append(c)
                    known.add(c)

    def _gas_acquire(self, owner: str) -> str:
        # 1) Fast path: pop from pool
        with self._gas_pool_lock:
            pool = self._gas_pool.setdefault(owner, deque())
            in_use = self._gas_in_use.setdefault(owner, set())
            if pool:
                coin = pool.pop()
                in_use.add(coin)
                return coin

        # 2) Slow path: refill (serialize refills per owner)
        refill_lock = self._get_refill_lock(owner)
        with refill_lock:
            # Re-check after waiting for refill lock
            with self._gas_pool_lock:
                pool = self._gas_pool.setdefault(owner, deque())
                in_use = self._gas_in_use.setdefault(owner, set())
                if pool:
                    coin = pool.pop()
                    in_use.add(coin)
                    return coin

            # Do the network call outside pool lock
            self._gas_refill(owner, limit=500)

        # 3) After refill attempt: wait briefly for coins to appear / return
        deadline = time.time() + 2.0
        while time.time() < deadline:
            with self._gas_pool_lock:
                pool = self._gas_pool.setdefault(owner, deque())
                in_use = self._gas_in_use.setdefault(owner, set())
                if pool:
                    coin = pool.pop()
                    in_use.add(coin)
                    return coin
            time.sleep(0.01)

        # Try one faucet top-up and refill, then wait a bit longer
        try:
            self.request_gas(owner)
        except Exception:
            pass

        self._gas_refill(owner, limit=200)

        deadline = time.time() + 5.0
        while time.time() < deadline:
            with self._gas_pool_lock:
                pool = self._gas_pool.setdefault(owner, deque())
                in_use = self._gas_in_use.setdefault(owner, set())
                if pool:
                    coin = pool.pop()
                    in_use.add(coin)
                    return coin
            time.sleep(0.02)

        raise RuntimeError(f"No gas coins available for {owner}")

    def _gas_release(self, owner: str, coin_id: str) -> None:
        if not coin_id:
            return
        with self._gas_pool_lock:
            pool = self._gas_pool.setdefault(owner, deque())
            in_use = self._gas_in_use.setdefault(owner, set())

            # Remove from in-use; if it wasn't marked, still put it back safely
            in_use.discard(coin_id)

            # Avoid duplicates in pool
            if coin_id not in pool:
                pool.append(coin_id)

    def _get_refill_lock(self, owner: str) -> threading.Lock:
        with self._gas_pool_lock:
            lk = self._gas_refill_lock.get(owner)
            if lk is None:
                lk = threading.Lock()
                self._gas_refill_lock[owner] = lk
            return lk

    def _try_delete_file_ref(self, ref: str) -> None:
        if not isinstance(ref, str):
            return
        if not ref.startswith("file://"):
            return
        path = ref.replace("file://", "", 1)
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        except Exception:
            pass

    def _delegate_respond_noninteractive(self, request_obj_id: str, simulate_work_hashes: int = 0) -> GasSummary:
        req_fields = self.fetch_object_fields(request_obj_id)
        assigned_delegate = _unwrap_sui_value(req_fields.get("assigned_delegate"))
        consumer_addr = _unwrap_sui_value(req_fields.get("consumer"))
        cti_id = _unwrap_sui_value(req_fields.get("cti_id"))
        encrypted_credentials = _unwrap_sui_value(req_fields.get("encrypted_credentials"))
        response_provided = _unwrap_sui_value(req_fields.get("response_provided"))

        if response_provided:
            return GasSummary()

        delegate_name = None
        for name, acct in self.accounts.items():
            if name.startswith("delegate_") and acct.address == assigned_delegate:
                delegate_name = name
                break
        if not delegate_name:
            raise RuntimeError("Assigned delegate not found locally")

        creds_plain = self.accounts[delegate_name].decrypt_payload(encrypted_credentials).decode("utf-8", errors="replace")

        if simulate_work_hashes > 0:
            x = creds_plain.encode("utf-8")
            for _ in range(int(simulate_work_hashes)):
                x = hashlib.sha256(x).digest()

        cti_fields = self.fetch_object_fields(cti_id)
        acmp = _unwrap_sui_value(cti_fields.get("acmp"))
        if not evaluate_acmp(str(acmp), creds_plain):
            return GasSummary()

        cti_plain = self._decrypt_cti_for_delegate(cti_id, delegate_name)

        consumer_account = None
        for _, acct in self.accounts.items():
            if acct.address == consumer_addr:
                consumer_account = acct
                break
        if consumer_account is None:
            raise RuntimeError("Consumer account not found locally")

        encrypted_response_json = encrypt_for_public_key(consumer_account.public_key, cti_plain)

        # Force stable file:// pointer in benchmarks
        response_ref = self.upload_response_to_ipfs(encrypted_response_json, request_obj_id)

        delegate_addr = self.accounts[delegate_name].address

        resp, gas = self._rpc_move_call_commit(
            signer=delegate_addr,
            package_id=self.package_id,
            module="cti",
            function="response_cti",
            args=[request_obj_id, response_ref],  # Move String, not json.dumps()
            gas_budget="100000000",
        )

        if not isinstance(resp, dict) or not resp.get("effects"):
            raise RuntimeError("response_cti RPC execution returned unexpected response")

        self._cache_invalidate(request_obj_id)
        return gas

    def _pre_split_gas(self, owner: str, num_coins: int = 120, amount_each: int = 1_000_000_000):
        """
        Pre-split gas into many SUI coins.

        - Preferred: 0x2::pay::split (single tx, amounts: vector<u64>)
        - Fallback: 0x2::coin::split repeated (num_coins txs, amount: u64)

        amount_each is in MIST (1e9 MIST = 1 SUI). Default: 1 SUI each.
        """
        print(f"Pre-splitting gas for {owner[:10]}... into {num_coins} coins")

        # Grab coins and pick the largest as the source
        coins = self._rpc_call("suix_getCoins", [owner, "0x2::sui::SUI", None, 50]).get("data") or []
        if not coins:
            raise RuntimeError("No gas coins found")

        coins.sort(key=lambda c: int(c.get("balance", 0)), reverse=True)
        base_coin = coins[0]["coinObjectId"]
        base_bal = int(coins[0].get("balance", 0))

        needed = int(num_coins) * int(amount_each)
        if base_bal < needed:
            raise RuntimeError(
                f"Not enough balance in base coin to split: have {base_bal} mist, need {needed} mist "
                f"({needed / 1e9:.2f} SUI)."
            )

        amounts = [int(amount_each)] * int(num_coins)

        # ---- Preferred: pay::split (vector<u64>) ----
        try:
            self._rpc_move_call_commit(
                signer=owner,
                package_id="0x2",
                module="pay",
                function="split",
                type_args=["0x2::sui::SUI"],
                args=[base_coin, amounts],
                gas_budget="500000000",
            )
            self._gas_refill(owner, limit=500)
            print("Gas split complete via 0x2::pay::split.\n")
            return
        except Exception as e:
            # If function is missing or signature differs, fall back
            msg = str(e)
            if "Could not resolve function" in msg or "resolve function" in msg or "Could not serialize argument" in msg:
                print(f"pay::split not available/compatible, falling back to repeated coin::split. ({msg[:160]}...)\n")
            else:
                # Unexpected failure — still try fallback, but show full reason
                print(f"pay::split failed; trying fallback coin::split. Reason: {msg}\n")

        # ---- Fallback: coin::split (u64) repeated ----
        for i in range(int(num_coins)):
            self._rpc_move_call_commit(
                signer=owner,
                package_id="0x2",
                module="coin",
                function="split",
                type_args=["0x2::sui::SUI"],
                args=[base_coin, int(amount_each)],
                gas_budget="200000000",
            )

            # After first split, re-select the largest coin again
            # (the "base_coin" may change balance; this keeps it safe)
            coins2 = self._rpc_call("suix_getCoins", [owner, "0x2::sui::SUI", None, 50]).get("data") or []
            coins2.sort(key=lambda c: int(c.get("balance", 0)), reverse=True)
            base_coin = coins2[0]["coinObjectId"]

            if (i + 1) % 20 == 0:
                print(f"  split progress: {i+1}/{num_coins}")

        self._gas_refill(owner, limit=500)
        print("Gas split complete via repeated 0x2::coin::split.\n")

    def _consumer_verify_noninteractive(self, request_obj_id: str, *, delete_blob: bool = False) -> bool:
        req_fields = self.fetch_object_fields(request_obj_id)
        if not _unwrap_sui_value(req_fields.get("response_provided")):
            return False

        cti_id = _unwrap_sui_value(req_fields.get("cti_id"))
        resp_nft_id = _unwrap_option_id(req_fields.get("encrypted_response_nft_id"))

        encrypted_json: Optional[str] = None
        ref: Optional[str] = None

        try:
            if resp_nft_id:
                nft_fields = self.fetch_fields_any_object(resp_nft_id)
                ref = _unwrap_sui_value(nft_fields.get("data"))
                if not isinstance(ref, str) or not ref:
                    return False

                if ref.startswith("ipfs://"):
                    encrypted_json = self.ipfs_cat(ref)

                elif ref.startswith("file://"):
                    path = ref.replace("file://", "", 1)
                    with open(path, "r", encoding="utf-8") as f:
                        encrypted_json = f.read()

                else:
                    return False

            else:
                direct = _unwrap_sui_value(req_fields.get("encrypted_response"))
                if isinstance(direct, str) and direct.strip():
                    encrypted_json = direct
                else:
                    return False

            if not isinstance(encrypted_json, str) or not encrypted_json.strip():
                return False

            plaintext = self.accounts["consumer"].decrypt_payload(encrypted_json)
            local_hash = hashlib.sha256(plaintext).digest()

            cti_fields = self.fetch_object_fields(cti_id)
            on_chain_hash = cti_fields.get("cti_hash")
            if not isinstance(on_chain_hash, list):
                return False

            return (local_hash == bytes(on_chain_hash))

        finally:
            # Only delete if explicitly requested
            if delete_blob and isinstance(ref, str) and ref.startswith("file://"):
                path = ref.replace("file://", "", 1)
                try:
                    os.remove(path)
                except FileNotFoundError:
                    pass
                except Exception:
                    pass

    def _add_delegate_noninteractive(self, cti_id: str, request_obj_id: str) -> GasSummary:
        consumer_addr = self.accounts["consumer"].address
        self._cache_invalidate(request_obj_id)

        req_fields = self.fetch_object_fields(request_obj_id)
        resp_nft_id = _unwrap_option_id(req_fields.get("encrypted_response_nft_id"))
        if not resp_nft_id:
            raise RuntimeError("No response nft id; run response first")

        nft_fields = self.fetch_fields_any_object(resp_nft_id)
        ref = _unwrap_sui_value(nft_fields.get("data"))
        if not isinstance(ref, str):
            raise RuntimeError("No ref on response blob")

        if ref.startswith("ipfs://"):
            encrypted_json = self.ipfs_cat(ref)
        elif ref.startswith("file://"):
            path = ref.replace("file://", "")
            with open(path, "r", encoding="utf-8") as f:
                encrypted_json = f.read()
        else:
            raise RuntimeError("Unknown ref type")

        plaintext = self.accounts["consumer"].decrypt_payload(encrypted_json)

        enc_for_consumer_delegate = encrypt_for_public_key(self.accounts["consumer"].public_key, plaintext)
        new_delegate_ref = self.upload_blob_to_ipfs(enc_for_consumer_delegate, "delegate_payload", request_obj_id)
        ref_arg = json.dumps(new_delegate_ref)

        data, gas, raw = self._sui_call_json(
            [
                "sui", "client", "call",
                "--package", self.package_id,
                "--module", "cti",
                "--function", "add_delegate",
                "--args", cti_id, consumer_addr, ref_arg,
                "--json",
            ],
            address=consumer_addr
        )
        if not data:
            raise RuntimeError("add_delegate did not return JSON:\n" + raw[:1200])
        return gas

    # ---------------- Option 8: paper-style outputs ----------------

    def _plot_fig6(self, fig6_points: dict, max_rps: int):
        fig, axes = plt.subplots(1, 4, figsize=(14, 3.2), sharey=True)
        for idx, dn in enumerate([1, 2, 3, 4]):
            ax = axes[idx]
            xs = list(range(1, max_rps + 1))
            means, stds = [], []
            for rps in xs:
                m, s = _mean_std(fig6_points.get((dn, rps), []))
                means.append(m)
                stds.append(s)

            ax.errorbar(xs, means, yerr=stds, marker="o", linewidth=1)
            ax.plot(xs, xs, linewidth=1)  # 1-to-1 threshold line

            ax.set_title(f"Number of delegates: {dn}")
            ax.set_xlabel("Request Per Second")
            if idx == 0:
                ax.set_ylabel("Responses Per Second")
            ax.set_xlim(1, max_rps)
        plt.tight_layout()
        plt.savefig(os.path.join("bench_outputs", "fig6.png"), dpi=200)
        plt.close(fig)

    def _ensure_gas_coins(self, owner: str, target_coins: int, *, do_faucet: bool = True) -> None:
        """
        Ensure the owner's gas pool has at least `target_coins` available coins.

        Strategy:
        1) refill pool from RPC coin list
        2) if still short, optionally call faucet once, refill again
        3) if still short, split ONLY the missing number of coins (not a big fixed number)
        """
        target_coins = max(0, int(target_coins))

        # Step 1: refill
        self._gas_refill(owner, limit=500)
        with self._gas_pool_lock:
            have = len(self._gas_pool.get(owner, []))

        if have >= target_coins:
            print(f"Gas pool already has {have} coins for {owner[:10]}... (target={target_coins}), skipping split.\n")
            return

        missing = target_coins - have
        print(f"Gas pool has {have} coins for {owner[:10]}... (target={target_coins}), missing={missing}")

        # Step 2: optional faucet top-up (often fast on localnet)
        if do_faucet:
            try:
                self.request_gas(owner)
            except Exception:
                pass
            self._gas_refill(owner, limit=500)
            with self._gas_pool_lock:
                have2 = len(self._gas_pool.get(owner, []))
            if have2 >= target_coins:
                print(f"Faucet+refill brought pool to {have2} coins, skipping split.\n")
                return
            missing = target_coins - have2
            print(f"After faucet+refill: have={have2}, still missing={missing}")

        # Step 3: split ONLY what we still need
        # (This is what saves you minutes.)
        self._pre_split_gas(owner, num_coins=missing)
        self._gas_refill(owner, limit=500)

        with self._gas_pool_lock:
            final_have = len(self._gas_pool.get(owner, []))
        print(f"Final gas pool for {owner[:10]}... now has {final_have} coins (target={target_coins}).\n")

    def _render_table1(self, cost_rows: List[dict]):
        xs = [float(r["delegate_count"]) for r in cost_rows]
        ys = [float(r["share_net"]) for r in cost_rows]
        a, b = _linear_fit(xs, ys)

        # pick best DN row that has request/response costs (prefer DN=4)
        r = next((x for x in cost_rows if x["delegate_count"] == 4), None) or \
            next((x for x in cost_rows if x["delegate_count"] == 3), None) or \
            next((x for x in cost_rows if x["delegate_count"] == 2), None) or \
            next((x for x in cost_rows if x["delegate_count"] == 1), None) or \
            cost_rows[0]

        table = [
            ["Share", "2", f"{int(round(a))} + {int(round(b))} × D\u2099"],
            ["Request", "4", f"{int(r.get('request_step4_net', 0))}"],
            ["Request", "6", f"{int(r.get('request_step6_net', 0))}"],
            ["Response", "10", f"{int(r.get('response_step10_net', 0))}"],
            ["Delegate", "13", f"{int(r.get('delegate_step13_net', 0))}"],
        ]

        fig, ax = plt.subplots(figsize=(7.2, 2.4))
        ax.axis("off")
        ax.set_title("TABLE I. Gas cost for each smart contract function", pad=10)

        tbl = ax.table(
            cellText=table,
            colLabels=["Function", "Associated Step", "Gas Cost (net)"],
            cellLoc="center",
            loc="center",
        )
        tbl.auto_set_font_size(False)
        tbl.set_fontsize(9)
        tbl.scale(1.0, 1.3)

        plt.savefig(os.path.join("bench_outputs", "table1.png"), dpi=200, bbox_inches="tight")
        plt.close(fig)

    def _plot_fig7(self, cost_rows: List[dict], fig6_points: dict, max_rps: int):
        labels = ["0 delegates", "1 delegate", "2 delegates", "3 delegates", "4 delegates"]
        x = list(range(0, 5))

        share = [r["share_net"] for r in cost_rows]

        rr = [0] * 5
        for r in cost_rows:
            dn = r["delegate_count"]
            if dn >= 1:
                rr[dn] = int(r["request_step4_net"]) + int(r["request_step6_net"]) + int(r["response_step10_net"])

        mrps = [0.0] * 5
        for dn in [1, 2, 3, 4]:
            best = 0.0
            for rps in range(1, max_rps + 1):
                m, _ = _mean_std(fig6_points.get((dn, rps), []))
                best = max(best, m)
            mrps[dn] = best

        fig, ax1 = plt.subplots(figsize=(7.6, 3.2))
        ax1.plot(x, share, marker="x", linewidth=1, label="Share Cost")
        ax1.plot(x, rr, marker="o", linewidth=1, label="Request-Response Cost")
        ax1.set_xticks(x)
        ax1.set_xticklabels(labels)
        ax1.set_ylabel("Cost (net gas units)")
        ax1.legend(loc="upper left")

        ax2 = ax1.twinx()
        ax2.plot(x, mrps, marker="s", linewidth=1, color="green", label="Scalability (MRPS)")
        ax2.set_ylabel("Scalability (MRPS)")
        ax2.legend(loc="upper right")

        plt.tight_layout()
        plt.savefig(os.path.join("bench_outputs", "fig7.png"), dpi=200)
        plt.close(fig)

    def run_benchmarks_paper_style(self):
        def _fmt_seconds(s: float) -> str:
            s = max(0, int(round(s)))
            h = s // 3600
            m = (s % 3600) // 60
            sec = s % 60
            if h > 0:
                return f"{h:d}h {m:02d}m {sec:02d}s"
            if m > 0:
                return f"{m:d}m {sec:02d}s"
            return f"{sec:d}s"

        bench_t0_wall = time.time()
        bench_t0 = time.perf_counter()
        print(f"\n⏱️  Benchmark started at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(bench_t0_wall))}\n")

        try:
            os.makedirs("bench_outputs", exist_ok=True)

            # Benchmark should NOT include IPFS overhead in the hot path
            self.ipfs_enabled = False

            # ---- Ask benchmark parameters FIRST (so we can size gas coins correctly) ----
            try:
                iterations = int(input("Iterations per (delegates,rps) point (paper used 100): ").strip() or "30")
            except ValueError:
                iterations = 30
            try:
                seconds = int(input("Seconds per iteration window (paper used 90): ").strip() or "15")
            except ValueError:
                seconds = 15
            try:
                max_rps = int(input("Max request rate per second (paper used 11): ").strip() or "11")
            except ValueError:
                max_rps = 11
            try:
                simulate_work = int(input("Simulated off-chain hash ops per request (0=off, paper used 100000): ").strip() or "0")
            except ValueError:
                simulate_work = 0

            # ---- GAS COIN SIZING (reduce splits massively) ----
            #
            # Consumer stage A does 2 tx per request (request_cti + credentials_cti).
            # You cap REQ_WORKERS in your loop to <= 16, so concurrency is bounded.
            #
            # Delegates stage B concurrency is dn (1..4), so each delegate needs only a small cushion.
            #
            # These targets are intentionally modest but safe for your current code structure.
            REQ_WORKERS_CAP = 16
            consumer_target = 2 * REQ_WORKERS_CAP + 12   # ~44 coins is plenty vs 120
            delegate_target = 12                         # vs 60; enough for dn<=4 + bursts

            consumer = self.accounts["consumer"].address

            # Ensure consumer pool has enough coins (skip splitting if already sufficient)
            self._ensure_gas_coins(consumer, consumer_target, do_faucet=True)

            # Ensure each delegate has enough coins (skip splitting if already sufficient)
            for i in range(4):
                daddr = self.accounts[f"delegate_{i}"].address
                self._ensure_gas_coins(daddr, delegate_target, do_faucet=True)
                time.sleep(0.15)  # small delay to let localnet index new coins

            with self._gas_pool_lock:
                for i in range(4):
                    daddr = self.accounts[f"delegate_{i}"].address
                    print(f"DEBUG: gas pool for delegate_{i} now has {len(self._gas_pool.get(daddr, []))} coins")
                print(f"DEBUG: gas pool for consumer now has {len(self._gas_pool.get(consumer, []))} coins")

            payload = b'{"bench":"cti","msg":"hello"}'

            # ---- COSTS (DN=0..4) ----
            cost_rows = []
            print("\n--- Computing gas cost rows (DN=0..4) ---")
            for dn in range(0, 5):
                print(f"Creating cost row for delegates={dn}")
                cti_id, gas_share = self._create_cti_noninteractive(dn, payload, acmp_num=2)
                row = {
                    "delegate_count": dn,
                    "share_net": gas_share.net,
                    "request_step4_net": 0,
                    "request_step6_net": 0,
                    "response_step10_net": 0,
                    "delegate_step13_net": 0,
                }
                if dn >= 1:
                    req_id, _, gas4, gas6 = self._request_and_credentials(cti_id, credentials_text="andres")
                    gas10 = self._delegate_respond_noninteractive(req_id, simulate_work_hashes=simulate_work)

                    # IMPORTANT: do NOT delete the response file yet; Step 13 needs it.
                    _ = self._consumer_verify_noninteractive(req_id, delete_blob=False)

                    gas13 = self._add_delegate_noninteractive(cti_id, req_id)

                    # Now it's safe to delete it (optional cleanup)
                    _ = self._consumer_verify_noninteractive(req_id, delete_blob=True)

                    row["request_step4_net"] = gas4.net
                    row["request_step6_net"] = gas6.net
                    row["response_step10_net"] = gas10.net
                    row["delegate_step13_net"] = gas13.net
                cost_rows.append(row)

            # ---- FIG6 points (DN=1..4, rps=1..max) ----
            fig6_points: Dict[Tuple[int, int], List[float]] = {}

            for dn in range(1, 5):
                cti_id, _ = self._create_cti_noninteractive(dn, payload, acmp_num=2)

                for rps in range(1, max_rps + 1):
                    rates = []

                    for _it in range(iterations):
                        start = time.time()
                        end = start + seconds
                        next_tick = start

                        attempted = ok = fail_req = fail_resp = fail_verify = 0
                        printed_first_fail_req = False

                        MAX_INFLIGHT = max(20, rps * 5)
                        REQ_WORKERS  = min(REQ_WORKERS_CAP, max(4, rps * 2))
                        VER_WORKERS  = 4

                        with ThreadPoolExecutor(max_workers=REQ_WORKERS) as ex_req, \
                            ThreadPoolExecutor(max_workers=dn) as ex_resp, \
                            ThreadPoolExecutor(max_workers=VER_WORKERS) as ex_ver:

                            req_futs: List[object] = []
                            resp_futs: List[Tuple[object, str]] = []
                            ver_futs: List[Tuple[object, str]] = []

                            def _stageA_request_and_creds():
                                req_id, _, _, _ = self._request_and_credentials(cti_id, credentials_text="andres")
                                return req_id

                            while True:
                                now = time.time()
                                if now >= end:
                                    break

                                if now >= next_tick:
                                    while now >= next_tick and now < end:
                                        next_tick += 1.0 / max(1, rps)

                                        if len(req_futs) < MAX_INFLIGHT:
                                            attempted += 1
                                            req_futs.append(ex_req.submit(_stageA_request_and_creds))
                                        now = time.time()
                                else:
                                    time.sleep(min(0.002, max(0.0, next_tick - now)))

                                # Stage A -> Stage B
                                new_req_futs = []
                                for f in req_futs:
                                    if not f.done():
                                        new_req_futs.append(f)
                                        continue
                                    try:
                                        req_id = f.result()
                                    except Exception as e:
                                        fail_req += 1
                                        if not printed_first_fail_req:
                                            printed_first_fail_req = True
                                            print("First fail_req error:", repr(e))
                                        continue

                                    rf = ex_resp.submit(self._delegate_respond_noninteractive, req_id, simulate_work_hashes=simulate_work)
                                    resp_futs.append((rf, req_id))
                                req_futs = new_req_futs

                                # Stage B -> Stage C
                                new_resp_futs = []
                                for rf, req_id in resp_futs:
                                    if not rf.done():
                                        new_resp_futs.append((rf, req_id))
                                        continue
                                    try:
                                        _ = rf.result()
                                    except Exception:
                                        fail_resp += 1
                                        continue

                                    vf = ex_ver.submit(self._consumer_verify_noninteractive, req_id, delete_blob=True)
                                    ver_futs.append((vf, req_id))
                                resp_futs = new_resp_futs

                                # Stage C harvest
                                new_ver_futs = []
                                for vf, req_id in ver_futs:
                                    if not vf.done():
                                        new_ver_futs.append((vf, req_id))
                                        continue
                                    try:
                                        if vf.result():
                                            ok += 1
                                        else:
                                            fail_verify += 1
                                    except Exception:
                                        fail_verify += 1
                                ver_futs = new_ver_futs

                            # Grace period
                            grace_end = time.time() + 1.0
                            while time.time() < grace_end and (req_futs or resp_futs or ver_futs):
                                new_req_futs = []
                                for f in req_futs:
                                    if not f.done():
                                        new_req_futs.append(f)
                                        continue
                                    try:
                                        req_id = f.result()
                                    except Exception as e:
                                        fail_req += 1
                                        if not printed_first_fail_req:
                                            printed_first_fail_req = True
                                            print("First fail_req error (grace):", repr(e))
                                        continue
                                    rf = ex_resp.submit(self._delegate_respond_noninteractive, req_id, simulate_work_hashes=simulate_work)
                                    resp_futs.append((rf, req_id))
                                req_futs = new_req_futs

                                new_resp_futs = []
                                for rf, req_id in resp_futs:
                                    if not rf.done():
                                        new_resp_futs.append((rf, req_id))
                                        continue
                                    try:
                                        _ = rf.result()
                                    except Exception:
                                        fail_resp += 1
                                        continue
                                    vf = ex_ver.submit(self._consumer_verify_noninteractive, req_id, delete_blob=True)
                                    ver_futs.append((vf, req_id))
                                resp_futs = new_resp_futs

                                new_ver_futs = []
                                for vf, req_id in ver_futs:
                                    if not vf.done():
                                        new_ver_futs.append((vf, req_id))
                                        continue
                                    try:
                                        if vf.result():
                                            ok += 1
                                        else:
                                            fail_verify += 1
                                    except Exception:
                                        fail_verify += 1
                                ver_futs = new_ver_futs

                                time.sleep(0.01)

                        rate = ok / max(1e-9, float(seconds))
                        print(
                            f"[dn={dn} rps={rps} it={_it}] "
                            f"attempted={attempted} target~={rps*seconds} ok={ok} "
                            f"fail_req={fail_req} fail_resp={fail_resp} fail_verify={fail_verify} "
                            f"resp/s={rate:.2f}"
                        )
                        rates.append(rate)

                    fig6_points[(dn, rps)] = rates
                    m, s = _mean_std(rates)
                    print(f"delegates={dn} rps={rps} mean_resp/s={m:.2f} std={s:.2f}")

            raw = {
                "iterations": iterations,
                "seconds": seconds,
                "max_rps": max_rps,
                "simulate_work_hashes": simulate_work,
                "cost_rows": cost_rows,
                "fig6_points": {f"{dn},{rps}": rates for (dn, rps), rates in fig6_points.items()},
            }
            with open(os.path.join("bench_outputs", "raw_results.json"), "w", encoding="utf-8") as f:
                json.dump(raw, f, indent=2)

            self._plot_fig6(fig6_points, max_rps)
            self._render_table1(cost_rows)
            self._plot_fig7(cost_rows, fig6_points, max_rps)

            print("\n✅ Generated:")
            print("  bench_outputs/fig6.png")
            print("  bench_outputs/table1.png")
            print("  bench_outputs/fig7.png")
            print("  bench_outputs/raw_results.json\n")

        finally:
            bench_dt = time.perf_counter() - bench_t0
            bench_t1_wall = time.time()
            print(f"\n⏱️  Benchmark finished at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(bench_t1_wall))}")
            print(f"⏱️  Total benchmark time: {_fmt_seconds(bench_dt)} ({bench_dt:.2f} seconds)\n")

    def _rpc_call(self, method: str, params: list):
        with self._rpc_id_lock:
            rid = self._rpc_next_id
            self._rpc_next_id += 1

        payload = {
            "jsonrpc": "2.0",
            "id": rid,
            "method": method,
            "params": params
        }

        r = requests.post("http://127.0.0.1:9000", json=payload, timeout=30)
        r.raise_for_status()
        result = r.json()

        if "error" in result:
            raise RuntimeError(result["error"])

        return result["result"]
    
    def _sign_txbytes_with_keytool(self, address: str, tx_bytes_b64: str) -> str:
        """
        Returns a Sui signature string for sui_executeTransactionBlock.
        Thread-safe: keytool/keystore access is serialized.
        Uses this thread's SUI_CONFIG_DIR so threads don't fight.
        """
        with self._keytool_lock:
            r = subprocess.run(
                ["sui", "keytool", "sign", "--address", address, "--data", tx_bytes_b64, "--json"],
                capture_output=True,
                text=True,
                env=self._sui_env(),  # <-- IMPORTANT: thread-local config dir
            )

        if r.returncode != 0:
            raise RuntimeError(r.stderr or r.stdout or "sui keytool sign failed")

        try:
            j = json.loads(r.stdout)
        except Exception:
            raise RuntimeError("Failed to parse keytool sign JSON:\n" + (r.stdout or "")[:800])

        sig = j.get("suiSignature")
        if not isinstance(sig, str) or not sig:
            raise RuntimeError("keytool sign did not return suiSignature:\n" + r.stdout[:800])

        return sig
    
    def _rpc_unsafe_move_call(
        self,
        signer: str,
        package_id: str,
        module: str,
        function: str,
        type_arguments: Optional[List[str]],
        arguments: List[object],
        gas_object: Optional[str] = None,
        gas_budget: str = "100000000",
    ):
        arguments = self._rpc_normalize_args(arguments)  # <-- ADD THIS LINE

        return self._rpc_call(
            "unsafe_moveCall",
            [
                signer,
                package_id,
                module,
                function,
                type_arguments or [],
                arguments,
                gas_object,
                gas_budget,
                None,
            ],
        )
    
    def _rpc_execute_tx(self, tx_bytes_b64: str, signature: str) -> dict:
        """
        Executes txBytes with signature via sui_executeTransactionBlock.
        Returns the transaction response including effects/objectChanges/events if requested.
        :contentReference[oaicite:6]{index=6}
        """
        options = {
            "showEffects": True,
            "showObjectChanges": True,
            "showEvents": True,
        }
        return self._rpc_call(
            "sui_executeTransactionBlock",
            [
                tx_bytes_b64,
                [signature],
                options,
                "WaitForLocalExecution",
            ],
        )
    
    def _rpc_move_call_commit(
        self,
        signer: str,
        package_id: str,
        module: str,
        function: str,
        args: List[object],
        type_args: Optional[List[str]] = None,
        gas_object: Optional[str] = None,
        gas_budget: str = "100000000",
    ) -> Tuple[dict, GasSummary]:
        """
        1) unsafe_moveCall -> txBytes
        2) keytool sign    -> suiSignature
        3) execute         -> tx response
        Uses a per-tx unique gas coin from the pool unless gas_object is provided.
        """
        owned_gas = None
        if gas_object is None:
            owned_gas = self._gas_acquire(signer)
            gas_object = owned_gas

        try:
            tb = self._rpc_unsafe_move_call(
                signer=signer,
                package_id=package_id,
                module=module,
                function=function,
                type_arguments=type_args,
                arguments=args,
                gas_object=gas_object,   # ALWAYS specific now
                gas_budget=gas_budget,
            )

            txb = tb.get("txBytes")
            if not isinstance(txb, str) or not txb:
                raise RuntimeError("unsafe_moveCall did not return txBytes:\n" + json.dumps(tb, indent=2)[:800])

            sig = self._sign_txbytes_with_keytool(signer, txb)
            resp = self._rpc_execute_tx(txb, sig)
            return resp, _parse_gas_summary(resp)

        finally:
            if owned_gas is not None:
                self._gas_release(signer, owned_gas)

    def _rpc_normalize_args(self, x):
        """
        Sui JSON-RPC expects u64 values as STRINGS, not JSON numbers.
        - int -> str
        - list[int] that looks like bytes (0..255) -> keep ints (vector<u8>)
        - list -> recurse
        - dict -> recurse values
        """
        if isinstance(x, bool) or x is None:
            return x
        if isinstance(x, int):
            return str(x)
        if isinstance(x, list):
            # keep likely vector<u8> as ints
            if x and all(isinstance(v, int) and 0 <= v <= 255 for v in x):
                return x
            return [self._rpc_normalize_args(v) for v in x]
        if isinstance(x, dict):
            return {k: self._rpc_normalize_args(v) for k, v in x.items()}
        return x

    # ---------------- run ----------------

    def run(self):
        atexit.register(self.stop_localnet)
        atexit.register(self.stop_ipfs)
        atexit.register(self.cleanup_thread_configs)

        if not self.start_localnet():
            return

        self.start_ipfs()
        if not self.setup_accounts_6():
            return

        if os.path.exists("Pub.local.toml"):
            try:
                os.remove("Pub.local.toml")
            except Exception:
                pass

        if not self.publish_package():
            return

        while True:
            print("1) Share CTI (Steps 1 & 2)")
            print("2) Retrieve CTI (delegate) (Step 3)")
            print("3) Request CTI (consumer) (Steps 4 & 5)")
            print("4) Submit Credentials (consumer) (Step 6)")
            print("5) Delegate control + respond (Steps 7, 8, 9 & 10)")
            print("6) Consumer fetch + decrypt + verify (Steps 11 & 12)")
            print("7) Become delegate (consumer) (Step 13)")
            print("8) Benchmark + generate Table/Figs")
            print("0) Exit")
            choice = input("> ").strip()

            if choice == "1":
                self.share_cti()
            elif choice == "2":
                self.retrieve_cti_as_delegate()
            elif choice == "3":
                self.request_cti_as_consumer()
            elif choice == "4":
                self.submit_credentials_as_consumer()
            elif choice == "5":
                self.delegate_steps_7_8_9()
            elif choice == "6":
                self.consumer_steps_11_12()
            elif choice == "7":
                self.consumer_step_13_become_delegate()
            elif choice == "8":
                self.run_benchmarks_paper_style()
            elif choice == "0":
                return


if __name__ == "__main__":
    prog = CTISharingProgram()
    try:
        prog.run()
    finally:
        prog.stop_ipfs()
        prog.stop_localnet()