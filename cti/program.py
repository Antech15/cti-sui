#!/usr/bin/env python3
import atexit
import base64
import csv
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
        self.localnet_process: Optional[subprocess.Popen] = None
        self.accounts: Dict[str, Account] = {}
        self.package_id: Optional[str] = None
        self.registry_id: Optional[str] = None

        self.explorer_base = "https://explorer.polymedia.app"
        self.network_param = "?network=http%3A%2F%2F127.0.0.1%3A9000"

        self.ipfs = IPFSDaemon()
        self.ipfs_enabled = False

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

    def fetch_object_fields(self, object_id: str) -> dict:
        data = self._fetch_object_json(object_id)
        content = data.get("content") or {}
        if isinstance(content, dict):
            return (content.get("fields") or {})
        return {}

    def fetch_fields_any_object(self, object_id: str) -> dict:
        return self.fetch_object_fields(object_id)

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

    def _sui_call_json(self, args_list: List[str]) -> Tuple[Optional[dict], GasSummary, str]:
        r = subprocess.run(args_list, capture_output=True, text=True)
        out = r.stdout or ""
        try:
            data = json.loads(out)
        except Exception:
            return None, GasSummary(), out
        return data, _parse_gas_summary(data), out

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

        self.switch_account(self.accounts["producer"].address)

        data, gas, _ = self._sui_call_json(
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
            ]
        )
        if not data:
            raise RuntimeError("share_cti did not return JSON")

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
        if not self.switch_account(consumer_addr):
            raise RuntimeError("Failed to switch to consumer account")

        data4, gas4, raw4 = self._sui_call_json(
            [
                "sui", "client", "call",
                "--package", self.package_id,
                "--module", "cti",
                "--function", "request_cti",
                "--args", cti_id,
                "--json",
            ]
        )
        if not data4:
            raise RuntimeError(f"request_cti did not return JSON: {raw4[:200]}")

        request_obj_id = None
        for change in data4.get("objectChanges", []):
            if change.get("type") == "created" and (change.get("objectType") or "").endswith("::CTIRequest"):
                request_obj_id = change.get("objectId")
                break
        if not request_obj_id:
            raise RuntimeError("Could not extract CTIRequest objectId")

        assigned_delegate = None
        for ev in data4.get("events", []):
            et = ev.get("type") or ev.get("eventType") or ""
            if et.endswith("::CTIRequested"):
                parsed = ev.get("parsedJson") or {}
                assigned_delegate = parsed.get("assigned_delegate")
                break

        if not assigned_delegate:
            req_fields = self.fetch_object_fields(request_obj_id)
            assigned_delegate = _unwrap_sui_value(req_fields.get("assigned_delegate"))

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
        enc_arg = json.dumps(enc_cred_json)

        data6, gas6, raw6 = self._sui_call_json(
            [
                "sui", "client", "call",
                "--package", self.package_id,
                "--module", "cti",
                "--function", "credentials_cti",
                "--args",
                request_obj_id,
                enc_arg,
                "--json",
            ]
        )
        if not data6:
            raise RuntimeError(f"credentials_cti did not return JSON: {raw6[:200]}")

        return request_obj_id, assigned_delegate, gas4, gas6

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

        if not self.switch_account(self.accounts[delegate_name].address):
            raise RuntimeError("Failed to switch to delegate account")

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
        response_ref = self.upload_response_to_ipfs(encrypted_response_json, request_obj_id)
        ref_arg = json.dumps(response_ref)

        data, gas, raw = self._sui_call_json(
            [
                "sui", "client", "call",
                "--package", self.package_id,
                "--module", "cti",
                "--function", "response_cti",
                "--args",
                request_obj_id,
                ref_arg,
                "--json",
            ]
        )
        if not data:
            raise RuntimeError(f"response_cti did not return JSON: {raw[:200]}")
        return gas

    def _consumer_verify_noninteractive(self, request_obj_id: str) -> bool:
        consumer_addr = self.accounts["consumer"].address
        self.switch_account(consumer_addr)

        req_fields = self.fetch_object_fields(request_obj_id)
        if not _unwrap_sui_value(req_fields.get("response_provided")):
            return False

        cti_id = _unwrap_sui_value(req_fields.get("cti_id"))
        resp_nft_id = _unwrap_option_id(req_fields.get("encrypted_response_nft_id"))

        encrypted_json = None
        if resp_nft_id:
            nft_fields = self.fetch_fields_any_object(resp_nft_id)
            ref = _unwrap_sui_value(nft_fields.get("data"))
            if not isinstance(ref, str):
                return False
            if ref.startswith("ipfs://"):
                encrypted_json = self.ipfs_cat(ref)
            elif ref.startswith("file://"):
                path = ref.replace("file://", "")
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

        plaintext = self.accounts["consumer"].decrypt_payload(encrypted_json)
        local_hash = hashlib.sha256(plaintext).digest()

        cti_fields = self.fetch_object_fields(cti_id)
        on_chain_hash = cti_fields.get("cti_hash")
        if not isinstance(on_chain_hash, list):
            return False

        return local_hash == bytes(on_chain_hash)

    def _add_delegate_noninteractive(self, cti_id: str, request_obj_id: str) -> GasSummary:
        consumer_addr = self.accounts["consumer"].address
        self.switch_account(consumer_addr)

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
                "--args",
                cti_id,
                consumer_addr,
                ref_arg,
                "--json",
            ]
        )
        if not data:
            raise RuntimeError(f"add_delegate did not return JSON: {raw[:200]}")
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
        ax2.plot(x, mrps, marker="s", linewidth=1, label="Scalability (MRPS)")
        ax2.set_ylabel("Scalability (MRPS)")
        ax2.legend(loc="upper right")

        plt.tight_layout()
        plt.savefig(os.path.join("bench_outputs", "fig7.png"), dpi=200)
        plt.close(fig)

    def run_benchmarks_paper_style(self):
        os.makedirs("bench_outputs", exist_ok=True)

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

        payload = b'{"bench":"cti","msg":"hello"}'

        # ---- COSTS (DN=0..4) ----
        cost_rows = []
        for dn in range(0, 5):
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
                _ = self._consumer_verify_noninteractive(req_id)
                gas13 = self._add_delegate_noninteractive(cti_id, req_id)
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
                    responded = 0
                    next_tick = start
                    while time.time() < end:
                        now = time.time()
                        if now < next_tick:
                            time.sleep(min(0.005, next_tick - now))
                            continue
                        next_tick += 1.0 / rps
                        try:
                            req_id, _, _, _ = self._request_and_credentials(cti_id, credentials_text="andres")
                            self._delegate_respond_noninteractive(req_id, simulate_work_hashes=simulate_work)
                            if self._consumer_verify_noninteractive(req_id):
                                responded += 1
                        except Exception:
                            pass
                    duration = max(0.0001, time.time() - start)
                    rates.append(responded / duration)

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

    # ---------------- run ----------------

    def run(self):
        atexit.register(self.stop_localnet)
        atexit.register(self.stop_ipfs)

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