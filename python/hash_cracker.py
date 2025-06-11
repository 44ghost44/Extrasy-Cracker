import argparse
import hashlib
import concurrent.futures
import sys
import os
import shutil
from rich.console import Console
from rich.table import Table
import multiprocessing
import importlib

console = Console()

def detect_algo(hash_str):
    h = hash_str.lower()
    if h.startswith("$2a$") or h.startswith("$2b$") or h.startswith("$2y$"):
        return "bcrypt"
    elif h.startswith("$6$"):
        return "crypt-sha512"
    elif len(h) == 32 and all(c in "0123456789abcdef" for c in h):
        return "md5/ntlm"
    elif len(h) == 32 and all(c in "0123456789abcdef" for c in h.upper()):
        return "ntlm"
    elif len(h) == 40 and all(c in "0123456789abcdef" for c in h):
        return "sha1"
    elif len(h) == 41 and h.startswith("*") and all(c in "0123456789abcdef" for c in h[1:]):
        return "mysql-sha1"
    elif len(h) == 64 and all(c in "0123456789abcdef" for c in h):
        return "sha256"
    elif len(h) == 96 and all(c in "0123456789abcdef" for c in h):
        return "sha384"
    elif len(h) == 128 and all(c in "0123456789abcdef" for c in h):
        return "sha512"
    elif len(h) == 16 and all(c in "0123456789abcdef" for c in h):
        return "lm"
    elif len(h) in (56, 112) and all(c in "0123456789abcdef" for c in h):
        return "whirlpool"
    elif len(h) == 64 and all(c in "0123456789abcdef" for c in h):
        return "sha3_256"
    elif len(h) == 128 and all(c in "0123456789abcdef" for c in h):
        return "sha3_512"
    else:
        return "unknown"

def hash_word(word, algo, salt=None):
    word_bytes = word.encode('utf-8', errors='ignore')
    if algo == "md5":
        return hashlib.md5(word_bytes).hexdigest()
    elif algo == "sha1":
        return hashlib.sha1(word_bytes).hexdigest()
    elif algo == "sha256":
        return hashlib.sha256(word_bytes).hexdigest()
    elif algo == "sha384":
        return hashlib.sha384(word_bytes).hexdigest()
    elif algo == "sha512":
        return hashlib.sha512(word_bytes).hexdigest()
    elif algo == "ntlm":
        try:
            from Crypto.Hash import MD4
            return MD4.new(word.encode('utf-16le')).hexdigest()
        except Exception:
            return None
    elif algo == "lm":
        return None
    elif algo == "mysql-sha1":
        return None
    elif algo == "whirlpool":
        try:
            from Crypto.Hash import Whirlpool
            return Whirlpool.new(word_bytes).hexdigest()
        except Exception:
            return None
    elif algo == "sha3_256":
        return hashlib.sha3_256(word_bytes).hexdigest()
    elif algo == "sha3_512":
        return hashlib.sha3_512(word_bytes).hexdigest()
    elif algo == "crypt-sha512" and salt:
        try:
            import crypt
            return crypt.crypt(word, salt)
        except Exception:
            return None
    else:
        return None

def crack_one(args):
    hash_line, dict_file = args
    detected = detect_algo(hash_line)
    if detected == "unknown":
        return (hash_line, "UNKNOWN TYPE", "magenta")
    if detected == "bcrypt":
        if shutil.which("hashcat") or shutil.which("john"):
            return (hash_line, "BCRYPT (usá hashcat/john)", "yellow")
        return (hash_line, "BCRYPT (no soportado, usá hashcat/john)", "yellow")
    if detected == "crypt-sha512":
        try:
            salt = "$6$" + hash_line.split("$")[2] + "$"
        except Exception:
            salt = None
        algo = "crypt-sha512"
        with open(dict_file, "r", encoding="utf-8", errors="ignore") as f:
            for word in f:
                word = word.strip()
                if not word or word.startswith("#"):
                    continue
                hashed = hash_word(word, algo, salt)
                if hashed == hash_line:
                    return (hash_line, f"{word} (crypt-sha512)", "green")
        return (hash_line, "NOT FOUND", "red")
    algos = []
    if detected == "md5/ntlm":
        algos = ["md5", "ntlm"]
    else:
        algos = [detected]
    with open(dict_file, "r", encoding="utf-8", errors="ignore") as f:
        for word in f:
            word = word.strip()
            if not word or word.startswith("#"):
                continue
            for algo in algos:
                hashed = hash_word(word, algo)
                if hashed and hashed.lower() == hash_line.lower():
                    return (hash_line, f"{word} ({algo})", "green")
    return (hash_line, "NOT FOUND", "red")

def crack_hashes(hashes_file, dict_file, threads=4):
    hashes = []
    with open(hashes_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            hashes.append(line)
    results = []
    with multiprocessing.get_context("spawn").Pool(threads) as pool:
        for result in pool.imap_unordered(crack_one, [(h, dict_file) for h in hashes]):
            results.append(result)
            color = result[2]
            console.print(f"[{color}]{result[0]} : {result[1]}[/{color}]")
    cracked = [r for r in results if r[2] == "green"]
    notfound = [r for r in results if r[2] == "red"]
    unknown = [r for r in results if r[2] in ("magenta", "yellow")]
    console.print()
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Tipo")
    table.add_column("Cantidad")
    table.add_column("Ejemplos", overflow="fold")
    table.add_row("[green]Crackeados[/green]", str(len(cracked)), "\n".join(f"{r[0]} : {r[1]}" for r in cracked[:3]) + (" ..." if len(cracked) > 3 else ""))
    table.add_row("[red]No encontrados[/red]", str(len(notfound)), "\n".join(f"{r[0]}" for r in notfound[:3]) + (" ..." if len(notfound) > 3 else ""))
    table.add_row("[magenta]Tipo desconocido[/magenta]", str(len(unknown)), "\n".join(f"{r[0]} : {r[1]}" for r in unknown[:3]) + (" ..." if len(unknown) > 3 else ""))
    table.add_row("[blue]Total[/blue]", str(len(results)), "")
    console.print(table)

if __name__ == "__main__":
    import shutil
    parser = argparse.ArgumentParser(description="Hashcracker robusto (MD5, SHA1, SHA256, SHA384, SHA512, SHA3, NTLM, bcrypt detecta, crypt-sha512, MySQL, Whirlpool, LM)")
    parser.add_argument("--hashes", required=True)
    parser.add_argument("--dict", required=True)
    parser.add_argument("--threads", type=int, default=4)
    args = parser.parse_args()
    if not os.path.isfile(args.hashes):
        console.print(f"[red]Archivo de hashes '{args.hashes}' no existe o no es legible.[/red]")
        sys.exit(1)
    if not os.path.isfile(args.dict):
        console.print(f"[red]Archivo diccionario '{args.dict}' no existe o no es legible.[/red]")
        sys.exit(1)
    crack_hashes(args.hashes, args.dict, args.threads)
    
    