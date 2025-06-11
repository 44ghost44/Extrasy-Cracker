from rich.console import Console
from rich.text import Text
import subprocess
import sys
import threading
import time
import os

console = Console()

def print_multicolor_logo():
    logo_lines = [
        " ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ",
        "||E |||x |||t |||a |||s |||y |||- |||C |||r |||a |||c |||k |||e |||r ||",
        "||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__||",
        "|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|"
    ]
    colors = [
        "red", "yellow", "green", "cyan", "blue", "magenta", "bright_red",
        "bright_yellow", "bright_green", "bright_cyan", "bright_blue",
        "bright_magenta", "white", "bright_white"
    ]
    for i, line in enumerate(logo_lines):
        text = Text()
        blocks = [line[j:j+5] for j in range(0, len(line), 5)]
        for idx, block in enumerate(blocks):
            color = colors[idx % len(colors)]
            text.append(block, style=color)
        console.print(text)
    print()
    descripcion = (
        "Tool para crackear contraseñas.\n"
        "Python: MD5, SHA1, SHA256, SHA384, SHA512, SHA3, NTLM, Whirlpool, MySQL, bcrypt detecta, crypt-sha512.\n"
        "Go:     MD5, SHA1, SHA256, SHA384, SHA512.\n"
        "Bash:   MD5, SHA1, SHA256, SHA384, SHA512.\n"
        "Multi-engine para pentesters, CTFs y curiosos xd. Para ayuda: --help o -h"
    )
    console.print(Text(descripcion, style="bold green"))
    print()
    firma = (
        Text("By", style="bold red")
        + Text("44", style="bold yellow")
        + Text("ghost", style="bold blue")
        + Text("44", style="bold magenta")
        + Text("<3", style="bold magenta")
    )
    console.print(firma, justify="left")
    print()

def ask(question, default=None, options=None):
    while True:
        prompt = f"{question}"
        if options:
            prompt += f" [{'/'.join(options)}]"
        if default:
            prompt += f" (default: {default})"
        prompt += ": "
        answer = input(prompt).strip()
        if not answer and default is not None:
            return default
        if options and answer not in options:
            print(f"Opción inválida. Escoge entre: {', '.join(options)}")
            continue
        if answer:
            return answer

def run_with_spinner(cmd):
    spinner_chars = ["|", "/", "-", "\\"]
    done = threading.Event()
    start_time = time.time()

    def spinner():
        idx = 0
        while not done.is_set():
            print(f"\rCrackeando... {spinner_chars[idx % 4]}", end="", flush=True)
            idx += 1
            time.sleep(0.12)
        print("\r" + " " * 50 + "\r", end="", flush=True)

    spin_thread = threading.Thread(target=spinner)
    spin_thread.start()
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        while True:
            output = process.stdout.readline()
            if output == "" and process.poll() is not None:
                break
            if output:
                print(output, end="")
        process.wait()
    finally:
        elapsed = time.time() - start_time
        if elapsed < 1:
            time.sleep(1 - elapsed)
        done.set()
        spin_thread.join()

if __name__ == "__main__":
    print_multicolor_logo()
    engines = {
        "python": ["python", "python/hash_cracker.py"],
        "go": ["go", "run", "go/batch_checker.go"],
        "bash": ["bash/quick_md5_crack.sh"]
    }
    engine = ask("¿Qué engine buscás usar?", default="python", options=["python", "go", "bash"])
    print()
    hashes = ask("Ruta del archivo de hashes")
    while not os.path.isfile(hashes):
        print("Archivo no encontrado. Intenta de nuevo.")
        hashes = ask("Ruta del archivo de hashes")
    print()
    diccionario = ask("Ruta del archivo de diccionario")
    while not os.path.isfile(diccionario):
        print("Archivo no encontrado. Intenta de nuevo.")
        diccionario = ask("Ruta del archivo de diccionario")
    print()
    threads = None
    if engine in ["python", "go"]:
        try:
            threads = int(ask("¿Número de hilos?", default="4"))
            if threads < 1:
                threads = 4
        except Exception:
            threads = 4
        print()
    if engine == "python":
        cmd = engines["python"] + ["--hashes", hashes, "--dict", diccionario, "--threads", str(threads)]
    elif engine == "go":
        cmd = engines["go"] + ["--file", hashes, "--dict", diccionario, "--threads", str(threads)]
    elif engine == "bash":
        cmd = engines["bash"] + [hashes, diccionario]
    else:
        console.print("[red]Engine no soportado[/red]")
        sys.exit(1)
    run_with_spinner(cmd)
    