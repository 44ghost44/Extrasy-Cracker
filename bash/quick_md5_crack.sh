#!/bin/bash
set -euo pipefail
hashes_file="$1"
dict_file="$2"
has_tput=$(command -v tput || echo "")
c_red=""; c_green=""; c_yellow=""; c_blue=""; c_magenta=""; c_cyan=""; c_reset=""
if [[ -n "$has_tput" ]]; then
    c_red=$(tput setaf 1)
    c_green=$(tput setaf 2)
    c_yellow=$(tput setaf 3)
    c_blue=$(tput setaf 4)
    c_magenta=$(tput setaf 5)
    c_cyan=$(tput setaf 6)
    c_reset=$(tput sgr0)
fi
if [[ ! -r "$hashes_file" ]]; then
    echo "${c_red}Archivo de hashes '$hashes_file' no existe o no es legible.${c_reset}" >&2
    exit 1
fi
if [[ ! -r "$dict_file" ]]; then
    echo "${c_red}Archivo diccionario '$dict_file' no existe o no es legible.${c_reset}" >&2
    exit 1
fi
total=0; cracked=0; notfound=0; unknown=0
declare -A summary_cracked
declare -A summary_notfound
declare -A summary_unknown
while IFS= read -r hash || [[ -n "$hash" ]]; do
    hash="${hash//[$'\n\r']}"
    [[ -z "$hash" || "$hash" =~ ^# ]] && continue
    ((total++))
    found=0
    if [[ "$hash" =~ ^[a-fA-F0-9]{32}$ ]]; then
        algo="md5"
    elif [[ "$hash" =~ ^[a-fA-F0-9]{40}$ ]]; then
        algo="sha1"
    elif [[ "$hash" =~ ^[a-fA-F0-9]{64}$ ]]; then
        algo="sha256"
    elif [[ "$hash" =~ ^[a-fA-F0-9]{128}$ ]]; then
        algo="sha512"
    elif [[ "$hash" =~ ^[A-F0-9]{32}$ ]]; then
        algo="ntlm"
    elif [[ "$hash" =~ ^\$2[aby]\$ ]]; then
        echo -e "${c_yellow}$hash : BCRYPT (usá hashcat/john)${c_reset}"
        summary_unknown["$hash"]="BCRYPT"
        ((unknown++))
        continue
    elif [[ "$hash" =~ ^\$6\$ ]]; then
        algo="crypt-sha512"
    elif [[ "$hash" =~ ^[a-fA-F0-9]{16}$ ]]; then
        algo="lm"
    elif [[ "$hash" =~ ^\*[A-F0-9]{40}$ ]]; then
        algo="mysql-sha1"
    elif [[ "$hash" =~ ^[a-fA-F0-9]{96}$ ]]; then
        algo="sha384"
    else
        echo -e "${c_magenta}$hash : UNKNOWN TYPE${c_reset}"
        summary_unknown["$hash"]="UNKNOWN"
        ((unknown++))
        continue
    fi
    while IFS= read -r word || [[ -n "$word" ]]; do
        [[ -z "$word" || "$word" =~ ^# ]] && continue
        if [[ "$algo" == "md5" ]]; then
            w_hash=$(printf "%s" "$word" | md5sum | awk '{print $1}')
        elif [[ "$algo" == "sha1" ]]; then
            w_hash=$(printf "%s" "$word" | sha1sum | awk '{print $1}')
        elif [[ "$algo" == "sha256" ]]; then
            w_hash=$(printf "%s" "$word" | sha256sum | awk '{print $1}')
        elif [[ "$algo" == "sha512" ]]; then
            w_hash=$(printf "%s" "$word" | sha512sum | awk '{print $1}')
        elif [[ "$algo" == "sha384" ]]; then
            w_hash=$(printf "%s" "$word" | openssl dgst -sha384 | awk '{print $2}')
        elif [[ "$algo" == "ntlm" ]]; then
            if command -v iconv &>/dev/null; then
                w_hash=$(printf "%s" "$word" | iconv -f UTF-8 -t UTF-16LE | openssl dgst -md4 | awk '{print $2}' | tr 'a-z' 'A-Z')
            else
                w_hash=""
            fi
        elif [[ "$algo" == "lm" ]]; then
            w_hash=""
        elif [[ "$algo" == "mysql-sha1" ]]; then
            w_hash=""
        elif [[ "$algo" == "crypt-sha512" ]]; then
            if command -v mkpasswd &>/dev/null; then
                salt="$(echo "$hash" | awk -F'$' '{print $3}')"
                w_hash=$(mkpasswd -m sha-512 "$word" "\$6\$${salt}\$")
            elif command -v python3 &>/dev/null; then
                salt="$(echo "$hash" | awk -F'$' '{print $3}')"
                w_hash=$(python3 -c "import crypt; print(crypt.crypt('$word', '\$6\$${salt}\$'))")
            else
                w_hash=""
            fi
        else
            w_hash=""
        fi
        if [[ "$w_hash" == "$hash" ]]; then
            echo -e "${c_green}$hash : $word ($algo)${c_reset}"
            summary_cracked["$hash"]="$word"
            ((cracked++))
            found=1
            break
        fi
    done <"$dict_file"
    if [[ $found -eq 0 ]]; then
        echo -e "${c_red}$hash : NOT FOUND${c_reset}"
        summary_notfound["$hash"]=1
        ((notfound++))
    fi
done <"$hashes_file"
echo
echo -e "${c_cyan}Resumen:${c_reset}"
echo -e "${c_green}Crackeados: $cracked${c_reset}"
echo -e "${c_red}No encontrados: $notfound${c_reset}"
echo -e "${c_magenta}Tipo desconocido: $unknown${c_reset}"
echo -e "${c_blue}Total: $total${c_reset}"
[[ $cracked -gt 0 ]] && { echo -e "${c_green}Hashes crackeados:${c_reset}"; for h in "${!summary_cracked[@]}"; do echo "$h : ${summary_cracked[$h]}"; done; }
[[ $notfound -gt 0 ]] && { echo -e "${c_red}Hashes no encontrados:${c_reset}"; for h in "${!summary_notfound[@]}"; do echo "$h"; done; }
[[ $unknown -gt 0 ]] && { echo -e "${c_magenta}Hashes tipo desconocido:${c_reset}"; for h in "${!summary_unknown[@]}"; do echo "$h : ${summary_unknown[$h]}"; done; }