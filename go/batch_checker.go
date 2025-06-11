package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
)

var (
	cReset   = "\033[0m"
	cRed     = "\033[31m"
	cGreen   = "\033[32m"
	cYellow  = "\033[33m"
	cBlue    = "\033[34m"
	cMagenta = "\033[35m"
	cCyan    = "\033[36m"
)

func detectHashType(hash string) string {
	h := strings.ToLower(hash)
	switch {
	case len(h) == 32 && isHex(h):
		return "md5"
	case len(h) == 40 && isHex(h):
		return "sha1"
	case len(h) == 64 && isHex(h):
		return "sha256"
	case len(h) == 128 && isHex(h):
		return "sha512"
	case len(h) == 32 && !isHex(h):
		return "ntlm"
	case len(h) == 16 && isHex(h):
		return "lm"
	case len(h) == 96 && isHex(h):
		return "sha384"
	case strings.HasPrefix(h, "*") && len(h) == 41:
		return "mysql-sha1"
	case strings.HasPrefix(h, "$2a$") || strings.HasPrefix(h, "$2b$") || strings.HasPrefix(h, "$2y$"):
		return "bcrypt"
	case strings.HasPrefix(h, "$6$"):
		return "crypt-sha512"
	default:
		return ""
	}
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func crackHash(hashLine, hashType, dictFile string, ch chan<- string, counts *map[string]int, lock *sync.Mutex, cracked map[string]string, notfound map[string]bool, unknown map[string]string) {
	found := false
	f, err := os.Open(dictFile)
	if err != nil {
		ch <- fmt.Sprintf("%s%s : ERROR dict %v%s", cRed, hashLine, err, cReset)
		lock.Lock()
		(*counts)["unknown"]++
		unknown[hashLine] = "ERROR"
		lock.Unlock()
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		word := strings.TrimSpace(sc.Text())
		if word == "" || strings.HasPrefix(word, "#") {
			continue
		}
		var wHash string
		switch hashType {
		case "md5":
			h := md5.Sum([]byte(word))
			wHash = hex.EncodeToString(h[:])
		case "sha1":
			h := sha1.Sum([]byte(word))
			wHash = hex.EncodeToString(h[:])
		case "sha256":
			h := sha256.Sum256([]byte(word))
			wHash = hex.EncodeToString(h[:])
		case "sha384":
			h := sha512.Sum384([]byte(word))
			wHash = hex.EncodeToString(h[:])
		case "sha512":
			h := sha512.Sum512([]byte(word))
			wHash = hex.EncodeToString(h[:])
		case "ntlm":
			wHash = ""
		case "lm":
			wHash = ""
		case "mysql-sha1":
			wHash = ""
		case "crypt-sha512":
			wHash = ""
		}
		if wHash != "" && wHash == hashLine {
			ch <- fmt.Sprintf("%s%s : %s (%s)%s", cGreen, hashLine, word, hashType, cReset)
			lock.Lock()
			(*counts)["cracked"]++
			cracked[hashLine] = word
			lock.Unlock()
			found = true
			break
		}
	}
	if !found {
		ch <- fmt.Sprintf("%s%s : NOT FOUND%s", cRed, hashLine, cReset)
		lock.Lock()
		(*counts)["notfound"]++
		notfound[hashLine] = true
		lock.Unlock()
	}
}

func main() {
	filePtr := flag.String("file", "", "Hashes file")
	dictPtr := flag.String("dict", "", "Dictionary file")
	threads := flag.Int("threads", 8, "Threads")
	flag.Parse()
	if *filePtr == "" || *dictPtr == "" {
		fmt.Println("Faltan argumentos --file y/o --dict")
		os.Exit(1)
	}
	if _, err := os.Stat(*filePtr); err != nil {
		fmt.Printf("%sArchivo de hashes '%s' no existe%s\n", cRed, *filePtr, cReset)
		os.Exit(1)
	}
	if _, err := os.Stat(*dictPtr); err != nil {
		fmt.Printf("%sArchivo diccionario '%s' no existe%s\n", cRed, *dictPtr, cReset)
		os.Exit(1)
	}
	hashes := []string{}
	f, _ := os.Open(*filePtr)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hashes = append(hashes, line)
	}
	f.Close()
	ch := make(chan string, len(hashes))
	wg := sync.WaitGroup{}
	sem := make(chan struct{}, *threads)
	counts := map[string]int{"cracked": 0, "notfound": 0, "unknown": 0}
	cracked := make(map[string]string)
	notfound := make(map[string]bool)
	unknown := make(map[string]string)
	lock := sync.Mutex{}
	for _, hash := range hashes {
		hashType := detectHashType(hash)
		switch hashType {
		case "md5", "sha1", "sha256", "sha384", "sha512":
			wg.Add(1)
			sem <- struct{}{}
			go func(h, ht string) {
				defer wg.Done()
				crackHash(h, ht, *dictPtr, ch, &counts, &lock, cracked, notfound, unknown)
				<-sem
			}(hash, hashType)
		case "bcrypt":
			ch <- fmt.Sprintf("%s%s : BCRYPT (usá hashcat/john)%s", cYellow, hash, cReset)
			lock.Lock()
			counts["unknown"]++
			unknown[hash] = "BCRYPT"
			lock.Unlock()
		case "crypt-sha512":
			ch <- fmt.Sprintf("%s%s : CRYPT SHA512 (usá Bash/Python)%s", cYellow, hash, cReset)
			lock.Lock()
			counts["unknown"]++
			unknown[hash] = "CRYPT SHA512"
			lock.Unlock()
		case "ntlm":
			ch <- fmt.Sprintf("%s%s : NTLM (usá Python/hashcat)%s", cYellow, hash, cReset)
			lock.Lock()
			counts["unknown"]++
			unknown[hash] = "NTLM"
			lock.Unlock()
		case "lm":
			ch <- fmt.Sprintf("%s%s : LM (usá hashcat/john)%s", cYellow, hash, cReset)
			lock.Lock()
			counts["unknown"]++
			unknown[hash] = "LM"
			lock.Unlock()
		case "mysql-sha1":
			ch <- fmt.Sprintf("%s%s : MySQL-sha1 (usá hashcat)%s", cYellow, hash, cReset)
			lock.Lock()
			counts["unknown"]++
			unknown[hash] = "MYSQL-SHA1"
			lock.Unlock()
		default:
			ch <- fmt.Sprintf("%s%s : UNKNOWN TYPE%s", cMagenta, hash, cReset)
			lock.Lock()
			counts["unknown"]++
			unknown[hash] = "UNKNOWN"
			lock.Unlock()
		}
	}
	wg.Wait()
	close(ch)
	for res := range ch {
		fmt.Println(res)
	}
	fmt.Println()
	fmt.Printf("%sResumen:%s\n", cCyan, cReset)
	fmt.Printf("%sCrackeados: %d%s\n", cGreen, counts["cracked"], cReset)
	fmt.Printf("%sNo encontrados: %d%s\n", cRed, counts["notfound"], cReset)
	fmt.Printf("%sTipo desconocido: %d%s\n", cMagenta, counts["unknown"], cReset)
	fmt.Printf("%sTotal: %d%s\n", cBlue, len(hashes), cReset)
}
