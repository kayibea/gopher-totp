package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.design/x/clipboard"
)

const (
	step   = 30
	digits = 6
)

const totpMod uint32 = 1_000_000

func totp(secret []byte, mod uint32, t time.Time) uint32 {
	counter := uint64(t.Unix() / step)

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)

	return bin % mod
}

func printUsage() {
	fmt.Printf("Usage: %s\n", os.Args[0])
	fmt.Println("Reads the TOTP secret from stdin and prints the code every 30s.")
	fmt.Println("The current code is automatically copied to the clipboard while the program is running.")
	fmt.Println("Example:")
	fmt.Printf("  echo 'JBSWY3DPEHPK3PXP' | %s\n", os.Args[0])
}

func main() {
	if len(os.Args) > 1 {
		printUsage()
		os.Exit(1)
	}

	in := bufio.NewReader(os.Stdin)
	secretStr, err := in.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read secret from stdin: %v\n", err)
		os.Exit(1)
	}

	secretStr = strings.ReplaceAll(secretStr, " ", "")
	secretStr = strings.ToUpper(secretStr)
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid base32 secret")
		os.Exit(1)
	}

	var clipboardOk bool = true
	var lastCounter uint64 = ^uint64(0)
	var codeStr string
	var currentCode uint32

	err = clipboard.Init()
	if err != nil {
		clipboardOk = false
		fmt.Printf("Warning: clipboard unavailable (%v)\n", err)
	}

	fmt.Println("Ctrl+C to exit.")
	for {
		now := time.Now()
		counter := uint64(now.Unix() / step)

		if counter != lastCounter {
			lastCounter = counter
			currentCode = totp(secret, totpMod, now)
			codeStr = fmt.Sprintf("%0*d", digits, currentCode)

			if clipboardOk && codeStr != "" {
				clipboard.Write(
					clipboard.FmtText,
					[]byte(codeStr),
				)
			}
		}

		remaining := step - int(now.Unix()%step)
		readable := fmt.Sprintf("%s-%s", codeStr[:3], codeStr[3:])

		fmt.Printf("\rExpires in: %2ds | Code: %s", remaining, readable)
		os.Stdout.Sync()

		time.Sleep(1 * time.Second)
	}
}
