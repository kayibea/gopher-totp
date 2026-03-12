package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	"hash"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.design/x/clipboard"
)

type algoType string

const (
	algoSHA1   algoType = "sha1"
	algoSHA256 algoType = "sha256"
	algoSHA512 algoType = "sha512"
)

type uriConfig struct {
	secret string
	digits int
	period int
	algo   string
}

func parseOTPAuthURI(s string) (*uriConfig, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}

	if u.Scheme != "otpauth" {
		return nil, fmt.Errorf("not otpauth uri")
	}

	q := u.Query()

	cfg := &uriConfig{
		secret: q.Get("secret"),
	}

	if v := q.Get("digits"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.digits = n
		}
	}

	if v := q.Get("period"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.period = n
		}
	}

	if v := q.Get("algorithm"); v != "" {
		cfg.algo = strings.ToLower(v)
	}

	return cfg, nil
}

func getHash(algo algoType) func() hash.Hash {
	switch algo {
	case algoSHA1:
		return sha1.New
	case algoSHA256:
		return sha256.New
	case algoSHA512:
		return sha512.New
	default:
		panic("invalid algorithm")
	}
}

func generateHOTP(secret []byte, counter uint64, algo algoType) uint32 {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(getHash(algo), secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f

	bin :=
		(uint32(sum[offset])&0x7f)<<24 |
			(uint32(sum[offset+1])&0xff)<<16 |
			(uint32(sum[offset+2])&0xff)<<8 |
			(uint32(sum[offset+3]) & 0xff)

	return bin
}

func formatCode(code string, pretty bool) string {
	if !pretty {
		return code
	}

	mid := len(code) / 2
	return code[:mid] + "-" + code[mid:]
}

func readInput() (string, error) {
	reader := bufio.NewReader(os.Stdin)

	input, err := reader.ReadString('\n')
	if err != nil && len(input) == 0 {
		return "", err
	}

	return strings.TrimSpace(input), nil
}

func runTOTPGenerator(secret []byte, digits, period int, algo algoType, clip, pretty bool) {
	var clipboardOK bool

	if clip {
		if err := clipboard.Init(); err != nil {
			fmt.Fprintf(os.Stderr, "Clipboard unavailable: %v\n", err)
		} else {
			clipboardOK = true
		}
	}

	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}

	var lastStep int64 = -1
	var displayCode string

	for {
		now := time.Now()
		step := now.Unix() / int64(period)
		remaining := period - int(now.Unix()%int64(period))

		if step != lastStep {
			bin := generateHOTP(secret, uint64(step), algo)
			otp := bin % mod

			code := fmt.Sprintf("%0*d", digits, otp)

			if clip && clipboardOK {
				clipboard.Write(clipboard.FmtText, []byte(code))
			}

			displayCode = formatCode(code, pretty)
			lastStep = step
		}

		fmt.Printf("\rExpires in: %2ds | Code: %s", remaining, displayCode)
		time.Sleep(time.Second)
	}
}

func setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println()
		os.Exit(0)
	}()
}

func main() {
	digits := flag.Int("digits", 6, "")
	flag.IntVar(digits, "d", 6, "")

	period := flag.Int("period", 30, "")
	flag.IntVar(period, "p", 30, "")

	algo := flag.String("algo", "sha1", "")
	flag.StringVar(algo, "a", "sha1", "")

	clip := flag.Bool("clip", false, "")
	flag.BoolVar(clip, "c", false, "")

	pretty := flag.Bool("pretty", false, "")

	help := flag.Bool("help", false, "")
	flag.BoolVar(help, "h", false, "")

	flag.Parse()

	if *help {
		fmt.Printf("Usage: echo \"BASE32_SECRET\" | %s [options]\n", os.Args[0])
		fmt.Println()
		fmt.Println("Options:")
		fmt.Println("  -d, --digits NUM    Length of code (default: 6)")
		fmt.Println("  -p, --period SEC    Time step in seconds (default: 30)")
		fmt.Println("  -a, --algo TYPE     sha1, sha256, sha512 (default: sha1)")
		fmt.Println("  -c, --clip          Copy code to clipboard")
		fmt.Println("      --pretty        Format output (e.g. 123-456)")
		fmt.Println("  -h, --help          Show help")
		return
	}

	setupSignalHandler()

	flagSet := map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		flagSet[f.Name] = true
	})

	if stat, _ := os.Stdin.Stat(); (stat.Mode() & os.ModeCharDevice) != 0 {
		fmt.Fprintln(os.Stderr, "Enter Base32 secret or otpauth URI (press Enter to generate):")
	}

	input, err := readInput()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to read secret")
		os.Exit(1)
	}

	if input == "" {
		fmt.Fprintln(os.Stderr, "Error: No secret or URI provided")
		os.Exit(1)
	}

	var uri *uriConfig

	if strings.HasPrefix(input, "otpauth://") {
		u, err := parseOTPAuthURI(input)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Invalid otpauth URI")
			os.Exit(1)
		}

		if u.secret == "" {
			fmt.Fprintln(os.Stderr, "URI missing secret")
			os.Exit(1)
		}

		uri = u
		input = u.secret
	}

	if uri != nil {
		if uri.digits != 0 && !flagSet["digits"] && !flagSet["d"] {
			*digits = uri.digits
		}

		if uri.period != 0 && !flagSet["period"] && !flagSet["p"] {
			*period = uri.period
		}

		if uri.algo != "" && !flagSet["algo"] && !flagSet["a"] {
			*algo = uri.algo
		}
	}

	switch strings.ToLower(*algo) {
	case "sha1", "sha256", "sha512":
	default:
		fmt.Fprintf(os.Stderr, "Invalid algo '%s'\n", *algo)
		os.Exit(1)
	}

	clean := strings.ToUpper(strings.ReplaceAll(input, " ", ""))
	clean = strings.TrimRight(clean, "=")

	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(clean)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Invalid Base32 secret")
		os.Exit(1)
	}

	runTOTPGenerator(secret, *digits, *period, algoType(strings.ToLower(*algo)), *clip, *pretty)
}
