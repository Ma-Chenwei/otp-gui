package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

type OTPConfig struct {
	Secret    string
	Algorithm string
	Digits    int
	Period    int
}

func parseOTPAuth(raw string) (*OTPConfig, error) {
	raw = strings.TrimSpace(raw)

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URI")
	}

	if strings.ToLower(u.Scheme) != "otpauth" {
		return nil, fmt.Errorf("not an otpauth URI")
	}

	if strings.ToLower(u.Host) != "totp" {
		return nil, fmt.Errorf("only TOTP is supported")
	}

	q := u.Query()

	secret := strings.TrimSpace(q.Get("secret"))
	if secret == "" {
		return nil, fmt.Errorf("missing secret")
	}

	algorithm := strings.ToUpper(q.Get("algorithm"))
	if algorithm == "" {
		algorithm = "SHA1"
	}

	switch algorithm {
	case "SHA1", "SHA256", "SHA512":
	default:
		return nil, fmt.Errorf("unsupported algorithm")
	}

	digits := 6
	if v := q.Get("digits"); v != "" {
		digits, err = strconv.Atoi(v)
		if err != nil || (digits != 6 && digits != 8) {
			return nil, fmt.Errorf("invalid digits")
		}
	}

	period := 30
	if v := q.Get("period"); v != "" {
		period, err = strconv.Atoi(v)
		if err != nil || period <= 0 {
			return nil, fmt.Errorf("invalid period")
		}
	}

	return &OTPConfig{
		Secret:    secret,
		Algorithm: algorithm,
		Digits:    digits,
		Period:    period,
	}, nil
}

func decodeSecret(secret string) ([]byte, error) {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	secret = strings.ReplaceAll(secret, " ", "")
	secret = strings.TrimRight(secret, "=")

	// otpauth 通常使用 Base32，且没有 padding。
	data, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("invalid secret")
	}

	return data, nil
}

func getHashFunc(name string) func() hash.Hash {
	switch name {
	case "SHA256":
		return sha256.New
	case "SHA512":
		return sha512.New
	default:
		return sha1.New
	}
}

func generateTOTP(cfg *OTPConfig, now time.Time) (string, error) {
	secret, err := decodeSecret(cfg.Secret)
	if err != nil {
		return "", err
	}

	counter := uint64(now.Unix() / int64(cfg.Period))

	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)

	mac := hmac.New(getHashFunc(cfg.Algorithm), secret)
	_, _ = mac.Write(counterBytes[:])

	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f

	binCode := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)

	var mod uint32

	if cfg.Digits == 8 {
		mod = 100000000
	} else {
		mod = 1000000
	}

	code := binCode % mod

	if cfg.Digits == 8 {
		return fmt.Sprintf("%08d", code), nil
	}

	return fmt.Sprintf("%06d", code), nil
}

func main() {
	a := app.New()
	w := a.NewWindow("OTP")

	w.Resize(fyne.NewSize(500, 260))
	w.CenterOnScreen()

	input := widget.NewMultiLineEntry()
	input.SetPlaceHolder("otpauth://totp/...")
	input.Wrapping = fyne.TextWrapOff

	code := widget.NewLabel("------")
	code.Alignment = fyne.TextAlignCenter
	code.TextStyle = fyne.TextStyle{
		Bold: true,
	}

	// 大字体
	code.Resize(fyne.NewSize(400, 80))

	status := widget.NewLabel("")

	var cfg *OTPConfig

	update := func() {
		if cfg == nil {
			code.SetText("------")
			return
		}

		value, err := generateTOTP(cfg, time.Now())
		if err != nil {
			code.SetText("------")
			status.SetText(err.Error())
			return
		}

		code.SetText(value)
		status.SetText("")
	}

	parse := func() {
		value := strings.TrimSpace(input.Text)

		if value == "" {
			cfg = nil
			code.SetText("------")
			status.SetText("")
			return
		}

		newCfg, err := parseOTPAuth(value)
		if err != nil {
			cfg = nil
			code.SetText("------")
			status.SetText(err.Error())
			return
		}

		cfg = newCfg
		update()
	}

	input.OnChanged = func(_ string) {
		parse()
	}

	content := container.NewVBox(
		input,
		widget.NewSeparator(),
		code,
		status,
	)

	w.SetContent(container.NewPadded(content))

	// 每秒刷新一次。
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for range ticker.C {
			if cfg != nil {
				fyne.Do(update)
			}
		}
	}()

	w.ShowAndRun()
}