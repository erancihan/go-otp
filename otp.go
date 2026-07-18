// Package otp implements one-time passwords following the TOTP (RFC 6238)
// and HOTP (RFC 4226) standards, together with helpers for generating shared
// secrets, provisioning URIs, and QR codes for authenticator apps.
//
// The default configuration matches what authenticator apps expect: 6-digit
// codes, a 30-second TOTP period, and HMAC-SHA1. These can be overridden per
// OTP value via the Digits, Period, and Algorithm fields.
//
// Original implementation adapted from:
// http://www.inanzzz.com/index.php/post/y5nu/creating-a-one-time-password-otp-library-for-two-factor-authentication-2fa-with-golang
package otp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"net/url"
	"strconv"
	"time"

	"rsc.io/qr"
)

// NewQR encodes the given otpauth URI as a PNG-formatted QR code. The URI is
// typically produced by (*OTP).CreateURI.
func NewQR(uri string) ([]byte, error) {
	code, err := qr.Encode(uri, qr.Q)
	if err != nil {
		return nil, err
	}

	return code.PNG(), nil
}

const (
	// OTPLength is the default number of digits in a generated code.
	OTPLength = 6
	// OTPPeriod is the default TTL of a TOTP code in seconds.
	OTPPeriod = 30
)

// Algorithm identifies the HMAC hash function used to derive codes. The zero
// value is treated as AlgorithmSHA1, which is the default mandated by RFC 4226
// and understood by virtually all authenticator apps.
type Algorithm string

const (
	AlgorithmSHA1   Algorithm = "SHA1"
	AlgorithmSHA256 Algorithm = "SHA256"
	AlgorithmSHA512 Algorithm = "SHA512"
)

// hash returns the hash constructor for the algorithm along with its
// canonical name for use in an otpauth URI. Unknown or empty values fall back
// to SHA1.
func (a Algorithm) hash() (func() hash.Hash, string) {
	switch a {
	case AlgorithmSHA256:
		return sha256.New, string(AlgorithmSHA256)
	case AlgorithmSHA512:
		return sha512.New, string(AlgorithmSHA512)
	default:
		return sha1.New, string(AlgorithmSHA1)
	}
}

// NewSecret generates a cryptographically secure, Base32-encoded shared
// secret suitable for OTP provisioning. It reads 16 random bytes (128 bits
// of entropy) from crypto/rand and encodes them without padding, yielding a
// 26-character string.
func NewSecret() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes), nil
}

type OTP struct {
	// Issuer represents the service provider. It is you! e.g. your service,
	// your application, your organisation so on.
	Issuer string
	// Account represents the service user. It is the user! e.g. username, email
	// address so on.
	Account string
	// Secret is an arbitrary key value encoded in Base32 and belongs to the
	// service user.
	Secret string
	// Window is used for time (TOTP) and counter (HOTP) synchronization. Given
	// that the possible time and counter drifts between client and server, this
	// parameter helps overcome such issue. TOTP uses backward and forward time
	// window whereas HOTP uses look-ahead counter window that depends on the
	// Counter parameter.
	// Resynchronisation is an official recommended practise, however the
	// lower the better.
	// 0 = not recommended as synchronization is disabled
	//   TOTP: current time
	//   HOTP: current counter
	// 1 = recommended option
	//   TOTP: previous - current - next
	//   HOTP: current counter - next counter
	// 2 = being overcautious
	//   TOTP: previous,previous - current - next,next
	//   HOTP: current counter - next counter - next counter
	// * = Higher numbers may cause denial-of-service attacks.
	// https://datatracker.ietf.org/doc/html/rfc6238#page-7
	// https://datatracker.ietf.org/doc/html/rfc4226#page-11
	Window int
	// Counter is required for HOTP only and used for provisioning the code. Set
	// it to 0 if you with to use TOTP. Start from 1 for HOTP then fetch and use
	// the one in the persistent storage. The server counter is incremented only
	// after a successful code verification, however the counter on the code is
	// incremented every time a new code is requested by the user which causes
	// counters being out of sync. For that reason, time-synchronization should
	// be enabled.
	// https://datatracker.ietf.org/doc/html/rfc4226#page-11
	Counter int
	// Digits is the number of digits in a generated code. It defaults to
	// OTPLength (6) when zero. Authenticator apps typically support 6 or 8.
	Digits int
	// Period is the TOTP time step in seconds. It defaults to OTPPeriod (30)
	// when zero and is ignored for HOTP.
	Period int
	// Algorithm selects the HMAC hash function. The zero value defaults to
	// AlgorithmSHA1.
	Algorithm Algorithm
}

// digits returns the effective number of code digits, applying the default
// when the field is unset.
func (o *OTP) digits() int {
	if o.Digits > 0 {
		return o.Digits
	}
	return OTPLength
}

// period returns the effective TOTP time step in seconds, applying the
// default when the field is unset.
func (o *OTP) period() int {
	if o.Period > 0 {
		return o.Period
	}
	return OTPPeriod
}

// CreateURI builds the authentication URI which is used to create a QR code.
// If the counter is set to 0, the algorithm is assumed to be TOTP, otherwise
// HOTP.
// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
func (o *OTP) CreateURI() string {
	otpType := "totp"

	// The label is "Issuer:Account"; each component is escaped independently
	// so that the ":" separator is preserved.
	label := url.PathEscape(o.Issuer) + ":" + url.PathEscape(o.Account)

	_, algName := o.Algorithm.hash()

	query := url.Values{}
	query.Set("secret", o.Secret)
	query.Set("issuer", o.Issuer)
	query.Set("algorithm", algName)
	query.Set("digits", strconv.Itoa(o.digits()))

	if o.Counter != 0 {
		otpType = "hotp"
		query.Set("counter", strconv.Itoa(o.Counter))
	} else {
		query.Set("period", strconv.Itoa(o.period()))
	}

	return fmt.Sprintf("otpauth://%s/%s?%s", otpType, label, query.Encode())
}

// CreateHOTPCode creates a new HOTP with a specific counter. This method is
// ideal if you are planning to send manually created code via email, SMS etc.
// The user should not be present a QR code for this option otherwise there is
// a high posibility that the client and server counters will be out of sync,
// unless the user will be forced to rescan a newly generaed QR with up to date
// counter value.
func (o *OTP) CreateHOTPCode(counter int) (string, error) {
	val, err := o.createCode(counter)
	if err != nil {
		return "", fmt.Errorf("create code: %w", err)
	}

	o.Counter = counter
	return val, nil
}

// VerifyCode talks to an algorithm specific validator to verify the integrity
// of the code. If the counter is set to 0, the algorithm is assumed to be TOTP,
// otherwise HOTP.
func (o *OTP) VerifyCode(code string) (bool, error) {
	if len(code) != o.digits() {
		return false, fmt.Errorf("invalid length")
	}

	if o.Counter != 0 {
		ok, err := o.verifyHOTP(code)
		if err != nil {
			return false, fmt.Errorf("verify HOTP: %w", err)
		}
		if !ok {
			return false, nil
		}
		return true, nil
	}

	ok, err := o.verifyTOTP(code)
	if err != nil {
		return false, fmt.Errorf("verify TOTP: %w", err)
	}
	if !ok {
		return false, nil
	}

	return true, nil
}

// Depending on the given windows size, we handle clock resynchronisation. If
// the window size is set to 0, resynchronisation is disabled and we just use
// the current time. Otherwise, backward and forward window is taken into
// account as well.
func (o *OTP) verifyTOTP(code string) (bool, error) {
	curr := int(time.Now().UTC().Unix() / int64(o.period()))
	back := curr
	forw := curr
	if o.Window != 0 {
		back -= o.Window
		forw += o.Window
	}

	for i := back; i <= forw; i++ {
		val, err := o.createCode(i)
		if err != nil {
			return false, fmt.Errorf("create code: %w", err)
		}
		if subtle.ConstantTimeCompare([]byte(val), []byte(code)) == 1 {
			return true, nil
		}
	}

	return false, nil
}

// Depending on the given windows size, we handle counter resynchronisation. If
// the window size is set to 0, resynchronisation is disabled and we just use
// the current counter. Otherwise, look-ahead counter window is used. When the
// look-ahead window is used, we calculate the next codes and determine if there
// is a match by utilising counter resynchronisation.
func (o *OTP) verifyHOTP(code string) (bool, error) {
	size := 0
	if o.Window != 0 {
		size = o.Window
	}

	for i := 0; i <= size; i++ {
		val, err := o.createCode(o.Counter + i)
		if err != nil {
			return false, fmt.Errorf("create code: %w", err)
		}
		if subtle.ConstantTimeCompare([]byte(val), []byte(code)) == 1 {
			o.Counter += i + 1
			return true, nil
		}
	}

	o.Counter++
	return false, nil
}

// createCode creates a new OTP code based on either a time or counter interval.
// The time is used for TOTP and the counter is used for HOTP algorithm.
func (o *OTP) createCode(interval int) (string, error) {
	sec, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(o.Secret)
	if err != nil {
		return "", fmt.Errorf("decode string: %w", err)
	}

	hashFn, _ := o.Algorithm.hash()
	mac := hmac.New(hashFn, sec)
	if err := binary.Write(mac, binary.BigEndian, int64(interval)); err != nil {
		return "", fmt.Errorf("binary write: %w", err)
	}
	sign := mac.Sum(nil)

	// RFC 4226 dynamic truncation: the low nibble of the last byte selects a
	// 4-byte offset. Using len(sign)-1 keeps this correct for SHA1, SHA256,
	// and SHA512, whose digests have different lengths.
	offset := sign[len(sign)-1] & 15
	trunc := binary.BigEndian.Uint32(sign[offset : offset+4])

	digits := o.digits()
	mod := uint32(math.Pow10(digits))
	return fmt.Sprintf("%0*d", digits, (trunc&0x7fffffff)%mod), nil
}
