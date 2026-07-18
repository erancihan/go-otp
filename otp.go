package otp

/**
Retrieved from: http://www.inanzzz.com/index.php/post/y5nu/creating-a-one-time-password-otp-library-for-two-factor-authentication-2fa-with-golang
*/

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"

	"rsc.io/qr"
)

func NewQR(uri string) ([]byte, error) {
	code, err := qr.Encode(uri, qr.Q)
	if err != nil {
		return nil, err
	}

	return code.PNG(), nil
}

const (
	// https://datatracker.ietf.org/doc/html/rfc3548#section-5
	base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	// length defines the OTP code in character length.
	OTPLength = 6
	// period defines the TTL of a TOTP code in seconds.
	OTPPeriod = 30
)

func NewSecret() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	for index, value := range bytes {
		bytes[index] = base32Alphabet[value%byte(len(base32Alphabet))]
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
}

// CreateURI builds the authentication URI which is used to create a QR code.
// If the counter is set to 0, the algorithm is assumed to be TOTP, otherwise
// HOTP.
// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
func (o *OTP) CreateURI() string {
	algorithm := "totp"
	counter := ""

	if o.Counter != 0 {
		algorithm = "hotp"
		counter = fmt.Sprintf("&counter=%d", o.Counter)
	}

	return fmt.Sprintf("otpauth://%s/%s:%s?secret=%s&issuer=%s%s", algorithm, o.Issuer, o.Account, o.Secret, o.Issuer, counter)
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
	if len(code) != OTPLength {
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
	curr := int(time.Now().UTC().Unix() / OTPPeriod)
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
		if val == code {
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
		if val == code {
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

	hash := hmac.New(sha1.New, sec)
	if err := binary.Write(hash, binary.BigEndian, int64(interval)); err != nil {
		return "", fmt.Errorf("binary write: %w", err)
	}
	sign := hash.Sum(nil)

	offset := sign[19] & 15
	trunc := binary.BigEndian.Uint32(sign[offset : offset+4])

	return fmt.Sprintf("%0*d", OTPLength, (trunc&0x7fffffff)%1000000), nil
}
