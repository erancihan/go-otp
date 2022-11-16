package otp

import (
	"encoding/base32"
	"fmt"
	"testing"
	"time"
)

func Test_NewQR(t *testing.T) {
	qr, err := NewQR("otpauth://type/label?parameters")
	if err != nil {
		t.Error("an error was not \nEXPECTED:")
	}
	if len(qr) != 1445 {
		t.Error("\nEXPECTED: 1445 byte slice\nACTUAL  :", len(qr))
	}
}

func Test_NewSecret(t *testing.T) {
	// Encoded secret
	encSec, err := NewSecret()
	if err != nil {
		t.Error("an error was not \nEXPECTED: while encoding\nACTUAL  :", err.Error())
	}
	if len(encSec) != 26 {
		t.Error("\nEXPECTED: 26 characters long secret\nACTUAL  :", len(encSec))
	}
	if encSec[:26] == "=" {
		t.Error("did not expect padding")
	}

	// Decodeded secret
	decSec, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encSec)
	if err != nil {
		t.Error("an error was not \nEXPECTED: while decoding\nACTUAL  :", err.Error())
	}
	if len(decSec) != 16 {
		t.Error("\nEXPECTED: 16 byte slice\nACTUAL  :", len(decSec))
	}
}

func Test_OTP_CreateURI(t *testing.T) {
	twoFA := &OTP{
		Issuer:  "issuer",
		Account: "account",
		Secret:  "secret",
		Window:  0,
		Counter: 0,
	}

	t.Run("totp uri", func(t *testing.T) {
		uri := twoFA.CreateURI()
		if uri != "otpauth://totp/issuer:account?secret=secret&issuer=issuer" {
			t.Error("\nEXPECTED: otpauth://totp/issuer:account?secret=secret&issuer=issuer\nACTUAL  :", uri)
		}
	})

	t.Run("hotp uri", func(t *testing.T) {
		twoFA.Counter = 1
		uri := twoFA.CreateURI()
		if uri != "otpauth://hotp/issuer:account?secret=secret&issuer=issuer&counter=1" {
			t.Error("\nEXPECTED: otpauth://hotp/issuer:account?secret=secret&issuer=issuer&counter=1\nACTUAL  :", uri)
		}
	})
}

func Test_OTP_CreateHOTPCode(t *testing.T) {
	twoFA := &OTP{
		Issuer:  "issuer",
		Account: "account",
		Window:  0,
		Counter: 1,
	}

	t.Run("error if secret is illegal base32 data", func(t *testing.T) {
		twoFA.Secret = "secret"
		_, err := twoFA.CreateHOTPCode(2)
		if err == nil {
			t.Error("\nEXPECTED: an error\nACTUAL  : nil")
		}
		if err.Error() != "create code: decode string: illegal base32 data at input byte 0" {
			t.Error("\nEXPECTED: create code: decode string: illegal base32 data at input byte 0\nACTUAL  :", err.Error())
		}
		if twoFA.Counter != 1 {
			t.Error("counter should have been 1\nACTUAL  :", twoFA.Counter)
		}
	})

	t.Run("successful code creation and counter increase", func(t *testing.T) {
		twoFA.Secret = "GNFE2UCWJRCEOMZSLBHUMVCWKM"
		code, err := twoFA.CreateHOTPCode(2)
		if err != nil {
			t.Error("an error was not \nEXPECTED:\nACTUAL  :", err.Error())
		}
		if code != "501363" {
			t.Error("\nEXPECTED: 501363\nACTUAL  :", code)
		}
		if twoFA.Counter != 2 {
			t.Error("counter should have been 2\nACTUAL  :", twoFA.Counter)
		}
	})
}

func Test_OTP_VerifyCode(t *testing.T) {
	t.Run("error while using invalid code with length", func(t *testing.T) {
		twoFA := &OTP{}

		ok, err := twoFA.VerifyCode("00000") // Not equal to 6
		if err == nil {
			t.Error("\nEXPECTED: an error\nACTUAL  : nil")
		}
		if err.Error() != "invalid length" {
			t.Error("\nEXPECTED: invalid length\nACTUAL  :", err.Error())
		}
		if ok {
			t.Error("\nEXPECTED: false\nACTUAL  : true")
		}
	})

	t.Run("failed verification for hotp code with invalid secret", func(t *testing.T) {
		twoFA := &OTP{
			Secret:  "secret",
			Counter: 1,
		}
		ok, err := twoFA.VerifyCode("000000") // Random code
		if err == nil {
			t.Error("\nEXPECTED: an error\nACTUAL  : nil")
		}
		if err.Error() != "verify HOTP: create code: decode string: illegal base32 data at input byte 0" {
			t.Error("\nEXPECTED: verify HOTP: create code: decode string: illegal base32 data at input byte 0\nACTUAL  :", err.Error())
		}
		if ok {
			t.Error("\nEXPECTED: false\nACTUAL  : true")
		}
	})

	t.Run("failed verification for hotp code", func(t *testing.T) {
		twoFA := &OTP{
			Secret:  "GNFE2UCWJRCEOMZSLBHUMVCWKM",
			Counter: 1,
		}
		ok, err := twoFA.VerifyCode("000000") // Random code
		if err != nil {
			t.Error("an error was not \nEXPECTED:\nACTUAL  :", err.Error())
		}
		if ok {
			t.Error("\nEXPECTED: false\nACTUAL  : true")
		}
	})

	t.Run("successful verification for valid hotp code", func(t *testing.T) {
		twoFA := &OTP{
			Secret:  "GNFE2UCWJRCEOMZSLBHUMVCWKM",
			Counter: 1,
		}
		ok, err := twoFA.VerifyCode("204727") // Code for current counter
		if err != nil {
			t.Error("an error was not \nEXPECTED:\nACTUAL  :", err.Error())
		}
		if !ok {
			t.Error("\nEXPECTED: true\nACTUAL  : false")
		}
	})

	t.Run("failed verification for totp code with invalid secret", func(t *testing.T) {
		twoFA := &OTP{Secret: "secret"}
		ok, err := twoFA.VerifyCode("000000") // Random code
		if err == nil {
			t.Error("\nEXPECTED: an error\nACTUAL  : nil")
		}
		if err.Error() != "verify TOTP: create code: decode string: illegal base32 data at input byte 0" {
			t.Error("\nEXPECTED: verify TOTP: create code: decode string: illegal base32 data at input byte 0\nACTUAL  :", err.Error())
		}
		if ok {
			t.Error("\nEXPECTED: false\nACTUAL  : true")
		}
	})

	t.Run("failed verification for totp code", func(t *testing.T) {
		twoFA := &OTP{Secret: "GNFE2UCWJRCEOMZSLBHUMVCWKM"}
		ok, err := twoFA.VerifyCode("000000") // Random code
		if err != nil {
			t.Error("an error was not \nEXPECTED:\nACTUAL  :", err.Error())
		}
		if ok {
			t.Error("\nEXPECTED: false\nACTUAL  : true")
		}
	})

	t.Run("successful verification for valid totp code", func(t *testing.T) {
		twoFA := &OTP{Secret: "GNFE2UCWJRCEOMZSLBHUMVCWKM"}

		code, err := twoFA.createCode(int(time.Now().UTC().Unix() / OTPPeriod)) // Code from current time
		if err != nil {
			t.Error("an error was not \nEXPECTED:\nACTUAL  :", err.Error())
		}

		ok, err := twoFA.VerifyCode(code)
		if err != nil {
			t.Error("an error was not \nEXPECTED:\nACTUAL  :", err.Error())
		}
		if !ok {
			t.Error("\nEXPECTED: true\nACTUAL  : false")
		}
	})
}

func Test_OTP_verifyTOTP(t *testing.T) {
	t.Run("error while decoding illegal secret", func(t *testing.T) {
		twoFA := &OTP{Secret: "secret"}
		ok, err := twoFA.verifyTOTP("000000") // Random code
		if err == nil {
			t.Error("\nEXPECTED: an error\nACTUAL  : nil")
		}
		if err.Error() != "create code: decode string: illegal base32 data at input byte 0" {
			t.Error("\nEXPECTED: create code: decode string: illegal base32 data at input byte 0\nACTUAL  :", err.Error())
		}
		if ok {
			t.Error("\nEXPECTED: false\nACTUAL  : true")
		}
	})

	t.Run("failed verification for invalid code with resynchronisation disabled", func(t *testing.T) {
		twoFA := &OTP{
			Secret: "GNFE2UCWJRCEOMZSLBHUMVCWKM",
			Window: 0, // resynchronisation disabled
		}
		ok, err := twoFA.verifyTOTP("000000") // Random code
		if err != nil {
			t.Error("an error was not \nEXPECTED:\nACTUAL  :", err.Error())
		}
		if ok {
			t.Error("\nEXPECTED: false\nACTUAL  : true")
		}
	})

	t.Run("failed verification for invalid code with resynchronisation enabled", func(t *testing.T) {
		twoFA := &OTP{
			Secret: "GNFE2UCWJRCEOMZSLBHUMVCWKM",
			Window: 1, // resynchronisation enabled
		}
		ok, err := twoFA.verifyTOTP("000000") // Random code
		if err != nil {
			t.Error("an error was not \nEXPECTED:\nACTUAL  :", err.Error())
		}
		if ok {
			t.Error("\nEXPECTED: false\nACTUAL  : true")
		}
	})

	t.Run("successful verification with resynchronisation disabled and without time drift", func(t *testing.T) {
		twoFA := &OTP{
			Secret: "GNFE2UCWJRCEOMZSLBHUMVCWKM",
			Window: 0, // resynchronisation disabled
		}

		code, err := twoFA.createCode(int(time.Now().UTC().Unix() / OTPPeriod)) // Code from current window (no time drift)
		if err != nil {
			t.Error("an error was not \nEXPECTED:\nACTUAL  :", err.Error())
		}

		ok, err := twoFA.verifyTOTP(code)
		if err != nil {
			t.Error("an error was not \nEXPECTED:\nACTUAL  :", err.Error())
		}
		if !ok {
			t.Error("\nEXPECTED: true\nACTUAL  : false")
		}
	})

	t.Run("successful verification with resynchronisation enabled and with time drift of previous window", func(t *testing.T) {
		twoFA := &OTP{
			Secret: "GNFE2UCWJRCEOMZSLBHUMVCWKM",
			Window: 1, // resynchronisation enabled
		}

		code, err := twoFA.createCode(int(time.Now().UTC().Unix()/OTPPeriod) - 1) // Code from previous window (time drift)
		if err != nil {
			t.Error("an error was not \nEXPECTED:\nACTUAL  :", err.Error())
		}

		ok, err := twoFA.verifyTOTP(code)
		if err != nil {
			t.Error("an error was not \nEXPECTED:\nACTUAL  :", err.Error())
		}
		if !ok {
			t.Error("\nEXPECTED: true\nACTUAL  : false")
		}
	})

	t.Run("failed verification with resynchronisation disabled and with time drift of previous window", func(t *testing.T) {
		twoFA := &OTP{
			Secret: "GNFE2UCWJRCEOMZSLBHUMVCWKM",
			Window: 0, // resynchronisation disabled
		}

		code, err := twoFA.createCode(int(time.Now().UTC().Unix()/OTPPeriod) - 1) // Code from previous window (time drift)
		if err != nil {
			t.Error("an error was not \nEXPECTED:\nACTUAL  :", err.Error())
		}

		ok, err := twoFA.verifyTOTP(code)
		if err != nil {
			t.Error("an error was not \nEXPECTED:\nACTUAL  :", err.Error())
		}
		if ok {
			t.Error("\nEXPECTED: false\nACTUAL  : true")
		}
	})

	t.Run("successful verification with resynchronisation enabled and with time drift of next window", func(t *testing.T) {
		twoFA := &OTP{
			Secret: "GNFE2UCWJRCEOMZSLBHUMVCWKM",
			Window: 1, // resynchronisation enabled
		}

		code, err := twoFA.createCode(int(time.Now().UTC().Unix()/OTPPeriod) + 1) // Code from next window (time drift)
		if err != nil {
			t.Error("an error was not \nEXPECTED:\nACTUAL  :", err.Error())
		}

		ok, err := twoFA.verifyTOTP(code)
		if err != nil {
			t.Error("an error was not \nEXPECTED:\nACTUAL  :", err.Error())
		}
		if !ok {
			t.Error("\nEXPECTED: true\nACTUAL  : false")
		}
	})

	t.Run("failed verification with resynchronisation disabled and with time drift of next window", func(t *testing.T) {
		twoFA := &OTP{
			Secret: "GNFE2UCWJRCEOMZSLBHUMVCWKM",
			Window: 0, // resynchronisation disabled
		}

		code, err := twoFA.createCode(int(time.Now().UTC().Unix()/OTPPeriod) + 1) // Code from next window (time drift)
		if err != nil {
			t.Error("an error was not \nEXPECTED:\nACTUAL  :", err.Error())
		}

		ok, err := twoFA.verifyTOTP(code)
		if err != nil {
			t.Error("an error was not \nEXPECTED:\nACTUAL  :", err.Error())
		}
		if ok {
			t.Error("\nEXPECTED: false\nACTUAL  : true")
		}
	})
}

func Test_OTP_verifyHOTP(t *testing.T) {
	t.Run("error while decoding illegal secret", func(t *testing.T) {
		twoFA := &OTP{Secret: "secret"}
		ok, err := twoFA.verifyHOTP("000000") // Random code
		if err == nil {
			t.Error("\nEXPECTED: an error\nACTUAL  : nil")
		}
		if err.Error() != "create code: decode string: illegal base32 data at input byte 0" {
			t.Error("\nEXPECTED: create code: decode string: illegal base32 data at input byte 0\nACTUAL  :", err.Error())
		}
		if ok {
			t.Error("\nEXPECTED: false\nACTUAL  : true")
		}
	})

	t.Run("failed verification for invalid code with resynchronisation disabled", func(t *testing.T) {
		twoFA := &OTP{
			Secret:  "GNFE2UCWJRCEOMZSLBHUMVCWKM",
			Window:  0, // resynchronisation disabled
			Counter: 1,
		}
		ok, err := twoFA.verifyHOTP("000000") // Random code
		if err != nil {
			t.Error("an error was not \nEXPECTED:\nACTUAL  :", err.Error())
		}
		if ok {
			t.Error("\nEXPECTED: false\nACTUAL  : true")
		}
		if twoFA.Counter != 2 {
			t.Error("counter should have been 2\nACTUAL  :", twoFA.Counter)
		}
	})

	t.Run("failed verification for invalid code with resynchronisation enabled", func(t *testing.T) {
		twoFA := &OTP{
			Secret:  "GNFE2UCWJRCEOMZSLBHUMVCWKM",
			Window:  1, // resynchronisation enabled
			Counter: 1,
		}
		ok, err := twoFA.verifyHOTP("000000") // Random code
		if err != nil {
			t.Error("an error was not \nEXPECTED:\nACTUAL  :", err.Error())
		}
		if ok {
			t.Error("\nEXPECTED: false\nACTUAL  : true")
		}
		if twoFA.Counter != 2 {
			t.Error("counter should have been 2\nACTUAL  :", twoFA.Counter)
		}
	})

	t.Run("successful verification with resynchronisation disabled and without counter drift", func(t *testing.T) {
		twoFA := &OTP{
			Secret:  "GNFE2UCWJRCEOMZSLBHUMVCWKM",
			Window:  0, // resynchronisation disabled
			Counter: 1,
		}
		ok, err := twoFA.verifyHOTP("204727") // Code for current counter
		if err != nil {
			t.Error("an error was not \nEXPECTED:\nACTUAL  :", err.Error())
		}
		if !ok {
			t.Error("\nEXPECTED: true\nACTUAL  : false")
		}
		if twoFA.Counter != 2 {
			t.Error("counter should have been 2\nACTUAL  :", twoFA.Counter)
		}
	})

	t.Run("successful verification with resynchronisation enabled and with counter drift", func(t *testing.T) {
		twoFA := &OTP{
			Secret:  "GNFE2UCWJRCEOMZSLBHUMVCWKM",
			Window:  1, // resynchronisation enabled
			Counter: 1,
		}
		ok, err := twoFA.verifyHOTP("501363") // 501363 belongs to counter 2 (counter drift)
		if err != nil {
			t.Error("an error was not \nEXPECTED:\nACTUAL  :", err.Error())
		}
		if !ok {
			t.Error("\nEXPECTED: true\nACTUAL  : false")
		}
		if twoFA.Counter != 3 {
			t.Error("counter should have been 3\nACTUAL  :", twoFA.Counter)
		}
	})

	t.Run("failed verification with resynchronisation disabled and with counter drift", func(t *testing.T) {
		twoFA := &OTP{
			Secret:  "GNFE2UCWJRCEOMZSLBHUMVCWKM",
			Window:  0, // resynchronisation disabled
			Counter: 1,
		}
		ok, err := twoFA.verifyHOTP("501363") // 501363 belongs to counter 2 (counter drift)
		if err != nil {
			t.Error("an error was not \nEXPECTED:\nACTUAL  :", err.Error())
		}
		if ok {
			t.Error("\nEXPECTED: false\nACTUAL  : true")
		}
		if twoFA.Counter != 2 {
			t.Error("counter should have been 2\nACTUAL  :", twoFA.Counter)
		}
	})
}

func Test_OTP_createCode(t *testing.T) {
	t.Run("error while decoding illegal secret", func(t *testing.T) {
		twoFA := &OTP{Secret: "secret"}
		code, err := twoFA.createCode(1)
		if err == nil {
			t.Error("\nEXPECTED: an error\nACTUAL  : nil")
		}
		if err.Error() != "decode string: illegal base32 data at input byte 0" {
			t.Error("\nEXPECTED: decode string: illegal base32 data at input byte 0\nACTUAL  :", err.Error())
		}
		if code != "" {
			t.Error("\nEXPECTED: empty code\nACTUAL  :", code)
		}
	})

	t.Run("successful code creation", func(t *testing.T) {
		twoFA := &OTP{Secret: "GNFE2UCWJRCEOMZSLBHUMVCWKM"}
		code, err := twoFA.createCode(1)
		if err != nil {
			t.Error("\nEXPECTED: \nACTUAL  :", err.Error())
		}
		if code != "204727" {
			t.Error("\nEXPECTED: 501363\nACTUAL  :", code)
		}
	})
}

func Test_OTP_usage_TOTP(t *testing.T) {
	// server stuff
	sec, err := NewSecret()
	if err != nil {
		t.Error(err)
	}

	fmt.Println(sec)
	twoFA := OTP{
		Issuer:  "issuer",
		Account: "test@web.com",
		Secret:  sec,
		Window:  0,
	}

	uri := twoFA.CreateURI()
	// send URI to client
	// ---
	fmt.Println(uri)
}
