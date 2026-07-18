# go-otp

Yet another Go one-time password package. It implements the **TOTP**
([RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238)) and **HOTP**
([RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226)) algorithms used for
two-factor authentication (2FA), along with helpers for generating shared
secrets, provisioning URIs, and QR codes for authenticator apps.

## Install

```sh
go get github.com/erancihan/go-otp
```

```go
import otp "github.com/erancihan/go-otp"
```

## Quick start (TOTP)

```go
// 1. On enrolment, generate a cryptographically secure secret and store it
//    against the user.
secret, err := otp.NewSecret()
if err != nil {
    // handle error
}

twoFA := otp.OTP{
    Issuer:  "Example Inc",
    Account: "jane@example.com",
    Secret:  secret,
    Window:  1, // tolerate +/- one time step of clock drift
}

// 2. Show the user a QR code to scan with their authenticator app.
uri := twoFA.CreateURI()
png, err := otp.NewQR(uri)
if err != nil {
    // handle error
}
// serve `png` (image/png) to the client

// 3. Later, verify a code the user submits.
ok, err := twoFA.VerifyCode("123456")
if err != nil {
    // handle error (e.g. malformed input)
}
if ok {
    // code accepted
}
```

## HOTP (counter-based)

Set a non-zero `Counter` to switch to HOTP. This is handy for codes delivered
out of band, e.g. by email or SMS.

```go
twoFA := otp.OTP{
    Issuer:  "Example Inc",
    Account: "jane@example.com",
    Secret:  secret,
    Counter: 1,
}

code, err := twoFA.CreateHOTPCode(twoFA.Counter)
// deliver `code` to the user, persist the incremented counter

ok, err := twoFA.VerifyCode(code)
```

On successful verification the server-side `Counter` is advanced; persist it so
the next verification starts from the right value.

## Configuration

All options live on the `OTP` struct. The zero value matches what authenticator
apps expect (6 digits, 30-second period, HMAC-SHA1), so you only set what you
need to change.

| Field       | Type        | Default    | Description                                                        |
| ----------- | ----------- | ---------- | ------------------------------------------------------------------ |
| `Issuer`    | `string`    | —          | Service/provider name shown in the app.                            |
| `Account`   | `string`    | —          | User identifier (e.g. username or email).                          |
| `Secret`    | `string`    | —          | Base32-encoded shared secret (see `NewSecret`).                    |
| `Counter`   | `int`       | `0`        | `0` selects TOTP; any non-zero value selects HOTP.                 |
| `Window`    | `int`       | `0`        | Drift tolerance. `0` disables resync; `1` is the recommended value.|
| `Digits`    | `int`       | `6`        | Number of digits in a code (typically 6 or 8).                     |
| `Period`    | `int`       | `30`       | TOTP time step in seconds (ignored for HOTP).                      |
| `Algorithm` | `Algorithm` | `SHA1`     | Hash function: `AlgorithmSHA1`, `AlgorithmSHA256`, `AlgorithmSHA512`. |

```go
twoFA := otp.OTP{
    Issuer:    "Example Inc",
    Account:   "jane@example.com",
    Secret:    secret,
    Digits:    8,
    Period:    60,
    Algorithm: otp.AlgorithmSHA256,
    Window:    1,
}
```

> **Note on `Window`:** larger values widen the acceptance window and, per the
> RFCs, increase exposure to brute-force/DoS. `1` is the recommended balance.

## Security notes

- Secrets are generated with `crypto/rand` (128 bits of entropy) and returned
  as a 26-character Base32 string.
- Submitted codes are compared in constant time to avoid timing side-channels.
- HMAC-SHA1 is the default because it is universally supported; SHA256/SHA512
  are available but not every authenticator app supports them.

## Credits

The original implementation was adapted from
[this article by inanzzz](http://www.inanzzz.com/index.php/post/y5nu/creating-a-one-time-password-otp-library-for-two-factor-authentication-2fa-with-golang).

## License

Released into the public domain under the [Unlicense](LICENSE).
