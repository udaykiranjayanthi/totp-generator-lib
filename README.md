# totp-generator-lib

A TypeScript library for generating and validating Time-based One-Time Passwords (TOTP).

## Installation

You can install the library via npm:

```bash
npm install totp-generator-lib
```
or
```bash
yarn add totp-generator-lib
```

## Usage

### Importing

```typescript
import {
  generateOtp,
  generateBase32Secret,
  generateAuthURL,
  validateOtp,
} from 'totp-generator-lib';
```

### Generating Base32 Secret

```typescript
const secret = generateBase32Secret();
// S5OE62B7OKL5DCKKZGZA
```

You can pass custom length to generate secrent (default is 20 characters) 
```typescript
const secret = generateBase32Secret(25);
// S5OE62B7OKL5DCKKZGZAXIYWA
```

### Generating Auth URL

```typescript
const url = generateAuthURL({
  accountName: 'Example:john_doe@example.com',
  issuer: 'Example',
  secret: secret,
});
```
This will generate an URL in a format, which can be read by authentication apps like Google Authenticator, Authy etc. Convert this text into QR code on client side using any library of your choice. Authentications apps will complete the setup process automatically once you scan that QR code. 

Example auth URL: 
```crul
otpauth://totp/Example:Example%3Ajohn_doe%40example.com?accountName=Example%3Ajohn_doe%40example.com&issuer=Example&secret=C7WDQWTH54HDHXMZYUUU7ZXIYWALBTS5
```
#### Optional parameters
- `algorithm`: The hashing algorithm to use (default is "SHA-1").
- `digits`: The number of digits in the generated TOTP (default is 6).
- `period`: The time period in seconds for which the TOTP is valid (default is 30 seconds).

```typescript
const url = generateAuthURL({
  accountName: 'Example:john_doe@example.com',
  issuer: 'Example',
  secret: secret,
  algorithm: 'SHA1',
  digits: 6,
  period: 30,
});
```
```crul
otpauth://totp/Example:Example%3Ajohn_doe%40example.com?accountName=Example%3Ajohn_doe%40example.com&issuer=Example&secret=C7WDQWTH54HDHXMZYUUU7ZXIYWALBTS5&algorithm=SHA1&digits=6&period=30
```

### Generating TOTP

```typescript
const otp = generateOtp(secret);
// 456785
```

#### Options
- `algorithm`: The hashing algorithm to use (default is "SHA-1").
- `digits`: The number of digits in the generated TOTP (default is 6).
- `period`: The time period in seconds for which the TOTP is valid (default is 30 seconds).
- `timestamp`: The UNIX timestamp in milliseconds to use as the reference time for TOTP generation (default is the current time).

```typescript
const otp = generateOtp(secret, {
    algorithm: 'SHA-1',
    digits: 5,
    period: 30,
    timestamp: 1713354746707
});
// 34567
```

### Validating TOTP

```typescript
const isValid = validateOtp(otp, secret);
// false
```

#### Options
- `algorithm`: The hashing algorithm to use (default is "SHA-1").
- `digits`: The number of digits in the generated TOTP (default is 6).
- `period`: The time period in seconds for which the TOTP is valid (default is 30 seconds).
- `window`: The number of time steps before and after the current time step to check for valid OTPs during validation (default is 0).

```typescript
const isValid = validateOtp(34567, secret, {
    algorithm: 'SHA-1',
    digits: 5,
    period: 30,
    window: 1
});
// true
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
```
This README provides instructions on installing the library, its usage, API documentation, examples, and licensing information.