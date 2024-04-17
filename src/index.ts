import JsSHA from "jssha";
import { randomBytes } from "crypto";

type Algorithm = "SHA-1" | "SHA-256" | "SHA-512";

type OtpOptions = {
  secret: string;
  algorithm: Algorithm;
  digits: number;
  counter: number;
};

type Options = {
  algorithm?: Algorithm;
  digits?: number;
  period?: number;
  timestamp?: number;
};

type URLOptions = {
  accountName: string;
  issuer: string;
  secret: string;
  algorithm?: Algorithm;
  digits?: number;
  period?: number;
};

type ValidateOptions = {
  algorithm?: Algorithm;
  digits?: number;
  period?: number;
  window?: number;
};

function base32tohex(base32: string): string {
  const base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  let hex = "";

  const _base32 = base32.replace(/=+$/, "");

  for (let i = 0; i < _base32.length; i++) {
    const val = base32chars.indexOf(base32.charAt(i).toUpperCase());
    if (val === -1) throw new Error("Invalid base32 character in key");
    bits += val.toString(2).padStart(5, "0");
  }

  for (let i = 0; i + 8 <= bits.length; i += 8) {
    const chunk = bits.substr(i, 8);
    hex = hex + parseInt(chunk, 2).toString(16).padStart(2, "0");
  }
  return hex;
}

function hexToBase32(hexString: string): string {
  // Define the base32 characters
  const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

  // Initialize variables
  let binaryString = "";
  let result = "";

  // Convert hexadecimal to binary
  for (let i = 0; i < hexString.length; i += 2) {
    const byte = parseInt(hexString.substr(i, 2), 16)
      .toString(2)
      .padStart(8, "0");
    binaryString += byte;
  }

  // Convert binary to base32
  for (let i = 0; i < binaryString.length; i += 5) {
    const chunk = binaryString.substr(i, 5);
    result += base32Chars[parseInt(chunk, 2)];
  }

  // Add padding if necessary
  const padding = binaryString.length % 40;
  if (padding > 0) {
    result += "=".repeat(8 - padding / 5);
  }

  return result;
}

function extractCode(hmac: string): number {
  // Extract last 4 bits as offset
  const offset = parseInt(hmac[hmac.length - 1], 16) & 0xf;
  // Extract 31 bits starting from offset
  return parseInt(hmac.slice(offset * 2, offset * 2 + 8), 16) & 0x7fffffff;
}

function generateOtpForCounter({
  secret,
  algorithm,
  digits,
  counter,
}: OtpOptions): string {
  const counterHex = counter.toString(16).padStart(16, "0"); // 8 byte HEX

  // Generate Hash
  const sha = new JsSHA(algorithm, "HEX");
  sha.setHMACKey(base32tohex(secret), "HEX");
  sha.update(counterHex);
  const hmac = sha.getHash("HEX");

  const code = extractCode(hmac);

  const otp = code % Math.pow(10, digits); // Truncate and convert to required digits
  return otp.toString().padStart(digits, "0"); // Pad token with leading zeros if necessary
}

export function generateOtp(
  secret: string,
  { algorithm = "SHA-1", digits = 6, period = 30, timestamp }: Options = {}
): string {
  const time = Math.floor((timestamp ?? Date.now()) / 1000);
  const counter = Math.floor(time / period);

  return generateOtpForCounter({ secret, algorithm, digits, counter });
}

export function generateBase32Secret(length: number = 20): string {
  // Generate a random byte array
  const secretKey = randomBytes(length).toString("hex");

  return hexToBase32(secretKey);
}

export function generateAuthURL(options: URLOptions): string {
  const query = new URLSearchParams();

  Object.entries(options).forEach(([key, value]) => {
    query.append(key, value.toString().replace("-", ""));
  });

  const url = `otpauth://totp/${encodeURIComponent(
    options.issuer
  )}:${encodeURIComponent(options.accountName)}?${query.toString()}`;
  return url;
}

export function validateOtp(
  otp: string,
  secret: string,
  {
    algorithm = "SHA-1",
    digits = 6,
    period = 30,
    window = 0,
  }: ValidateOptions = {}
): boolean {
  const time = Math.floor(Date.now() / 1000);
  let counter: number = Math.floor(time / period);

  for (let i = -window; i <= window; i++) {
    const value = generateOtpForCounter({
      secret,
      algorithm,
      digits,
      counter: counter + i,
    });

    if (value === otp) {
      return true;
    }
  }

  return false;
}
