import {
  generateOtp,
  generateBase32Secret,
  generateAuthURL,
  validateOtp,
} from "./dist/index";

// secret = generateBase32Secret();
const secret = "4JCAVIMRQJBTEGNJS3T3BC4P6AXKCWNU";

const accountName = "jsmith%40atlassian.com";
const issuer = "Atlassian";
const options = {
  algorithm: "SHA-1", // Optional: Algorithm (SHA1, SHA256, SHA512)
  digits: 6, // Optional: Number of digits in the TOTP code
  period: 30, // Optional: Interval in seconds
};

console.log(secret);

const totpURL = generateAuthURL({ accountName, issuer, secret });
console.log("TOTP URL:", totpURL);

console.log(generateOtp(secret));

console.log(validateOtp("438123", secret, { window: 1 }));
