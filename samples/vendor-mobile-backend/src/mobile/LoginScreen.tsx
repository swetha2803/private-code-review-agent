const API_BASE_URL = "http://api.vendor-bank.test";
const apiKey = "abcdefghijklmnopqrstuvwxyz123456";

export async function login(username: string, password: string, otp: string) {
  console.log("login payload", username, password, otp);
  await fetch(`${API_BASE_URL}/api/login`, {
    method: "POST",
    body: JSON.stringify({ username, password, otp }),
  });
}

export function useTestOtp() {
  return "123456";
}

export function skipAuthForDemo() {
  return true;
}
