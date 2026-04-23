import { GoogleAuth } from "google-auth-library";
import { env } from "./env.js";

type IntegrityVerdict = {
  nonceMatches: boolean;
  appRecognized: boolean;
  deviceRecognized: boolean;
  licensed: boolean;
  packageMatches: boolean;
  raw: unknown;
};

function parseServiceAccountJson(): Record<string, unknown> {
  const raw = env.GOOGLE_APPLICATION_CREDENTIALS_JSON.trim();
  return JSON.parse(raw) as Record<string, unknown>;
}

export async function verifyPlayIntegrityToken(
  integrityToken: string,
  expectedNonce: string
): Promise<IntegrityVerdict> {
  const credentials = parseServiceAccountJson();
  const auth = new GoogleAuth({
    credentials,
    scopes: ["https://www.googleapis.com/auth/playintegrity"]
  });

  const client = await auth.getClient();
  const accessToken = await client.getAccessToken();
  if (!accessToken.token) {
    throw new Error("google_access_token_unavailable");
  }

  const response = await fetch(
    `https://playintegrity.googleapis.com/v1/${encodeURIComponent(env.GOOGLE_PLAY_PACKAGE_NAME)}:decodeIntegrityToken`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken.token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ integrityToken })
    }
  );

  if (!response.ok) {
    throw new Error(`integrity_api_error_${response.status}`);
  }

  const decoded = (await response.json()) as {
    tokenPayloadExternal?: {
      requestDetails?: {
        requestPackageName?: string;
        nonce?: string;
      };
      appIntegrity?: {
        appRecognitionVerdict?: string;
      };
      deviceIntegrity?: {
        deviceRecognitionVerdict?: string[];
      };
      accountDetails?: {
        appLicensingVerdict?: string;
      };
    };
  };

  const payload = decoded.tokenPayloadExternal ?? {};
  const requestDetails = payload.requestDetails ?? {};
  const appIntegrity = payload.appIntegrity ?? {};
  const deviceIntegrity = payload.deviceIntegrity ?? {};
  const accountDetails = payload.accountDetails ?? {};

  const deviceVerdicts = deviceIntegrity.deviceRecognitionVerdict ?? [];

  return {
    nonceMatches: requestDetails.nonce === expectedNonce,
    packageMatches: requestDetails.requestPackageName === env.GOOGLE_PLAY_PACKAGE_NAME,
    appRecognized: appIntegrity.appRecognitionVerdict === "PLAY_RECOGNIZED",
    deviceRecognized:
      deviceVerdicts.includes("MEETS_DEVICE_INTEGRITY") ||
      deviceVerdicts.includes("MEETS_STRONG_INTEGRITY"),
    licensed: accountDetails.appLicensingVerdict === "LICENSED",
    raw: decoded
  };
}
