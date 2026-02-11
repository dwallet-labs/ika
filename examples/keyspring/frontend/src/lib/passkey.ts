/**
 * WebAuthn Passkey Module for DKG Wallet Control
 *
 * Uses the PRF (Pseudo-Random Function) extension to derive deterministic
 * encryption keys from passkey authentication.
 */

// Types
export interface StoredCredential {
  credentialId: string; // base64url encoded
  publicKey: string; // base64url encoded
  createdAt: number;
  ethereumAddress?: string; // Associated dWallet address if exists
}

export interface PasskeyAuthResult {
  success: boolean;
  prfSecret?: Uint8Array; // 32 bytes deterministic secret
  error?: string;
}

export interface PasskeyRegistrationResult {
  success: boolean;
  credential?: StoredCredential;
  prfEnabled?: boolean;
  error?: string;
}

export interface PasskeySupportInfo {
  webauthnSupported: boolean;
  prfSupported: boolean;
}

// Constants
const STORAGE_KEY = "passkey_credential";
const DKG_PRF_SALT = new TextEncoder().encode("ika-dwallet-dkg-seed-v1");
const RP_NAME = "KeySpring by Ika";

// Get RP ID (hostname without port)
function getRpId(): string {
  if (typeof window === "undefined") return "";
  return window.location.hostname;
}

// Helper: ArrayBuffer to base64url
function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// Helper: base64url to ArrayBuffer
function base64UrlToArrayBuffer(base64url: string): ArrayBuffer {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(
    base64.length + ((4 - (base64.length % 4)) % 4),
    "="
  );
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Check if WebAuthn and PRF extension are supported
 */
export async function checkPasskeySupport(): Promise<PasskeySupportInfo> {
  const webauthnSupported =
    typeof window !== "undefined" &&
    window.PublicKeyCredential !== undefined &&
    typeof window.PublicKeyCredential === "function";

  if (!webauthnSupported) {
    return { webauthnSupported: false, prfSupported: false };
  }

  // PRF support detection is tricky - we assume it's potentially supported
  // and handle failures gracefully at runtime
  // Modern browsers (Chrome 116+, Safari 18+) support PRF
  let prfSupported = true;

  // Try to detect via getClientCapabilities if available
  try {
    const pkc = window.PublicKeyCredential as typeof PublicKeyCredential & {
      getClientCapabilities?: () => Promise<{ extensions?: string[] }>;
    };
    if (typeof pkc.getClientCapabilities === "function") {
      const caps = await pkc.getClientCapabilities();
      if (Array.isArray(caps?.extensions)) {
        prfSupported = caps.extensions.includes("prf");
      }
    }
  } catch {
    // Fallback: assume PRF might be supported
  }

  return { webauthnSupported, prfSupported };
}

/**
 * Check if user has a stored credential
 */
export function hasStoredCredential(): boolean {
  if (typeof window === "undefined") return false;
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    return stored !== null;
  } catch {
    return false;
  }
}

/**
 * Get stored credential from localStorage
 */
export function getStoredCredential(): StoredCredential | null {
  if (typeof window === "undefined") return null;
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored) return null;
    return JSON.parse(stored) as StoredCredential;
  } catch {
    return null;
  }
}

/**
 * Store credential in localStorage
 */
export function storeCredential(credential: StoredCredential): void {
  if (typeof window === "undefined") return;
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(credential));
  } catch (err) {
    console.error("Failed to store credential:", err);
  }
}

/**
 * Clear stored credential
 */
export function clearStoredCredential(): void {
  if (typeof window === "undefined") return;
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Ignore
  }
}

/**
 * Update stored credential with ethereum address
 */
export function updateCredentialEthAddress(address: string): void {
  const cred = getStoredCredential();
  if (cred) {
    cred.ethereumAddress = address;
    storeCredential(cred);
  }
}

/**
 * Register a new passkey with PRF enabled
 */
export async function registerPasskey(
  username?: string
): Promise<PasskeyRegistrationResult> {
  try {
    // Generate random user ID
    const userId = new Uint8Array(32);
    crypto.getRandomValues(userId);

    // Generate challenge
    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);

    const displayName = username || `KeySpring User`;
    const userName = username || `keyspring-${Date.now()}`;

    const createOptions: PublicKeyCredentialCreationOptions = {
      rp: {
        name: RP_NAME,
        id: getRpId(),
      },
      user: {
        id: userId,
        name: userName,
        displayName: displayName,
      },
      challenge: challenge,
      pubKeyCredParams: [
        { alg: -7, type: "public-key" }, // ES256 (ECDSA with P-256)
        { alg: -257, type: "public-key" }, // RS256
      ],
      timeout: 60000,
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required",
      },
      attestation: "none",
      extensions: {
        prf: {},
      } as AuthenticationExtensionsClientInputs,
    };

    const credential = (await navigator.credentials.create({
      publicKey: createOptions,
    })) as PublicKeyCredential | null;

    if (!credential) {
      return { success: false, error: "Passkey creation cancelled" };
    }

    // Check if PRF was enabled
    const extensionResults = credential.getClientExtensionResults() as {
      prf?: { enabled?: boolean };
    };
    const prfEnabled = extensionResults?.prf?.enabled === true;

    // Store credential
    const response =
      credential.response as AuthenticatorAttestationResponse & {
        getPublicKey?: () => ArrayBuffer | null;
      };

    const publicKeyBuffer = response.getPublicKey?.();
    const storedCred: StoredCredential = {
      credentialId: arrayBufferToBase64Url(credential.rawId),
      publicKey: publicKeyBuffer
        ? arrayBufferToBase64Url(publicKeyBuffer)
        : "",
      createdAt: Date.now(),
    };

    storeCredential(storedCred);

    return {
      success: true,
      credential: storedCred,
      prfEnabled,
    };
  } catch (err) {
    console.error("Passkey registration error:", err);
    return {
      success: false,
      error: err instanceof Error ? err.message : "Failed to create passkey",
    };
  }
}

/**
 * Authenticate with existing passkey and derive PRF secret
 */
export async function authenticateWithPasskey(): Promise<PasskeyAuthResult> {
  try {
    const storedCred = getStoredCredential();

    // Generate challenge
    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);

    const getOptions: PublicKeyCredentialRequestOptions = {
      challenge: challenge,
      timeout: 60000,
      rpId: getRpId(),
      userVerification: "required",
      extensions: {
        prf: {
          eval: {
            first: DKG_PRF_SALT,
          },
        },
      } as AuthenticationExtensionsClientInputs,
    };

    // If we have a stored credential, use allowCredentials for faster UX
    if (storedCred) {
      getOptions.allowCredentials = [
        {
          type: "public-key",
          id: base64UrlToArrayBuffer(storedCred.credentialId),
        },
      ];
    }

    const assertion = (await navigator.credentials.get({
      publicKey: getOptions,
    })) as PublicKeyCredential | null;

    if (!assertion) {
      return { success: false, error: "Authentication cancelled" };
    }

    // Extract PRF result
    const extensionResults = assertion.getClientExtensionResults() as {
      prf?: { results?: { first?: ArrayBuffer } };
    };
    const prfResults = extensionResults?.prf?.results;

    if (!prfResults?.first) {
      return {
        success: false,
        error:
          "PRF extension not supported by this passkey or browser. Please use a compatible device.",
      };
    }

    // Update stored credential if different (user might have multiple passkeys)
    const newCredId = arrayBufferToBase64Url(assertion.rawId);
    if (!storedCred || storedCred.credentialId !== newCredId) {
      storeCredential({
        credentialId: newCredId,
        publicKey: storedCred?.publicKey || "",
        createdAt: Date.now(),
      });
    }

    return {
      success: true,
      prfSecret: new Uint8Array(prfResults.first),
    };
  } catch (err) {
    console.error("Passkey authentication error:", err);
    return {
      success: false,
      error: err instanceof Error ? err.message : "Authentication failed",
    };
  }
}

/**
 * Convert PRF secret to format compatible with existing DKG flow
 * Returns hex string that can be passed to computeEncryptionKeys()
 */
export function prfSecretToSeedString(prfSecret: Uint8Array): string {
  return (
    "0x" +
    Array.from(prfSecret)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  );
}
