import crypto from "isomorphic-webcrypto";



// Flow:
// +------------+                                  +--------+
// | Client App |                                  | Server |
// +------------+                                  +--------+
//    |-> Generates Code Challenge                     |
//    |   And Verifier                                 |
//    |                                                |
//    |-> Request with Code Challenge ---------------->|
//    |                                                |
//    |<------- After ask for consent send auth code <-|
//    |                                                |
//    |-> Sends auth code with verifier -------------->|
//    |                                                |
//    |                      Verifies code challenge <-|
//    |                                                |
//    |<---------- Returns an access token to ckient <-|
//    |                                                |
export function generateRandomString(): string {
    const buff = new Uint16Array(56/2);
    crypto.getRandomValues(buff);
    return Array.from(buff, decToHex).join('');
}
export function createBuffer(plain: string): Uint8Array {
    return (new TextEncoder()).encode(plain);
}

export function decToHex(dec: number): string {
    return `0${dec.toString(16)}`.substring(-2)
}

export function base64EncodeBase(source: string, encoding: 'base64' | 'base64url' = 'base64'): string {
        const res = Buffer.from(source).toString(encoding);
        return encoding === 'base64url'
            ? base64url(res)
            : res;
}
export function base64url(plain: string): string {
    return plain.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64Encode(source: ArrayBuffer): string {
    return base64EncodeBase(String.fromCharCode.apply(null, (new Uint8Array(source) as unknown as [number])), 'base64url');
}

export async function createHashSha256(plain: string): Promise<ArrayBuffer> {
    return crypto.subtle.digest({
    name: 'SHA-256'
}, createBuffer(plain));
}
export async function createPKCEChallengeFromVerifier(verifier: string): Promise<string> {
    return createHashSha256(verifier).then((buff) => base64Encode(buff));
}

export async function createPKCE(): Promise<{
    verifier: string,
    code_challenge: string,
    method: 'SHA256'
}> {
    const verifier = generateRandomString();
    return {
        verifier,
        code_challenge: await createPKCEChallengeFromVerifier(verifier),
        method: 'SHA256'
    }
}

export async function verify(challenge: string, verifier:string): Promise<boolean> {
    const newChallenge = await createPKCEChallengeFromVerifier(verifier);
    return challenge === newChallenge;
}
