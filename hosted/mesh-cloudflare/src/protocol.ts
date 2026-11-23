/** Strict ASCII-only subset of the Python mesh v1 canonical wire contract. */
export const ZERO = '0'.repeat(64);
export const MAX_WIRE = 2 * 1024 * 1024;
export type Body = Record<string, any>;
export class Refused extends Error {}
const encoder = new TextEncoder();

export function requireThat(value: unknown, message = 'request refused'): asserts value {
  if (!value) throw new Refused(message);
}
export function fields(body: Body, names: string[]) {
  requireThat(body && typeof body === 'object' && !Array.isArray(body));
  requireThat(Object.keys(body).sort().join(',') === names.sort().join(','));
}
export function integer(value: unknown, min = 0, max = 100_000): asserts value is number {
  requireThat(typeof value === 'number' && Number.isSafeInteger(value) && value >= min && value <= max);
}
export function bytes(value: unknown, length: number): Uint8Array {
  requireThat(typeof value === 'string' && value.length === length * 2 && /^[0-9a-f]+$/.test(value));
  return Uint8Array.from(value.match(/../g)!, b => parseInt(b, 16));
}
export function hex(value: ArrayBuffer | Uint8Array): string {
  return [...new Uint8Array(value as ArrayBuffer)].map(b => b.toString(16).padStart(2, '0')).join('');
}
export function canonical(value: any): string {
  if (value === null) return 'null';
  if (typeof value === 'number') {
    requireThat(Number.isSafeInteger(value));
    return String(value);
  }
  if (typeof value === 'string') {
    requireThat(/^[\x00-\x7f]*$/.test(value));
    return JSON.stringify(value);
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  requireThat(value && typeof value === 'object');
  return '{' + Object.keys(value).sort().map(k => canonical(k) + ':' + canonical(value[k])).join(',') + '}';
}
export function wire(value: any): Uint8Array {
  const result = encoder.encode(canonical(value));
  requireThat(result.length <= MAX_WIRE);
  return result;
}
export async function digest(value: any): Promise<string> {
  return hex(await crypto.subtle.digest('SHA-256', wire(value)));
}
export async function verify(signed: Body, key: string) {
  requireThat(signed && typeof signed === 'object');
  const { signature, ...body } = signed;
  const publicKey = await crypto.subtle.importKey('raw', bytes(key, 32), 'Ed25519', false, ['verify']);
  requireThat(await crypto.subtle.verify('Ed25519', publicKey, bytes(signature, 64), wire(body)));
}
export async function validateBlock(block: Body) {
  fields(block, ['v', 'stream', 'height', 'previous', 'nonce', 'ciphertext', 'signature']);
  requireThat(block.v === 1);
  bytes(block.stream, 32); integer(block.height, 1); bytes(block.previous, 32); bytes(block.nonce, 12);
  requireThat(typeof block.ciphertext === 'string' && block.ciphertext.length >= 32 &&
    block.ciphertext.length <= MAX_WIRE / 2 && block.ciphertext.length % 2 === 0);
  bytes(block.ciphertext, block.ciphertext.length / 2);
  await verify(block, block.stream);
}
export async function validateRequest(req: Body, allowed: string[]) {
  fields(req, ['v', 'stream', 'op', 'height', 'nonce', 'signature', ...(req.op === 'put' ? ['block'] : [])]);
  requireThat(req.v === 1 && ['put', 'get', 'head'].includes(req.op) && allowed.includes(req.stream));
  integer(req.height); bytes(req.nonce, 16);
  await verify(req, req.stream);
  if (req.op === 'put') {
    await validateBlock(req.block);
    requireThat(req.block.stream === req.stream && req.block.height === req.height);
  }
}
export async function signedResponse(req: Body, block: Body | null, privatePkcs8: string, witness: string) {
  const body = { v: 1, witness, request: await digest(req), stream: req.stream, op: req.op,
    nonce: req.nonce, time: Math.floor(Date.now() / 1000), height: block?.height ?? 0,
    digest: block ? await digest(block) : ZERO, block: req.op === 'get' ? block : null };
  const privateKey = await crypto.subtle.importKey('pkcs8', bytes(privatePkcs8, 48), 'Ed25519', false, ['sign']);
  const result = { ...body, signature: hex(await crypto.subtle.sign('Ed25519', privateKey, wire(body))) };
  await verify(result, witness); // Refuse an inconsistent signing-key configuration.
  return result;
}
export async function boundedBody(request: Request): Promise<Body> {
  requireThat(request.headers.get('content-type') === 'application/json' && request.body);
  const declared = request.headers.get('content-length');
  if (declared !== null) requireThat(/^\d+$/.test(declared) && Number(declared) <= MAX_WIRE);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.length;
      requireThat(length <= MAX_WIRE);
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  }
  const data = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { data.set(chunk, offset); offset += chunk.length; }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(data));
}
