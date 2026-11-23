import { DurableObject } from 'cloudflare:workers';
import { ChainStore } from './ledger';
import { boundedBody, canonical, requireThat, signedResponse, validateRequest } from './protocol';

interface Env {
  EVIDENCE: DurableObjectNamespace<EvidenceLedger>;
  ALLOWED_PRODUCERS: string;
  WITNESS_PUBLIC: string;
  WITNESS_SIGNING_PKCS8: string;
  MAX_STORE_BYTES: string;
}
const json = (value: unknown, status = 200) => new Response(canonical(value), {
  status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store',
    'x-content-type-options': 'nosniff' },
});
function allowed(env: Env) {
  const keys = env.ALLOWED_PRODUCERS.split(',');
  requireThat(keys.length >= 1 && keys.length <= 32 && keys.every(k => /^[0-9a-f]{64}$/.test(k)));
  return keys;
}
export class EvidenceLedger extends DurableObject<Env> {
  async fetch(request: Request): Promise<Response> {
    try {
      const req = await boundedBody(request);
      await validateRequest(req, allowed(this.env));
      const store = new ChainStore(this.ctx.storage, Number(this.env.MAX_STORE_BYTES));
      const block = req.op === 'put' ? await store.append(req.block) :
        req.op === 'get' ? await store.get(req.height, req.stream) : await store.head(req.stream);
      await this.ctx.storage.sync();
      return json(await signedResponse(req, block, this.env.WITNESS_SIGNING_PKCS8, this.env.WITNESS_PUBLIC));
    } catch {
      return json({ error: 'request refused' }, 409);
    }
  }
}
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (request.method === 'GET' && path === '/healthz') {
      const ok = /^[0-9a-f]{64}$/.test(env.WITNESS_PUBLIC ?? '') && !!env.WITNESS_SIGNING_PKCS8;
      return json({ ok, protocol: 1, witness: env.WITNESS_PUBLIC ?? null, storage: 'sqlite-durable-object' }, ok ? 200 : 503);
    }
    if (request.method !== 'POST' || path !== '/v1/mesh') return json({ error: 'not found' }, 404);
    try {
      const req = await boundedBody(request);
      await validateRequest(req, allowed(env)); // No untrusted object allocation.
      const id = env.EVIDENCE.idFromName(req.stream);
      return await env.EVIDENCE.get(id).fetch(new Request('https://internal/v1/mesh', {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: canonical(req),
      }));
    } catch {
      return json({ error: 'request refused' }, 409);
    }
  },
} satisfies ExportedHandler<Env>;
