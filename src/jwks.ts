import { createRemoteJWKSet, customFetch } from "jose";

type RemoteJwks = ReturnType<typeof createRemoteJWKSet>;
const maximumCachedEndpoints = 32;
const defaultCache = new Map<string, RemoteJwks>();
const transportCaches = new WeakMap<typeof fetch, Map<string, RemoteJwks>>();

/** Reuse jose's key imports, in-flight fetch and rotation cooldown across verifications. */
export function remoteJwks(uri: string, fetchImpl?: typeof fetch): RemoteJwks {
  let cache = defaultCache;
  if (fetchImpl !== undefined) {
    const existing = transportCaches.get(fetchImpl);
    cache = existing ?? new Map<string, RemoteJwks>();
    if (existing === undefined) transportCaches.set(fetchImpl, cache);
  }

  const cached = cache.get(uri);
  if (cached !== undefined) {
    // LRU bounds issuer churn without retaining custom transports after their clients are gone.
    cache.delete(uri);
    cache.set(uri, cached);
    return cached;
  }

  const jwks = createRemoteJWKSet(
    new URL(uri),
    fetchImpl === undefined ? undefined : { [customFetch]: fetchImpl },
  );
  cache.set(uri, jwks);
  if (cache.size > maximumCachedEndpoints)
    cache.delete(cache.keys().next().value!);
  return jwks;
}
