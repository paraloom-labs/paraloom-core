// USD prices for the Home portfolio, from Jupiter's price API.
// To protect user privacy and unlinkability in the shielded pool (#1577),
// fetchPrices queries a fixed canonical universe by default, preventing
// leaking the set of unspent shielded SPL token mints to third-party endpoints.

const JUP_PRICE_URL = "https://lite-api.jup.ag/price/v3"

// Wrapped-SOL mint — the price id for native SOL.
export const SOL_MINT = "So11111111111111111111111111111111111111112"

// USDC mint on Solana mainnet.
export const USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

// Canonical public mint universe fetched by default. Because every client
// queries the exact same set, third-party logs cannot infer private shielded holdings.
export const CANONICAL_PRICE_MINTS: readonly string[] = [
  SOL_MINT,
  USDC_MINT
] as const

export interface TokenPrice {
  usdPrice: number
  priceChange24h: number // percent, e.g. -0.19
}

export interface FetchPricesOptions {
  /**
   * If true, allows querying prices for arbitrary user-provided mints.
   * If false or omitted (default), queries are strictly restricted to the
   * canonical public mint set to prevent metadata leaks (#1577).
   */
  optIn?: boolean
}

/**
 * Derives the safe set of mint IDs to query from the external price API.
 * In default mode (no opt-in), returns the fixed canonical universe so that
 * the query is never holdings-derived.
 */
export function getSafePriceQueryMints(
  userMints: string[] = [],
  optIn = false
): string[] {
  if (optIn) {
    return Array.from(new Set([SOL_MINT, ...userMints]))
      .filter((m): m is string => typeof m === "string" && /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(m))
  }
  // Safe default: invariant fixed canonical universe regardless of held shielded set
  return Array.from(CANONICAL_PRICE_MINTS)
}

export async function fetchPrices(
  mints: string[] = [],
  options?: FetchPricesOptions
): Promise<Record<string, TokenPrice>> {
  const ids = getSafePriceQueryMints(mints, options?.optIn)
  if (ids.length === 0) return {}

  const ctrl = new AbortController()
  const t = setTimeout(() => ctrl.abort(), 8000)
  try {
    const encodedIds = ids.map(encodeURIComponent).join(",")
    const res = await fetch(`${JUP_PRICE_URL}?ids=${encodedIds}`, {
      signal: ctrl.signal
    })
    if (!res.ok) return {}
    const data = (await res.json()) as Record<
      string,
      { usdPrice?: number; priceChange24h?: number } | null
    >
    const out: Record<string, TokenPrice> = {}
    if (data && typeof data === "object") {
      for (const [mint, v] of Object.entries(data)) {
        if (
          v &&
          typeof v.usdPrice === "number" &&
          Number.isFinite(v.usdPrice) &&
          v.usdPrice >= 0
        ) {
          out[mint] = {
            usdPrice: v.usdPrice,
            priceChange24h:
              typeof v.priceChange24h === "number" && Number.isFinite(v.priceChange24h)
                ? v.priceChange24h
                : 0
          }
        }
      }
    }
    return out
  } catch {
    return {}
  } finally {
    clearTimeout(t)
  }
}
