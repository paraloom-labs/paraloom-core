/**
 * Price fetching with rigorous validation against NaN, Infinity, and negative values.
 */

export interface PriceResponse {
  [token: string]: number;
}

export async function fetchPrices(tokens: string[]): Promise<PriceResponse> {
  if (!tokens || tokens.length === 0) {
    return {};
  }

  const response = await fetch(`https://api.coingecko.com/api/v3/simple/price?ids=${tokens.join(',')}&vs_currencies=usd`);
  if (!response.ok) {
    throw new Error(`Failed to fetch prices: ${response.statusText}`);
  }

  const json = await response.json();
  const validated: PriceResponse = {};

  for (const token of tokens) {
    const rawPrice = json[token]?.usd;
    if (typeof rawPrice !== 'number' || Number.isNaN(rawPrice) || !Number.isFinite(rawPrice) || rawPrice < 0) {
      throw new Error(`Invalid or poisoned price received for token ${token}: ${rawPrice}`);
    }
    validated[token] = rawPrice;
  }

  return validated;
}
