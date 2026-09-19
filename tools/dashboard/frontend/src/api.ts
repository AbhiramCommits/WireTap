export async function getJson<T>(url: string): Promise<T> {
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`${url}: ${resp.status}`);
  return (await resp.json()) as T;
}

export const fetchRate = (minutes: number) =>
  getJson<[string, number][]>(
    `/api/rate?from=${Math.floor(Date.now() / 1000) - minutes * 60}&bucket=1`,
  );

export const fetchGaps = (n: number) => getJson<unknown[][]>(`/api/gaps?n=${n}`);

export const fetchTopSymbols = (n: number) =>
  getJson<[string, number][]>(`/api/top_symbols?n=${n}`);
