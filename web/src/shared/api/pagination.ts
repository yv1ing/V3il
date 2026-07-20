type PagedPayload<T> = {
  items: T[];
  page: number;
  size: number;
  total: number;
};

type PagedEnvelope<T> = {
  data?: PagedPayload<T> | null;
};

type PagedResponse<T> = PagedPayload<T> | PagedEnvelope<T>;

export async function collectAllPages<T>(loadPage: (page: number) => Promise<PagedResponse<T>>): Promise<T[]> {
  const first = pagedPayload(await loadPage(1));
  if (!first) return [];
  const items = [...first.items];
  const pageCount = Math.ceil(first.total / first.size);
  for (let page = 2; page <= pageCount; page += 1) {
    const payload = pagedPayload(await loadPage(page));
    if (!payload) throw new Error(`Paginated response is missing page ${page}`);
    items.push(...payload.items);
  }
  return items;
}

function pagedPayload<T>(response: PagedResponse<T>): PagedPayload<T> | null {
  return "items" in response ? response : response.data ?? null;
}
