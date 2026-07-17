type PagedPayload<T> = {
  items: T[];
  page: number;
  size: number;
  total: number;
};

type PagedEnvelope<T> = {
  data?: PagedPayload<T> | null;
};


export async function collectAllPages<T>(loadPage: (page: number) => Promise<PagedEnvelope<T>>): Promise<T[]> {
  const first = (await loadPage(1)).data;
  if (!first) return [];
  const items = [...first.items];
  const pageCount = Math.ceil(first.total / first.size);
  for (let page = 2; page <= pageCount; page += 1) {
    const payload = (await loadPage(page)).data;
    if (!payload) throw new Error(`Paginated response is missing page ${page}`);
    items.push(...payload.items);
  }
  return items;
}
