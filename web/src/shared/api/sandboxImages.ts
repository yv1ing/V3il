import { defineJsonEndpoint } from "./client";
import { buildQuery } from "./query";
import type {
  CreateSandboxImageRequest,
  CreateSandboxImageResponse,
  QuerySandboxImagesParams,
  QuerySandboxImagesResponse,
  RetireSandboxImageResponse,
  SandboxImagePathParams,
} from "./types";

const SANDBOX_IMAGES_PATH = "/api/sandbox-images";

export const querySandboxImages = defineJsonEndpoint<[params: QuerySandboxImagesParams], QuerySandboxImagesResponse>(
  "GET", (params) => `${SANDBOX_IMAGES_PATH}${buildQuery(params)}`,
);
export const createSandboxImage = defineJsonEndpoint<[payload: CreateSandboxImageRequest], CreateSandboxImageResponse>(
  "POST", () => SANDBOX_IMAGES_PATH, (payload) => payload,
);
export const retireSandboxImage = defineJsonEndpoint<[id: SandboxImagePathParams["id"]], RetireSandboxImageResponse>(
  "POST", (id) => `${SANDBOX_IMAGES_PATH}/${id}/retire`,
);
