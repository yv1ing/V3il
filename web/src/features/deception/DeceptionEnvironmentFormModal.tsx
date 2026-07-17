import { Button, Input, Select, TextArea, Toast } from "@douyinfe/semi-ui";
import { FileUp, Link2, Plus, Radar, Trash2 } from "lucide-react";
import { ChangeEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  DECEPTION_ADAPTATION_MODE,
  DECEPTION_ADAPTATION_MODE_VALUES,
  MAX_DECEPTION_REFERENCE_FILE_BYTES,
  MAX_DECEPTION_REFERENCE_FILES,
  MAX_DECEPTION_REFERENCE_TOTAL_BYTES,
  MAX_DECEPTION_REFERENCE_URL_LENGTH,
  MAX_DECEPTION_REFERENCE_URLS,
  SANDBOX_CONTAINER_EGRESS_MODE,
} from "../../shared/api/generated/constants";
import type {
  CreateDeceptionEnvironmentRequest,
  EgressProxy,
  SandboxContainer,
  SandboxContainerHostOption,
  SandboxImage,
} from "../../shared/api/types";
import { FormField } from "../../shared/components/FormField";
import { OptionListSelect } from "../../shared/components/OptionListSelect";
import { ResourceModal } from "../../shared/components/ResourceModal";
import type { OptionListResult } from "../../shared/hooks/useOptionList";
import { formatEnumLabel } from "../../shared/lib/labels";
import {
  egressProxyOption,
  sandboxContainerOption,
  sandboxEgressModeOptions,
  sandboxHostOption,
  sandboxImageOption,
} from "../../shared/lib/sandboxOptions";

type Props = {
  open: boolean;
  saving: boolean;
  containers: OptionListResult<SandboxContainer>;
  hosts: OptionListResult<SandboxContainerHostOption>;
  images: OptionListResult<SandboxImage>;
  proxies: OptionListResult<EgressProxy>;
  onCancel: () => void;
  onSubmit: (payload: CreateDeceptionEnvironmentRequest) => Promise<void>;
};

const EMPTY: CreateDeceptionEnvironmentRequest = {
  name: "",
  description: "",
  sandbox_container_id: null,
  host_id: 0,
  image_id: 0,
  egress_mode: SANDBOX_CONTAINER_EGRESS_MODE.DIRECT,
  egress_proxy_id: null,
  adaptation_mode: DECEPTION_ADAPTATION_MODE.POLICY_AUTO,
  reference_urls: [],
  files: [],
};

export function DeceptionEnvironmentFormModal({
  open,
  saving,
  containers,
  hosts,
  images,
  proxies,
  onCancel,
  onSubmit,
}: Props) {
  const [values, setValues] = useState<CreateDeceptionEnvironmentRequest>(EMPTY);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setValues({ ...EMPTY, reference_urls: [], files: [] });
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  }, [open]);

  const selectedImage = useMemo(
    () => images.knownItems.find((image) => image.id === values.image_id),
    [images.knownItems, values.image_id],
  );
  const selectedContainer = useMemo(
    () => containers.knownItems.find((container) => container.id === values.sandbox_container_id),
    [containers.knownItems, values.sandbox_container_id],
  );
  const containerSelected = values.sandbox_container_id != null;
  const egressOptions = sandboxEgressModeOptions({
    includeProxy: proxies.knownItems.length > 0,
    supportsTor: Boolean(selectedContainer?.supports_tor ?? selectedImage?.supports_tor),
  });
  const referenceUrls = values.reference_urls ?? [];
  const files = values.files ?? [];
  const invalidReferenceUrl = referenceUrls.some((url) => !isHttpReferenceUrl(url));
  const disabled = !values.name.trim()
    || values.host_id < 1
    || values.image_id < 1
    || invalidReferenceUrl
    || (values.egress_mode === SANDBOX_CONTAINER_EGRESS_MODE.PROXY && !values.egress_proxy_id);

  const selectContainer = (sandbox_container_id: unknown) => {
    if (typeof sandbox_container_id !== "number") {
      setValues((current) => ({ ...current, sandbox_container_id: null }));
      return;
    }
    const container = containers.knownItems.find((item) => item.id === sandbox_container_id);
    if (!container) return;
    setValues((current) => ({
      ...current,
      sandbox_container_id,
      host_id: container.host_id,
      image_id: container.image_id,
      egress_mode: container.egress_mode,
      egress_proxy_id: container.egress_proxy_id,
    }));
  };

  const selectFiles = (event: ChangeEvent<HTMLInputElement>) => {
    const selected = Array.from(event.target.files ?? []);
    event.target.value = "";
    if (!selected.length) return;
    const next = [...files];
    const names = new Set(next.map((file) => file.name.toLocaleLowerCase()));
    let totalBytes = next.reduce((sum, file) => sum + file.size, 0);
    for (const file of selected) {
      if (next.length >= MAX_DECEPTION_REFERENCE_FILES) {
        Toast.warning(`At most ${MAX_DECEPTION_REFERENCE_FILES} reference files are allowed`);
        break;
      }
      if (names.has(file.name.toLocaleLowerCase())) {
        Toast.warning(`${file.name} is already selected`);
        continue;
      }
      if (file.size === 0) {
        Toast.warning(`${file.name} is empty`);
        continue;
      }
      if (file.size > MAX_DECEPTION_REFERENCE_FILE_BYTES) {
        Toast.warning(`${file.name} exceeds ${formatBytes(MAX_DECEPTION_REFERENCE_FILE_BYTES)}`);
        continue;
      }
      if (totalBytes + file.size > MAX_DECEPTION_REFERENCE_TOTAL_BYTES) {
        Toast.warning(`Reference files exceed ${formatBytes(MAX_DECEPTION_REFERENCE_TOTAL_BYTES)} in total`);
        break;
      }
      names.add(file.name.toLocaleLowerCase());
      totalBytes += file.size;
      next.push(file);
    }
    setValues((current) => ({ ...current, files: next }));
  };

  return (
    <ResourceModal
      open={open}
      title="Create Deception Environment"
      titleIcon={<Radar size={17} />}
      saving={saving}
      submitLabel="Create and open Console"
      submitDisabled={disabled}
      size="wide"
      onCancel={onCancel}
      onSubmit={() => onSubmit({
        ...values,
        name: values.name.trim(),
        description: values.description.trim(),
        reference_urls: referenceUrls.map((url) => url.trim()),
        files,
      })}
    >
      <div className="form-section-title">Environment context</div>
      <div className="form-grid-two">
        <FormField label="Name">
          <Input value={values.name} maxLength={255} onChange={(name) => setValues((current) => ({ ...current, name }))} />
        </FormField>
        <FormField label="Adaptation mode">
          <Select
            value={values.adaptation_mode}
            optionList={DECEPTION_ADAPTATION_MODE_VALUES.map((value) => ({ label: formatEnumLabel(value), value }))}
            onChange={(adaptation_mode) => typeof adaptation_mode === "string" && setValues((current) => ({ ...current, adaptation_mode }))}
          />
        </FormField>
      </div>
      <FormField label="Description">
        <TextArea
          value={values.description}
          rows={3}
          maxLength={4000}
          placeholder="Record the environment's purpose and operator-facing notes. Describe the actual build later in the Console."
          onChange={(description) => setValues((current) => ({ ...current, description }))}
        />
      </FormField>

      <div className="form-section-title">Operator-selected infrastructure</div>
      <FormField label="Existing sandbox container (optional)">
        <div className="workspace-tab-stack">
          <OptionListSelect
            source={containers}
            value={values.sandbox_container_id ?? undefined}
            optionList={containers.items.map(sandboxContainerOption)}
            filter
            showClear
            emptyContent="No available running containers"
            placeholder="Select a running, unbound container or provision one later"
            onChange={selectContainer}
          />
          <small>
            A selected container is dedicated to this environment and must already expose at least one service port.
            Leave this empty to let V3il create a container from the configuration below during initial deployment.
          </small>
        </div>
      </FormField>
      <div className="form-grid-two">
        <FormField label="Managed host">
          <OptionListSelect
            source={hosts}
            disabled={containerSelected}
            value={values.host_id || undefined}
            optionList={hosts.items.map(sandboxHostOption)}
            filter
            showClear
            placeholder="Select a managed host"
            onChange={(host_id) => setValues((current) => ({ ...current, host_id: typeof host_id === "number" ? host_id : 0 }))}
          />
        </FormField>
        <FormField label="Sandbox image">
          <OptionListSelect
            source={images}
            disabled={containerSelected}
            value={values.image_id || undefined}
            optionList={images.items.map(sandboxImageOption)}
            filter
            showClear
            placeholder="Select an image manually"
            onChange={(image_id) => setValues((current) => ({ ...current, image_id: typeof image_id === "number" ? image_id : 0 }))}
          />
        </FormField>
      </div>
      <div className="form-grid-two">
        <FormField label="Egress mode">
          <Select
            disabled={containerSelected}
            value={values.egress_mode}
            optionList={egressOptions}
            onChange={(egress_mode) => typeof egress_mode === "string" && setValues((current) => ({
              ...current,
              egress_mode,
              egress_proxy_id: egress_mode === SANDBOX_CONTAINER_EGRESS_MODE.PROXY ? current.egress_proxy_id : null,
            }))}
          />
        </FormField>
        <FormField label="Egress proxy">
          <OptionListSelect
            source={proxies}
            disabled={containerSelected || values.egress_mode !== SANDBOX_CONTAINER_EGRESS_MODE.PROXY}
            value={values.egress_proxy_id ?? undefined}
            optionList={proxies.items.map(egressProxyOption)}
            filter
            showClear
            placeholder="Select a proxy"
            onChange={(egress_proxy_id) => setValues((current) => ({
              ...current,
              egress_proxy_id: typeof egress_proxy_id === "number" ? egress_proxy_id : null,
            }))}
          />
        </FormField>
      </div>

      <div className="form-section-title">Optional reference material</div>
      <FormField label="Reference site URLs">
        <div className="workspace-tab-stack">
          {referenceUrls.map((url, index) => (
            <div className="resource-inline-cell" key={index}>
              <Link2 size={15} />
              <Input
                value={url}
                maxLength={MAX_DECEPTION_REFERENCE_URL_LENGTH}
                validateStatus={url && !isHttpReferenceUrl(url) ? "error" : "default"}
                placeholder="https://reference.example"
                onChange={(nextUrl) => setValues((current) => ({
                  ...current,
                  reference_urls: (current.reference_urls ?? []).map((item, itemIndex) => itemIndex === index ? nextUrl : item),
                }))}
              />
              <Button
                theme="borderless"
                type="tertiary"
                icon={<Trash2 size={15} />}
                aria-label={`Remove reference URL ${index + 1}`}
                onClick={() => setValues((current) => ({
                  ...current,
                  reference_urls: (current.reference_urls ?? []).filter((_, itemIndex) => itemIndex !== index),
                }))}
              />
            </div>
          ))}
          {referenceUrls.length < MAX_DECEPTION_REFERENCE_URLS ? (
            <Button
              icon={<Plus size={15} />}
              onClick={() => setValues((current) => ({
                ...current,
                reference_urls: [...(current.reference_urls ?? []), ""],
              }))}
            >Add reference URL</Button>
          ) : null}
        </div>
      </FormField>
      <FormField label="Reference files">
        <input ref={fileInputRef} hidden type="file" multiple onChange={selectFiles} />
        <div className="workspace-tab-stack">
          <Button icon={<FileUp size={15} />} onClick={() => fileInputRef.current?.click()}>
            Select code, archives, or other files
          </Button>
          <small>
            Up to {MAX_DECEPTION_REFERENCE_FILES} files, {formatBytes(MAX_DECEPTION_REFERENCE_FILE_BYTES)} each,
            {" "}{formatBytes(MAX_DECEPTION_REFERENCE_TOTAL_BYTES)} total. Files are staged on disk and copied into the dedicated container.
          </small>
          {files.length ? (
            <div className="compact-records">
              {files.map((file, index) => (
                <article key={`${file.name}:${file.lastModified}`}>
                  <header>
                    <strong>{file.name}</strong>
                    <Button
                      theme="borderless"
                      type="tertiary"
                      icon={<Trash2 size={14} />}
                      aria-label={`Remove ${file.name}`}
                      onClick={() => setValues((current) => ({
                        ...current,
                        files: (current.files ?? []).filter((_, itemIndex) => itemIndex !== index),
                      }))}
                    />
                  </header>
                  <small>{file.type || "application/octet-stream"} · {formatBytes(file.size)}</small>
                </article>
              ))}
            </div>
          ) : null}
        </div>
      </FormField>
    </ResourceModal>
  );
}

function isHttpReferenceUrl(value: string) {
  try {
    const url = new URL(value.trim());
    return (url.protocol === "http:" || url.protocol === "https:") && Boolean(url.host);
  } catch {
    return false;
  }
}

function formatBytes(value: number) {
  if (value >= 1024 * 1024) return `${Math.round(value / (1024 * 1024))} MiB`;
  if (value >= 1024) return `${Math.round(value / 1024)} KiB`;
  return `${value} B`;
}
