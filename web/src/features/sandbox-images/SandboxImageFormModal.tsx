import { Input, InputNumber, Select } from "@douyinfe/semi-ui";
import { Network, Package, Route } from "lucide-react";
import { useEffect, useState } from "react";
import { FIELD_CONSTRAINTS, FIELD_DEFAULTS } from "../../shared/api/generated/constants";
import type { CreateSandboxImageRequest } from "../../shared/api/types";
import { FormField } from "../../shared/components/FormField";
import { ResourceModal } from "../../shared/components/ResourceModal";

type SandboxImageFormModalProps = {
  open: boolean;
  saving: boolean;
  onCancel: () => void;
  onSubmit: (payload: CreateSandboxImageRequest) => Promise<void>;
};

const EMPTY: CreateSandboxImageRequest = {
  image_name: "deception-runtime:latest",
  control_proxy_port: FIELD_DEFAULTS.CreateSandboxImageRequest.control_proxy_port,
  supports_tor: FIELD_DEFAULTS.CreateSandboxImageRequest.supports_tor,
};
const IMAGE_CONSTRAINTS = FIELD_CONSTRAINTS.CreateSandboxImageRequest;

export function SandboxImageFormModal({ open, saving, onCancel, onSubmit }: SandboxImageFormModalProps) {
  const [values, setValues] = useState<CreateSandboxImageRequest>(EMPTY);

  useEffect(() => {
    if (open) setValues(EMPTY);
  }, [open]);

  return (
    <ResourceModal
      open={open}
      title="Create Sandbox Image"
      titleIcon={<Package size={17} />}
      saving={saving}
      submitLabel="Create"
      submitDisabled={
        !values.image_name.trim()
        || values.control_proxy_port < IMAGE_CONSTRAINTS.control_proxy_port.minimum
        || values.control_proxy_port > IMAGE_CONSTRAINTS.control_proxy_port.maximum
      }
      onCancel={onCancel}
      onSubmit={() => onSubmit({
        image_name: values.image_name.trim(),
        control_proxy_port: values.control_proxy_port,
        supports_tor: values.supports_tor,
      })}
    >
      <FormField label="Image Name">
        <Input prefix={<Package size={16} />} value={values.image_name}
          placeholder="ghcr.io/org/image:latest" maxLength={IMAGE_CONSTRAINTS.image_name.maxLength} required
          onChange={(image_name) => setValues((current) => ({ ...current, image_name }))}
        />
      </FormField>
      <FormField label="Control Port">
        <InputNumber
          prefix={<Network size={16} />}
          value={values.control_proxy_port}
          min={IMAGE_CONSTRAINTS.control_proxy_port.minimum}
          max={IMAGE_CONSTRAINTS.control_proxy_port.maximum}
          onChange={(control_proxy_port) => {
            if (typeof control_proxy_port === "number") setValues((current) => ({ ...current, control_proxy_port }));
          }}
        />
      </FormField>
      <FormField label="Tor">
        <Select
          prefix={<Route size={16} />}
          value={values.supports_tor ? "supported" : "unsupported"}
          optionList={[
            { label: "Unsupported", value: "unsupported" },
            { label: "Supported", value: "supported" },
          ]}
          onChange={(value) => {
            if (value === "supported" || value === "unsupported") {
              setValues((current) => ({ ...current, supports_tor: value === "supported" }));
            }
          }}
        />
      </FormField>
    </ResourceModal>
  );
}
