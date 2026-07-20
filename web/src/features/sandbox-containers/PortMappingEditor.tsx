import { Button, InputNumber, Select } from "@douyinfe/semi-ui";
import { Plug, Plus, Trash2 } from "lucide-react";
import {
  FIELD_CONSTRAINTS,
  SANDBOX_CONTAINER_PROTOCOL,
  SANDBOX_CONTAINER_PROTOCOL_VALUES,
} from "../../shared/api/generated/constants";
import type { SandboxContainerPortMapping, SandboxContainerProtocol } from "../../shared/api/types";
import { createClientId } from "../../shared/lib/id";

export type PortMappingFormValue = SandboxContainerPortMapping & {
  id: string;
};

type PortMappingEditorProps = {
  mappings: PortMappingFormValue[];
  onAdd: () => void;
  onRemove: (id: string) => void;
  onChange: (id: string, patch: Partial<PortMappingFormValue>) => void;
};

const PROTOCOL_OPTIONS = SANDBOX_CONTAINER_PROTOCOL_VALUES.map((protocol) => ({
  label: protocol.toUpperCase(),
  value: protocol,
}));
const PROTOCOL_SET = new Set<string>(SANDBOX_CONTAINER_PROTOCOL_VALUES);
const PORT_CONSTRAINTS = FIELD_CONSTRAINTS.SandboxContainerPortMapping;

export function createEmptyPortMapping(): PortMappingFormValue {
  return {
    id: createClientId("port-mapping"),
    container_port: 8080,
    host_port: 8080,
    protocol: SANDBOX_CONTAINER_PROTOCOL.TCP,
  };
}

export function PortMappingEditor({
  mappings,
  onAdd,
  onRemove,
  onChange,
}: PortMappingEditorProps) {
  return (
    <div className="port-mapping-fieldset">
      <div className="port-mapping-heading">
        <span>Port Mappings</span>
        <div className="port-mapping-actions">
          <Button icon={<Plus size={14} />} theme="borderless" type="tertiary" onClick={onAdd}>
            Add
          </Button>
        </div>
      </div>
      {mappings.length === 0 ? (
        <div className="port-mapping-empty">No exposed ports</div>
      ) : mappings.map((mapping) => (
        <div className="port-mapping-row" key={mapping.id}>
          <InputNumber
            prefix={<Plug size={14} />}
            value={mapping.host_port}
            min={PORT_CONSTRAINTS.host_port.minimum}
            max={PORT_CONSTRAINTS.host_port.maximum}
            onChange={(value) => typeof value === "number" && onChange(mapping.id, { host_port: value })}
          />
          <span className="port-arrow">to</span>
          <InputNumber
            value={mapping.container_port}
            min={PORT_CONSTRAINTS.container_port.minimum}
            max={PORT_CONSTRAINTS.container_port.maximum}
            onChange={(value) => typeof value === "number" && onChange(mapping.id, { container_port: value })}
          />
          <Select
            value={mapping.protocol}
            optionList={PROTOCOL_OPTIONS}
            onChange={(value) => {
              if (typeof value === "string" && PROTOCOL_SET.has(value)) {
                onChange(mapping.id, { protocol: value as SandboxContainerProtocol });
              }
            }}
          />
          <Button
            icon={<Trash2 size={14} />}
            theme="borderless"
            type="danger"
            aria-label="Remove port mapping"
            onClick={() => onRemove(mapping.id)}
          />
        </div>
      ))}
    </div>
  );
}
