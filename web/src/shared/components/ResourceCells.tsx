import { Button, Popconfirm } from "@douyinfe/semi-ui";
import { Eye, EyeOff, Trash2, User } from "lucide-react";
import { useState, type ComponentProps, type ReactNode } from "react";
import { UI_TEXT } from "../lib/uiText";

type ResourceIdentityProps = {
  before?: ReactNode;
  icon?: ReactNode;
  title: ReactNode;
  detail?: ReactNode;
};

export function ResourceIdentity({ before, detail, icon, title }: ResourceIdentityProps) {
  return (
    <div className="resource-identity">
      {before}
      {icon ? <div className="resource-avatar">{icon}</div> : null}
      <div>
        <strong>{title}</strong>
        {detail ? <span>{detail}</span> : null}
      </div>
    </div>
  );
}

export function OwnerCell({ children }: { children: ReactNode }) {
  return (
    <span className="resource-inline-cell">
      <User size={13} />
      {children}
    </span>
  );
}

export function ResourceText({ children, title }: { children: ReactNode; title?: string }) {
  return <span className="resource-description" title={title}>{children}</span>;
}

export function ResourceSecretText({ value }: { value: string }) {
  const [visible, setVisible] = useState(false);
  if (!value) return <ResourceText>-</ResourceText>;

  return (
    <span className="resource-secret-cell">
      <ResourceText title={visible ? value : undefined}>{visible ? value : "********"}</ResourceText>
      <Button
        aria-label={visible ? "Hide value" : "Show value"}
        aria-pressed={visible}
        icon={visible ? <EyeOff size={14} /> : <Eye size={14} />}
        size="small"
        theme="borderless"
        type="tertiary"
        onClick={() => setVisible((current) => !current)}
      />
    </span>
  );
}

export function RowActions({ children }: { children: ReactNode }) {
  return <div className="row-actions">{children}</div>;
}

type ButtonProps = NonNullable<ComponentProps<typeof Button>>;

type RowActionButtonProps = Omit<ButtonProps, "aria-label" | "icon" | "theme"> & {
  icon: ReactNode;
  label: string;
};

export function RowActionButton({ icon, label, type = "tertiary", ...props }: RowActionButtonProps) {
  return <Button {...props} icon={icon} theme="borderless" type={type} aria-label={label} />;
}

type DeleteRowActionProps = Partial<Pick<ButtonProps, "disabled" | "loading" | "size">> & {
  content: ReactNode;
  label: string;
  title: ReactNode;
  onConfirm: () => void | Promise<void>;
};

export function DeleteRowAction({ content, label, onConfirm, title, ...buttonProps }: DeleteRowActionProps) {
  const iconSize = buttonProps.size === "small" ? 14 : 15;
  return (
    <Popconfirm title={title} content={content} okType="danger" cancelText={UI_TEXT.cancel} onConfirm={onConfirm}>
      <Button {...buttonProps} icon={<Trash2 size={iconSize} />} theme="borderless" type="danger" aria-label={label} />
    </Popconfirm>
  );
}
