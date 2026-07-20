import { Input, Select } from "@douyinfe/semi-ui";
import { KeyRound, Mail, Shield, User, UserRound } from "lucide-react";
import { useEffect, useState } from "react";
import { getSystemUserRoles, isSystemUserRole } from "../../shared/api/contract";
import { FIELD_CONSTRAINTS, SYSTEM_USER_ROLE } from "../../shared/api/generated/constants";
import type { CreateSystemUserRequest, SystemUser, SystemUserRole, UpdateSystemUserRequest } from "../../shared/api/types";
import { FormField } from "../../shared/components/FormField";
import { ResourceModal } from "../../shared/components/ResourceModal";
import { SYSTEM_USER_ROLE_LABEL } from "../../shared/lib/labels";

type UserFormValues = {
  username: string;
  email: string;
  password: string;
  role: SystemUserRole;
};

type UserFormModalProps = {
  open: boolean;
  user: SystemUser | null;
  saving: boolean;
  onCancel: () => void;
  onCreate: (payload: CreateSystemUserRequest) => Promise<void>;
  onUpdate: (user: SystemUser, payload: UpdateSystemUserRequest) => Promise<void>;
};

const EMPTY: UserFormValues = { username: "", email: "", password: "", role: SYSTEM_USER_ROLE.USER };
const ROLES = getSystemUserRoles();
const USER_CONSTRAINTS = FIELD_CONSTRAINTS.CreateSystemUserRequest;

function initial(user: SystemUser | null): UserFormValues {
  if (!user) return EMPTY;
  return { username: user.username, email: user.email, password: user.password, role: user.role };
}

export function UserFormModal({ open, user, saving, onCancel, onCreate, onUpdate }: UserFormModalProps) {
  const [values, setValues] = useState<UserFormValues>(() => initial(user));
  const editing = Boolean(user);

  useEffect(() => {
    if (open) setValues(initial(user));
  }, [open, user]);

  const submit = async () => {
    const base = { username: values.username.trim(), email: values.email.trim(), role: values.role };
    if (!user) await onCreate({ ...base, password: values.password });
    else await onUpdate(user, { ...base, password: values.password });
  };

  return (
    <ResourceModal
      open={open}
      title={editing ? "Edit User" : "Create User"}
      titleIcon={<UserRound size={17} />}
      saving={saving}
      submitLabel={editing ? "Save" : "Create"}
      onCancel={onCancel}
      onSubmit={submit}
    >
      <FormField label="Username">
        <Input prefix={<User size={16} />} value={values.username} maxLength={USER_CONSTRAINTS.username.maxLength} required
          onChange={(username) => setValues((v) => ({ ...v, username }))}
        />
      </FormField>
      <FormField label="Email">
        <Input type="email" prefix={<Mail size={16} />} value={values.email} maxLength={USER_CONSTRAINTS.email.maxLength}
          onChange={(email) => setValues((v) => ({ ...v, email }))}
        />
      </FormField>
      <FormField label="Role">
        <Select prefix={<Shield size={16} />} value={values.role}
          onChange={(role) => isSystemUserRole(role) && setValues((v) => ({ ...v, role }))}
          optionList={ROLES.map((role) => ({ label: SYSTEM_USER_ROLE_LABEL[role], value: role }))}
        />
      </FormField>
      <FormField label="Password">
        <Input mode="password" prefix={<KeyRound size={16} />} value={values.password} maxLength={USER_CONSTRAINTS.password.maxLength}
          required
          placeholder="Password"
          onChange={(password) => setValues((v) => ({ ...v, password }))}
        />
      </FormField>
    </ResourceModal>
  );
}
