import { Tag } from "@douyinfe/semi-ui";
import { Pencil, Users } from "lucide-react";
import { useMemo, useState } from "react";
import { createSystemUser, querySystemUsers, retireSystemUser, updateSystemUser } from "../../shared/api/systemUsers";
import { SYSTEM_USER_ROLE, SYSTEM_USER_ROLE_VALUES } from "../../shared/api/generated/constants";
import type { CreateSystemUserRequest, SystemUser, UpdateSystemUserRequest } from "../../shared/api/types";
import { PagedResourceTable } from "../../shared/components/PagedResourceTable";
import type { ResourceColumn } from "../../shared/components/ResourceTable";
import { ResourceIdentity, ResourceSecretText, RetireRowAction, RowActionButton, RowActions } from "../../shared/components/ResourceCells";
import { useAdminResourceHeader } from "../../shared/hooks/useAdminResourceHeader";
import { usePagedResourceList } from "../../shared/hooks/usePagedResourceList";
import { useResourceAction } from "../../shared/hooks/useResourceAction";
import { useResourceSubmit } from "../../shared/hooks/useResourceSubmit";
import { formatDateTime } from "../../shared/lib/date";
import { countBy } from "../../shared/lib/array";
import { SYSTEM_USER_ROLE_COLOR, SYSTEM_USER_ROLE_LABEL } from "../../shared/lib/labels";
import { UserFormModal } from "./UserFormModal";

type ModalState = { mode: "create" } | { mode: "edit"; user: SystemUser } | null;

export function SystemUsersPage() {
  const users = usePagedResourceList<SystemUser>({ query: querySystemUsers });
  const [modal, setModal] = useState<ModalState>(null);
  const { run: retireUser, busyId: retiringUserId } = useResourceAction<SystemUser>(
    (user) => retireSystemUser(user.id),
    users.loadItems,
  );

  useAdminResourceHeader({
    createLabel: "Create User",
    refreshLabel: "Refresh users",
    loading: users.loading,
    onCreate: () => setModal({ mode: "create" }),
    onRefresh: users.loadItems,
  });

  const { saving, submit } = useResourceSubmit({
    onSuccess: async () => {
      setModal(null);
      await users.loadItems();
    },
  });

  const summary = useMemo(() => countBy(users.items, SYSTEM_USER_ROLE_VALUES, (user) => user.role), [users.items]);

  const columns: ResourceColumn<SystemUser>[] = [
    {
      key: "user", header: "User", width: "minmax(220px, 300px)",
      render: (user) => (
        <ResourceIdentity icon={user.username.slice(0, 1).toUpperCase()} title={user.username} detail={user.email || "-"} />
      ),
    },
    {
      key: "role", header: "Role", width: "190px",
      render: (user) => <Tag color={SYSTEM_USER_ROLE_COLOR[user.role]}>{SYSTEM_USER_ROLE_LABEL[user.role]}</Tag>,
    },
    {
      key: "password", header: "Password", width: "minmax(160px, 0.8fr)",
      render: (user) => <ResourceSecretText value={user.password} />,
    },
    { key: "created", header: "Created", width: "minmax(150px, 1fr)", render: (u) => formatDateTime(u.created_at) },
    { key: "updated", header: "Updated", width: "minmax(150px, 1fr)", render: (u) => formatDateTime(u.updated_at) },
    {
      key: "actions", header: "Actions", width: "104px",
      render: (user) => (
        <RowActions>
          <RowActionButton icon={<Pencil size={15} />} label={`Edit ${user.username}`}
            onClick={() => setModal({ mode: "edit", user })}
          />
          <RetireRowAction title="Retire user" content={`Retire ${user.username}?`} label={`Retire ${user.username}`}
            loading={retiringUserId === user.id} onConfirm={() => void retireUser(user)}
          />
        </RowActions>
      ),
    },
  ];

  return (
    <>
      <PagedResourceTable
        ariaLabel="System users"
        columns={columns}
        rows={users.items}
        rowKey={(user) => user.id}
        searchPlaceholder="Search username or email"
        state={users}
        metrics={[
          { label: "Total", value: users.total },
          { label: "Admins", value: summary[SYSTEM_USER_ROLE.ADMIN] },
          { label: "Users", value: summary[SYSTEM_USER_ROLE.USER] },
        ]}
        emptyIcon={<Users size={42} />}
        emptyTitle="No users found"
      />

      <UserFormModal
        open={Boolean(modal)}
        user={modal?.mode === "edit" ? modal.user : null}
        saving={saving}
        onCancel={() => setModal(null)}
        onCreate={(payload: CreateSystemUserRequest) => submit(() => createSystemUser(payload))}
        onUpdate={(user, payload: UpdateSystemUserRequest) => submit(() => updateSystemUser(user.id, payload))}
      />
    </>
  );
}
