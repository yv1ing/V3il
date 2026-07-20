import { Tag } from "@douyinfe/semi-ui";
import { Boxes, Network, Route } from "lucide-react";
import { useMemo, useState } from "react";
import { createSandboxImage, querySandboxImages, retireSandboxImage } from "../../shared/api/sandboxImages";
import type { CreateSandboxImageRequest, SandboxImage } from "../../shared/api/types";
import { PagedResourceTable } from "../../shared/components/PagedResourceTable";
import type { ResourceColumn } from "../../shared/components/ResourceTable";
import { ResourceIdentity, ResourceText, RetireRowAction, RowActions } from "../../shared/components/ResourceCells";
import { useAdminResourceHeader } from "../../shared/hooks/useAdminResourceHeader";
import { usePagedResourceList } from "../../shared/hooks/usePagedResourceList";
import { useResourceAction } from "../../shared/hooks/useResourceAction";
import { useResourceSubmit } from "../../shared/hooks/useResourceSubmit";
import { formatDateTime } from "../../shared/lib/date";
import { SandboxImageFormModal } from "./SandboxImageFormModal";

export function SandboxImagesPage() {
  const images = usePagedResourceList<SandboxImage>({ query: querySandboxImages });
  const [modalOpen, setModalOpen] = useState(false);

  const { run: retireImage, busyId: retiringId } = useResourceAction<SandboxImage>(
    (image) => retireSandboxImage(image.id), images.loadItems,
  );

  useAdminResourceHeader({
    createLabel: "Create Image",
    refreshLabel: "Refresh sandbox images",
    loading: images.loading,
    onCreate: () => setModalOpen(true),
    onRefresh: images.loadItems,
  });

  const { saving, submit } = useResourceSubmit({
    onSuccess: async () => {
      setModalOpen(false);
      await images.loadItems();
    },
  });

  const torImageCount = useMemo(() => images.items.filter((image) => image.supports_tor).length, [images.items]);

  const handleCreate = (payload: CreateSandboxImageRequest) => submit(() => createSandboxImage(payload));

  const columns: ResourceColumn<SandboxImage>[] = [
    {
      key: "image", header: "Image", width: "minmax(280px, 360px)",
      render: (image) => (
        <ResourceIdentity
          icon={<Boxes size={18} />}
          title={image.image_name}
          detail={<><Network size={13} />Control port {image.control_proxy_port}</>}
        />
      ),
    },
    { key: "port", header: "Control Port", width: "130px", render: (image) => image.control_proxy_port },
    {
      key: "capabilities", header: "Capabilities", width: "180px",
      render: (image) => (
        <div className="port-mapping-list">
          {image.supports_tor ? <Tag color="violet" prefixIcon={<Route size={12} />}>Tor</Tag> : null}
          {!image.supports_tor ? <ResourceText>None</ResourceText> : null}
        </div>
      ),
    },
    { key: "created", header: "Created", width: "minmax(150px, 1fr)", render: (i) => formatDateTime(i.created_at) },
    { key: "updated", header: "Updated", width: "minmax(150px, 1fr)", render: (i) => formatDateTime(i.updated_at) },
    {
      key: "actions", header: "Actions", width: "104px",
      render: (image) => (
        <RowActions>
          <RetireRowAction title="Retire image" content={`Retire ${image.image_name}?`} label={`Retire ${image.image_name}`}
            loading={retiringId === image.id} onConfirm={() => void retireImage(image)}
          />
        </RowActions>
      ),
    },
  ];

  return (
    <>
      <PagedResourceTable
        ariaLabel="Sandbox images"
        columns={columns}
        rows={images.items}
        rowKey={(image) => image.id}
        searchPlaceholder="Search image name"
        state={images}
        metrics={[
          { label: "Total", value: images.total },
          { label: "Tor", value: torImageCount },
        ]}
        emptyIcon={<Boxes size={42} />}
        emptyTitle="No images found"
      />

      <SandboxImageFormModal
        open={modalOpen}
        saving={saving}
        onCancel={() => setModalOpen(false)}
        onSubmit={handleCreate}
      />
    </>
  );
}
