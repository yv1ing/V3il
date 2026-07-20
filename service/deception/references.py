import asyncio
import hashlib
import json
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from unicodedata import category
from uuid import uuid4

from fastapi import UploadFile

from logger import get_logger
from utils.time import utc_now
from schema.deception.environments import (
    DeceptionReferenceBundleSchema,
    DeceptionReferenceFileSchema,
    DeceptionReferenceFileState,
    MAX_DECEPTION_REFERENCE_FILE_BYTES,
    MAX_DECEPTION_REFERENCE_FILES,
    MAX_DECEPTION_REFERENCE_TOTAL_BYTES,
)
from service.sandbox.files import (
    ContainerUploadSource,
    create_container_directory,
    upload_container_files,
    write_container_file,
)


logger = get_logger(__name__)
REFERENCE_ROOT = Path(tempfile.gettempdir()) / "v3il" / "deception-references"
REFERENCE_CONTAINER_ROOT = "/opt/deception/reference"
REFERENCE_MANIFEST_NAME = "manifest.json"
MAX_REFERENCE_FILENAME_BYTES = 255
_COPY_CHUNK_BYTES = 1024 * 1024


class DeceptionReferenceError(ValueError):
    pass


@dataclass(frozen=True)
class StagedReferenceBundle:
    directory: Path
    files: tuple[DeceptionReferenceFileSchema, ...]


async def stage_reference_uploads(uploads: list[UploadFile]) -> StagedReferenceBundle:
    if len(uploads) > MAX_DECEPTION_REFERENCE_FILES:
        raise DeceptionReferenceError(
            f"at most {MAX_DECEPTION_REFERENCE_FILES} reference files may be uploaded"
        )
    await asyncio.to_thread(REFERENCE_ROOT.mkdir, parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix=".staging-", dir=REFERENCE_ROOT))
    files: list[DeceptionReferenceFileSchema] = []
    names: set[str] = set()
    total_size = 0
    try:
        for upload in uploads:
            filename = _validate_filename(upload.filename or "")
            normalized_name = filename.casefold()
            if normalized_name in names:
                raise DeceptionReferenceError("reference file names must be unique")
            names.add(normalized_name)
            destination = directory / filename
            await upload.seek(0)
            size, sha256 = await asyncio.to_thread(
                _copy_upload,
                upload.file,
                destination,
                MAX_DECEPTION_REFERENCE_FILE_BYTES,
            )
            total_size += size
            if total_size > MAX_DECEPTION_REFERENCE_TOTAL_BYTES:
                raise DeceptionReferenceError(
                    f"reference files exceed the {MAX_DECEPTION_REFERENCE_TOTAL_BYTES // (1024 * 1024)} MiB total limit"
                )
            files.append(DeceptionReferenceFileSchema(
                filename=filename,
                media_type=(upload.content_type or "application/octet-stream")[:255],
                size=size,
                sha256=sha256,
                container_path=f"{REFERENCE_CONTAINER_ROOT}/{filename}",
            ))
    except BaseException:
        await asyncio.to_thread(shutil.rmtree, directory, True)
        raise
    return StagedReferenceBundle(directory=directory, files=tuple(files))


async def commit_staged_reference_bundle(
    staged: StagedReferenceBundle,
    environment_id: int,
    reference_urls: list[str],
) -> DeceptionReferenceBundleSchema:
    bundle = DeceptionReferenceBundleSchema(
        environment_id=environment_id,
        reference_urls=reference_urls,
        files=list(staged.files),
    )
    destination = _environment_directory(environment_id)
    await asyncio.to_thread(_commit_bundle, staged.directory, destination, bundle)
    return bundle


async def discard_staged_reference_bundle(staged: StagedReferenceBundle | None) -> None:
    if staged is not None:
        await asyncio.to_thread(shutil.rmtree, staged.directory, True)


async def delete_reference_bundle(environment_id: int) -> None:
    await asyncio.to_thread(shutil.rmtree, _environment_directory(environment_id), True)


async def load_reference_bundle(
    environment_id: int,
    reference_urls: list[str] | None = None,
) -> DeceptionReferenceBundleSchema:
    try:
        bundle = await _require_reference_bundle(environment_id)
    except FileNotFoundError:
        return DeceptionReferenceBundleSchema(
            environment_id=environment_id,
            reference_urls=reference_urls or [],
        )
    except Exception:
        logger.exception("invalid deception reference manifest: environment=%s", environment_id)
        return DeceptionReferenceBundleSchema(
            environment_id=environment_id,
            reference_urls=reference_urls or [],
        )
    if reference_urls is not None:
        bundle = bundle.model_copy(update={"reference_urls": reference_urls})
    return bundle


async def copy_reference_bundle_to_container(
    environment_id: int,
    reference_urls: list[str],
    container_id: int,
) -> DeceptionReferenceBundleSchema:
    bundle = await _require_reference_bundle(environment_id)
    bundle = bundle.model_copy(update={"reference_urls": reference_urls})
    directory = _environment_directory(environment_id)
    source_paths: list[tuple[str, Path]] = []
    for item in bundle.files:
        if item.state != DeceptionReferenceFileState.STAGED:
            raise DeceptionReferenceError(
                f"reference file is not staged for copying: {item.filename}"
            )
        source_path = directory / item.filename
        if source_path.is_symlink() or not source_path.is_file():
            raise FileNotFoundError(f"staged reference file is unavailable: {item.filename}")
        size, sha256 = await asyncio.to_thread(_file_digest, source_path)
        if size != item.size or sha256 != item.sha256:
            raise DeceptionReferenceError(
                f"staged reference file integrity check failed: {item.filename}"
            )
        source_paths.append((item.filename, source_path))
    await create_container_directory(container_id, REFERENCE_CONTAINER_ROOT)
    if source_paths:
        sources: list[ContainerUploadSource] = []
        try:
            for filename, source_path in source_paths:
                sources.append(ContainerUploadSource(
                    filename=filename,
                    stream=source_path.open("rb"),
                ))
        except BaseException:
            for source in sources:
                source.stream.close()
            raise
        await upload_container_files(
            container_id,
            REFERENCE_CONTAINER_ROOT,
            sources,
            overwrite=True,
        )
    container_manifest = bundle.model_dump(mode="json")
    container_manifest["copied_container_id"] = container_id
    await write_container_file(
        container_id,
        f"{REFERENCE_CONTAINER_ROOT}/{REFERENCE_MANIFEST_NAME}",
        json.dumps(container_manifest, ensure_ascii=False, indent=2),
    )
    return bundle


async def finalize_reference_bundle(environment_id: int, container_id: int) -> None:
    directory = _environment_directory(environment_id)
    bundle = await _require_reference_bundle(environment_id)
    copied_at = utc_now()
    files = [
        item.model_copy(update={
            "state": DeceptionReferenceFileState.COPIED,
            "copied_container_id": container_id,
            "copied_at": copied_at,
        })
        for item in bundle.files
    ]
    finalized = bundle.model_copy(update={"files": files})
    await asyncio.to_thread(_write_manifest, directory, finalized)
    for item in files:
        try:
            await asyncio.to_thread((directory / item.filename).unlink, missing_ok=True)
        except OSError:
            logger.warning(
                "could not remove staged deception reference file: environment=%s file=%s",
                environment_id,
                item.filename,
                exc_info=True,
            )


def _validate_filename(value: str) -> str:
    filename = Path(value.replace("\\", "/")).name.strip()
    if (
        not filename
        or filename in {".", "..", REFERENCE_MANIFEST_NAME}
        or any(category(character) in {"Cc", "Cf", "Cs"} for character in filename)
        or len(filename.encode("utf-8")) > MAX_REFERENCE_FILENAME_BYTES
    ):
        raise DeceptionReferenceError("reference file name is invalid")
    return filename


def _copy_upload(source, destination: Path, limit: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with destination.open("xb") as target:
        while chunk := source.read(_COPY_CHUNK_BYTES):
            size += len(chunk)
            if size > limit:
                raise DeceptionReferenceError(
                    f"reference file exceeds the {limit // (1024 * 1024)} MiB limit"
                )
            digest.update(chunk)
            target.write(chunk)
    if size == 0:
        raise DeceptionReferenceError("reference files must not be empty")
    return size, digest.hexdigest()


def _file_digest(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(_COPY_CHUNK_BYTES):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


async def _require_reference_bundle(environment_id: int) -> DeceptionReferenceBundleSchema:
    manifest_path = _manifest_path(environment_id)
    payload = await asyncio.to_thread(manifest_path.read_text, encoding="utf-8")
    try:
        bundle = DeceptionReferenceBundleSchema.model_validate_json(payload)
    except Exception as exc:
        raise DeceptionReferenceError(
            f"deception reference manifest is invalid for environment {environment_id}"
        ) from exc
    if bundle.environment_id != environment_id:
        raise DeceptionReferenceError(
            f"deception reference manifest belongs to environment {bundle.environment_id}"
        )
    return bundle


def _environment_directory(environment_id: int) -> Path:
    return REFERENCE_ROOT / str(environment_id)


def _manifest_path(environment_id: int) -> Path:
    return _environment_directory(environment_id) / REFERENCE_MANIFEST_NAME


def _commit_bundle(
    staged_directory: Path,
    destination: Path,
    bundle: DeceptionReferenceBundleSchema,
) -> None:
    _write_manifest(staged_directory, bundle)
    if not destination.exists():
        staged_directory.replace(destination)
        return
    orphaned = destination.with_name(f".{destination.name}.orphan-{uuid4().hex}")
    destination.replace(orphaned)
    try:
        staged_directory.replace(destination)
    except BaseException:
        if not destination.exists() and orphaned.exists():
            orphaned.replace(destination)
        raise
    shutil.rmtree(orphaned, ignore_errors=True)


def _write_manifest(directory: Path, bundle: DeceptionReferenceBundleSchema) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    temporary = directory / f".{REFERENCE_MANIFEST_NAME}.tmp"
    temporary.write_text(bundle.model_dump_json(indent=2), encoding="utf-8")
    temporary.replace(directory / REFERENCE_MANIFEST_NAME)
