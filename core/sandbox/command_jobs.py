import asyncio

from core.runtime.context import AgentRuntimeContext
from config import get_config
from core.sandbox import command_output
from core.sandbox.command_output import COMMAND_TIMEOUT_ERROR
from logger import get_logger
from schema.sandbox.async_jobs import SandboxAsyncJobSnapshot, SandboxAsyncJobStatus
from service.runtime.leases import RuntimeLeaseLost, RuntimeLeaseUnavailable, runtime_lease
from service.sandbox import async_jobs
from service.sandbox.commands import (
    SandboxContainerCommandTerminationError,
    SandboxContainerCommandTimeoutError,
    execute_sandbox_container_command,
    terminate_sandbox_container_command,
)


logger = get_logger(__name__)
_LEASE_NAME = "sandbox-command-runtime"
_LEASE_TTL_SECONDS = 15
_POLL_SECONDS = 0.5
_OUTPUT_STAT_TIMEOUT_SECONDS = 30

_driver: asyncio.Task[None] | None = None
_executions: dict[str, asyncio.Task[None]] = {}


async def start_async_sandbox_runtime() -> None:
    global _driver
    if _driver is None:
        _driver = asyncio.create_task(_runtime_loop(), name="sandbox-command-runtime")


async def start_async_sandbox_command(
    *,
    run_id: str,
    context: AgentRuntimeContext,
    command: str,
    output_file: str,
    timeout_seconds: int,
) -> SandboxAsyncJobSnapshot:
    if context.sandbox_container_id is None or not context.run_id or not context.attempt_id:
        raise ValueError("sandbox command requires an active persisted Agent Run")
    return await async_jobs.create_async_job(
        run_id=run_id,
        waiting_run_id=context.run_id,
        session_id=context.session_id,
        attempt_id=context.attempt_id,
        investigation_task_id=context.investigation_task_id,
        command=command,
        output_file=output_file,
        timeout_seconds=timeout_seconds,
        execution_marker=command_output.execution_marker_for_run(run_id),
        sandbox_container_id=context.sandbox_container_id,
        sandbox_container_generation=context.sandbox_container_generation,
    )


async def cancel_async_sandbox_command(run_id: str) -> bool:
    return await async_jobs.cancel_async_job(
        run_id,
        "Sandbox command cancellation requested.",
    ) is not None


async def cancel_session_async_sandbox_commands(session_id: str) -> bool:
    snapshots = await async_jobs.cancel_running_async_jobs_for_session(
        session_id,
        "Agent session canceled.",
    )
    return bool(snapshots)


async def cancel_run_async_sandbox_commands(waiting_run_id: str) -> bool:
    snapshots = await async_jobs.cancel_running_async_jobs_for_run(
        waiting_run_id,
        "Agent Run canceled.",
    )
    return bool(snapshots)


async def cancel_sandbox_async_commands(container_id: int) -> bool:
    snapshots = await async_jobs.cancel_running_async_jobs_for_container(
        container_id,
        "Sandbox container stopped.",
    )
    return bool(snapshots)


async def stop_async_sandbox_commands() -> None:
    global _driver
    driver, _driver = _driver, None
    if driver is not None:
        driver.cancel()
        await asyncio.gather(driver, return_exceptions=True)


async def _runtime_loop() -> None:
    while True:
        try:
            async with runtime_lease(
                _LEASE_NAME,
                ttl_seconds=_LEASE_TTL_SECONDS,
                wait_timeout_seconds=1,
            ) as lease:
                await _recover_stale_jobs(lease)
                await _run_owned_jobs(lease)
        except asyncio.CancelledError:
            raise
        except RuntimeLeaseUnavailable:
            await asyncio.sleep(_POLL_SECONDS)
        except RuntimeLeaseLost:
            logger.warning("sandbox command runtime lease ownership changed")
        except Exception:
            logger.exception("sandbox command runtime iteration failed")
            await asyncio.sleep(_POLL_SECONDS)


async def _run_owned_jobs(lease) -> None:
    try:
        while True:
            await lease.assert_owned()
            await async_jobs.cancel_orphaned_queued_jobs(lease)
            await async_jobs.fail_unavailable_queued_jobs(lease)
            await _cancel_requested_jobs(lease)
            await async_jobs.resume_waiting_runs_with_finished_jobs(lease)
            capacity = get_config().agent_runtime.max_concurrent_sandbox_jobs - len(_executions)
            if capacity > 0:
                for job in await async_jobs.claim_queued_jobs(lease, limit=capacity):
                    task = asyncio.create_task(
                        _execute_owned_job(lease, job),
                        name=f"sandbox-command-{job.run_id}",
                    )
                    _executions[job.run_id] = task
                    task.add_done_callback(
                        lambda completed, run_id=job.run_id: _discard_execution(run_id, completed)
                    )
            await asyncio.sleep(_POLL_SECONDS)
    finally:
        tasks = list(_executions.items())
        for _, task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*(task for _, task in tasks), return_exceptions=True)
        for run_id, _ in tasks:
            try:
                await async_jobs.finish_owned_job(
                    lease,
                    run_id,
                    SandboxAsyncJobStatus.FAILED,
                    error="Sandbox command runtime stopped during execution.",
                )
            except RuntimeLeaseLost:
                break
        _executions.clear()


async def _execute_owned_job(lease, job: SandboxAsyncJobSnapshot) -> None:
    try:
        await lease.assert_owned()
        result = await execute_sandbox_container_command(
            id=job.sandbox_container_id,
            command=command_output.async_command(job.command, job.output_file),
            timeout_seconds=job.timeout_seconds,
            expected_generation=job.sandbox_container_generation,
            execution_marker=job.execution_marker,
        )
        output_bytes, output_lines = await _stat(job)
        await async_jobs.finish_owned_job(
            lease,
            job.run_id,
            SandboxAsyncJobStatus.COMPLETED if result.exit_code == 0 else SandboxAsyncJobStatus.FAILED,
            exit_code=result.exit_code,
            output_bytes=output_bytes,
            output_lines=output_lines,
        )
    except asyncio.CancelledError:
        raise
    except RuntimeLeaseLost:
        return
    except SandboxContainerCommandTimeoutError:
        output_bytes, output_lines = await _stat(job)
        await async_jobs.finish_owned_job(
            lease,
            job.run_id,
            SandboxAsyncJobStatus.FAILED,
            error=COMMAND_TIMEOUT_ERROR,
            output_bytes=output_bytes,
            output_lines=output_lines,
        )
    except SandboxContainerCommandTerminationError as exc:
        await async_jobs.finish_owned_job(
            lease,
            job.run_id,
            SandboxAsyncJobStatus.RECOVERY_REQUIRED,
            error=str(exc),
        )
    except Exception as exc:
        logger.exception("sandbox command failed: %s", job.run_id)
        await async_jobs.finish_owned_job(
            lease,
            job.run_id,
            SandboxAsyncJobStatus.FAILED,
            error=str(exc) or "Sandbox command failed.",
        )


async def _cancel_requested_jobs(lease) -> None:
    run_ids = await async_jobs.list_owned_cancel_requests(lease)
    tasks = [(run_id, _executions.get(run_id)) for run_id in run_ids]
    for _, task in tasks:
        if task is not None and not task.done():
            task.cancel()
    await asyncio.gather(
        *(task for _, task in tasks if task is not None),
        return_exceptions=True,
    )
    for run_id in run_ids:
        await async_jobs.finish_owned_job(
            lease,
            run_id,
            SandboxAsyncJobStatus.CANCELED,
            error="Sandbox command cancellation requested.",
        )


async def _recover_stale_jobs(lease) -> None:
    for job in await async_jobs.list_stale_running_jobs(lease):
        error = "Sandbox command was interrupted by runtime ownership change."
        status = SandboxAsyncJobStatus.FAILED
        if await async_jobs.is_job_container_binding_current(job.run_id):
            try:
                await terminate_sandbox_container_command(
                    job.sandbox_container_id,
                    job.execution_marker,
                    expected_generation=job.sandbox_container_generation,
                )
            except Exception as exc:
                error = f"{error} Cleanup failed: {str(exc) or type(exc).__name__}"
                status = SandboxAsyncJobStatus.RECOVERY_REQUIRED
        else:
            error = "Sandbox command was interrupted by a container lifecycle transition."
        output_bytes, output_lines = await _stat(job)
        await async_jobs.fail_stale_running_job(
            lease,
            job.run_id,
            error=error,
            status=status,
            output_bytes=output_bytes,
            output_lines=output_lines,
        )


async def _stat(job: SandboxAsyncJobSnapshot) -> tuple[int, int]:
    try:
        result = await execute_sandbox_container_command(
            id=job.sandbox_container_id,
            command=command_output.stat_command(job.output_file),
            timeout_seconds=_OUTPUT_STAT_TIMEOUT_SECONDS,
            expected_generation=job.sandbox_container_generation,
        )
        values = result.output.strip().split()
        return (int(values[0]), int(values[1])) if len(values) >= 2 else (0, 0)
    except Exception:
        return 0, 0


def _discard_execution(run_id: str, task: asyncio.Task[None]) -> None:
    if _executions.get(run_id) is task:
        _executions.pop(run_id, None)
    try:
        task.result()
    except asyncio.CancelledError:
        pass
    except Exception:
        logger.exception("sandbox command task escaped: %s", run_id)
