from collections.abc import Iterable

from agents import RunContextWrapper, Tool, function_tool

from core.agent.protocols import AgentRegistryProtocol
from core.runtime.context import AgentRuntimeContext
from schema.agent.sessions import AgentCode
from schema.agent.types import AgentRunWaitReason
from service.agent import delegation


def build_subagent_tools(
    parent_code: str,
    mounted_codes: Iterable[str],
    *,
    registry: AgentRegistryProtocol,
) -> list[Tool]:
    del registry
    allowed = frozenset(mounted_codes)
    allowed_text = ", ".join(sorted(allowed))

    async def start_subagent_task(
        ctx: RunContextWrapper[AgentRuntimeContext],
        agent_code: str,
        brief: str,
        investigation_task_id: int | None = None,
        environment_revision_id: int | None = None,
    ) -> str:
        """Delegate a bounded task to an isolated specialist Agent Run."""
        code = agent_code.strip()
        if code not in allowed:
            return delegation.tool_result({"error": f"agent_code must be one of: {allowed_text}"})
        body = brief.strip()
        if not body:
            return delegation.tool_result({"error": "brief is required"})
        try:
            run = await delegation.create_child_run(
                parent_run_id=ctx.context.run_id,
                parent_context_id=ctx.context.context_id,
                child_agent_code=AgentCode(code),
                brief=body,
                investigation_task_id=investigation_task_id,
                environment_revision_id=environment_revision_id,
            )
        except ValueError as exc:
            return delegation.tool_result({"error": str(exc)})
        ctx.context.wait_requested = True
        ctx.context.wait_reason = AgentRunWaitReason.CHILD_RUN
        ctx.context.wait_reference_id = run.id
        return delegation.tool_result({
            "run": run.model_dump(mode="json"),
            "message": "Delegated run queued. End this turn; the parent run will continue after completion.",
        })

    async def read_subagent_task(ctx: RunContextWrapper[AgentRuntimeContext], run_id: str) -> str:
        run = await delegation.get_child_run(ctx.context.session_id, run_id.strip())
        return delegation.tool_result(
            {
                "run": run.model_dump(mode="json"),
                "message": "delegated run state loaded",
            }
            if run
            else {"error": "delegated run not found"}
        )

    async def list_subagent_tasks(ctx: RunContextWrapper[AgentRuntimeContext], limit: int = 20) -> str:
        runs = await delegation.list_child_runs(ctx.context.session_id, limit)
        return delegation.tool_result({"items": [run.model_dump(mode="json") for run in runs]})

    async def cancel_subagent_task(ctx: RunContextWrapper[AgentRuntimeContext], run_id: str) -> str:
        run = await delegation.cancel_child_run(
            ctx.context.session_id,
            run_id.strip(),
            f"agent:{parent_code}",
        )
        return delegation.tool_result(run.model_dump(mode="json") if run else {"error": "delegated run not found"})

    return [
        function_tool(start_subagent_task, name_override="start_subagent_task"),
        function_tool(read_subagent_task, name_override="read_subagent_task"),
        function_tool(list_subagent_tasks, name_override="list_subagent_tasks"),
        function_tool(cancel_subagent_task, name_override="cancel_subagent_task"),
    ]
