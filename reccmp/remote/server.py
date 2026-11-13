import asyncio
import contextlib
import enum
import logging
import time
import traceback
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from aiohttp import (
    web,
)
from pydantic import TypeAdapter
from watchfiles import awatch
from reccmp.compare import Compare
from reccmp.compare.db import ReccmpEntity
from reccmp.types import EntityType
from reccmp.report import (
    ReccmpReportEntity,
    ReccmpStatusReport,
    serialize_reccmp_report,
)
from reccmp.project.detect import (
    RecCmpProject,
    RecCmpTarget,
)
from .registry import register_daemon
from .shared import DaemonReady

logger = logging.getLogger(__name__)


class DaemonStatus(enum.Enum):
    READY = enum.auto()
    BUILDING = enum.auto()
    FAILED = enum.auto()


class DaemonApp:
    # pylint:disable=too-many-instance-attributes
    target: RecCmpTarget
    status: DaemonStatus
    reccmp: Compare
    report: ReccmpStatusReport | None
    error: str | None
    last_update: float
    stop: asyncio.Event
    reset_requested: asyncio.Event
    _executor: ThreadPoolExecutor

    def __init__(self, target: RecCmpTarget):
        # TODO: Report staleness if we are recalculating this target.
        self.target = target
        self.status = DaemonStatus.BUILDING
        self.report = None
        self.error = None
        self.last_update = time.monotonic()
        self.stop = asyncio.Event()
        self.reset_requested = asyncio.Event()
        self.executor = ThreadPoolExecutor(max_workers=1)

    MAX_IDLE_S = 600
    """Idle timeout."""

    def request_stop(self):
        self.stop.set()

    def request_reset(self):
        """Rebuild the reccmp core when the reset worker is free.
        If we are already rebuilding, combine any rebuild requests into one."""
        self.reset_requested.set()

    def bump(self):
        """Keep this session active if a file just changed or the user requested some data."""
        self.last_update = time.monotonic()

    async def wait_for_stop(self):
        """Return when a client requests a stop or the daemon has been inactive too long."""

        while True:
            remaining = self.MAX_IDLE_S - (time.monotonic() - self.last_update)
            if remaining <= 0:
                logger.info("Timed out.")
                return

            try:
                await asyncio.wait_for(self.stop.wait(), timeout=remaining)
                logger.info("Stop requested.")
                return
            except asyncio.TimeoutError:
                # Don't stop yet. Check no-activity timeout on the next pass.
                pass

    def reset(self):
        self.reccmp = Compare.from_target(self.target)
        self.report = None

    def get_report(self) -> ReccmpStatusReport:
        if self.report is None:
            ignore_functions = self.target.report_config.ignore_functions

            def entity_filter(entity: ReccmpEntity) -> bool:
                return not (
                    entity.entity_type == EntityType.FUNCTION
                    and entity.name in ignore_functions
                )

            self.report = self.reccmp.to_report(
                filename=self.target.original_path.name, filter_fn=entity_filter
            )

        return self.report

    def serialize_report(self, diff_included: bool, library_included: bool) -> str:
        report = self.get_report()
        if not library_included:
            # Filtering modifies the report, so make a copy first.
            filtered = ReccmpStatusReport(
                filename=report.filename, timestamp=report.timestamp
            )
            for ent in report.entities.values():
                if not ent.is_library:
                    filtered.add_match(ent)

            report = filtered

        return serialize_reccmp_report(report, diff_included=diff_included, version=2)

    def get_entity(self, addr: int) -> ReccmpReportEntity | None:
        # Use the cached report if we have it, but don't build the entire report for one address.
        if self.report is not None:
            ent = self.report.entities.get(addr)
            if ent is not None:
                return ent

        return self.reccmp.compare_address(addr)

    async def report_json(self, diff_included: bool, library_included: bool) -> str:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self.executor, self.serialize_report, diff_included, library_included
        )

    async def entity(self, addr: int) -> ReccmpReportEntity | None:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self.executor, self.get_entity, addr)

    async def reset_worker(self):
        """Rebuild the reccmp internal structures when a reset is requested."""
        try:
            while True:
                # TODO: Interrupt reccmp core here when this becomes possible.
                await self.reset_requested.wait()
                self.reset_requested.clear()
                self.status = DaemonStatus.BUILDING
                loop = asyncio.get_running_loop()
                try:
                    await loop.run_in_executor(self.executor, self.reset)
                except Exception:  # pylint: disable=broad-exception-caught
                    # Keep the daemon running so the next recompile can try again.
                    logger.exception("Failed to create the reccmp core")
                    # Save the error for HTTP requests received until we can successfully rebuild.
                    self.error = traceback.format_exc()
                    self.status = DaemonStatus.FAILED
                else:
                    self.error = None
                    self.status = DaemonStatus.READY
        except asyncio.CancelledError:
            pass

    async def recompile_worker(self):
        """Watch for changes to recomp artifacts.
        When we detect a recompile, update reccmp's internal structures."""
        watched = {
            self.target.recompiled_path.resolve(),
            self.target.recompiled_pdb.resolve(),
        }
        changed: set[Path] = set()
        try:
            # Wait for the dust to settle: no writes to watched files after 1 second.
            async for changes in awatch(
                *watched,
                rust_timeout=1000,
                yield_on_timeout=True,
            ):
                if changes:
                    self.bump()
                    changed.update(Path(path).resolve() for _, path in changes)
                elif changed >= watched:
                    # Both files changed.
                    changed.clear()
                    logger.info("Rebuilding...")
                    self.request_reset()
        except asyncio.CancelledError:
            pass

    @contextlib.asynccontextmanager
    async def running(self) -> AsyncIterator[None]:
        tasks = [
            asyncio.create_task(self.reset_worker()),
            asyncio.create_task(self.recompile_worker()),
        ]
        try:
            yield
        finally:
            for task in tasks:
                task.cancel()
            for task in tasks:
                await task


###
### aiohttp-specific items below this line.
###


STATE_KEY = web.AppKey("app_state", DaemonApp)


async def state_ctx(app) -> AsyncIterator[None]:
    async with app[STATE_KEY].running():
        yield


async def handle_report(request):
    state: DaemonApp = request.app[STATE_KEY]

    if state.status is DaemonStatus.FAILED:
        raise web.HTTPInternalServerError(text=state.error)

    if state.status is not DaemonStatus.READY:
        raise web.HTTPServiceUnavailable()

    diff_included = request.query.get("diffs", "0") != "0"
    library_included = request.query.get("library", "1") != "0"
    text = await state.report_json(diff_included, library_included)
    return web.json_response(text=text)


async def handle_rerun(request):
    request.app[STATE_KEY].request_reset()
    return web.HTTPNoContent()


async def handle_addr(request):
    state: DaemonApp = request.app[STATE_KEY]

    if state.status is DaemonStatus.FAILED:
        raise web.HTTPInternalServerError(text=state.error)

    if state.status is not DaemonStatus.READY:
        raise web.HTTPServiceUnavailable()

    int_addr = int(request.match_info["addr"])

    ent = await state.entity(int_addr)

    if ent is None or not ent.is_matched():
        raise web.HTTPNotFound()

    return web.json_response(
        body=TypeAdapter(ReccmpReportEntity).dump_json(ent),
    )


async def handle_stop(request):
    request.app[STATE_KEY].request_stop()
    return web.HTTPNoContent()


async def handle_ready(request):
    state: DaemonApp = request.app[STATE_KEY]
    return web.json_response(
        text=DaemonReady(
            ready=state.status is DaemonStatus.READY,
            target=state.target.target_id,
            recompiled=state.target.recompiled_path,
        ).model_dump_json()
    )


@web.middleware
async def bump_timeout(request, handler):
    """Every request should delay the no-activity timeout."""
    request.app[STATE_KEY].bump()
    return await handler(request)


@web.middleware
async def traceback_on_error(request, handler):
    """Return HTTP 500 with details for uncaught exceptions."""
    try:
        return await handler(request)
    except web.HTTPException:
        # Don't re-raise for expected HTTP failures: e.g. 404, 503.
        raise
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.exception("Error handling %s", request.path)
        raise web.HTTPInternalServerError(text=traceback.format_exc()) from e


async def server_main(project: RecCmpProject, target: RecCmpTarget, port: int):
    state = DaemonApp(target)
    state.request_reset()

    app = web.Application(middlewares=[bump_timeout, traceback_on_error])
    app[STATE_KEY] = state
    app.cleanup_ctx.append(state_ctx)

    app.add_routes(
        [
            web.get("/", handle_ready),
            web.get("/ready", handle_ready),
            web.get("/report", handle_report),
            web.post("/rerun", handle_rerun),
            web.post("/stop", handle_stop),
            web.get(r"/addr/{addr:\d+}", handle_addr),
        ]
    )
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, host="127.0.0.1", port=port)
    try:
        await site.start()
    except OSError as e:
        logger.error("Could not listen on port %d: %s", port, e)
        await runner.cleanup()
        return

    # Save the port so clients can find this daemon.
    port = runner.addresses[0][1]
    registry_path = register_daemon(project, target.target_id, port)

    try:
        await state.wait_for_stop()
    except asyncio.CancelledError:
        pass
    finally:
        logger.info("Exiting...")
        registry_path.unlink(missing_ok=True)
        await runner.cleanup()
