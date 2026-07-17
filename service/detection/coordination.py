import asyncio


_bundle_mutation_lock = asyncio.Lock()


def detection_bundle_mutation_lock() -> asyncio.Lock:
    return _bundle_mutation_lock
