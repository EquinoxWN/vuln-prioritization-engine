"""Error types shared by every module."""


class InputError(ValueError):
    """An input file or argument is malformed, too large or unsupported."""


class VersionError(ValueError):
    """A version string cannot be parsed for its ecosystem."""


class FetchError(RuntimeError):
    """A live download failed after its bounded retries."""
