"""Errors raised by the rootless observation extension."""

from __future__ import annotations


class MareformaProError(Exception):
    """Base class for rootless observation failures."""


class ReceiptError(MareformaProError):
    """A receipt is malformed, expired, or fails its HMAC check."""


class ScopeError(MareformaProError):
    """A collector scope is missing, duplicate, or already closed."""


class RootlessUnavailableError(MareformaProError):
    """The host lacks a required rootless primitive (strace, bwrap, or FUSE)."""


class FuseMountError(MareformaProError):
    """A user-owned FUSE mount could not be created or completed INIT."""


class RootlessRunError(MareformaProError):
    """The observed command could not complete under the runner."""

    def __init__(self, message: str, *, evidence: object | None = None) -> None:
        super().__init__(message)
        self.evidence = evidence
