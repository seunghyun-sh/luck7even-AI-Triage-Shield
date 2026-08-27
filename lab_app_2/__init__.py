"""NovaStream intentionally vulnerable training application."""


def create_app(test_config: dict | None = None):
    """Load the application factory lazily for CLI and test use."""
    from .app import create_app as factory

    return factory(test_config)


__all__ = ["create_app"]
