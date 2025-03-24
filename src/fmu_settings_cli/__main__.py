"""The main entry point for fmu-settings-cli."""

import argparse
import asyncio
import hashlib
import secrets
import sys
import webbrowser
from concurrent.futures import ThreadPoolExecutor

import fmu_settings_api as api
import fmu_settings_gui as gui


def _parse_args(args: list[str] | None = None) -> argparse.Namespace:
    if args is None:
        args = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description="FMU Settings - Manage your FMU project's settings"
    )
    parser.add_argument(
        "--api-port",
        type=int,
        default=8001,
        help="Port to run the API on (default: 8001)",
    )
    parser.add_argument(
        "--gui-port",
        type=int,
        default=8000,
        help="Port to run the GUI on (default: 8000)",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host to bind the servers to (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    api_parser = subparsers.add_parser("api", help="Start the API server")
    api_parser.add_argument(
        "--port",
        type=int,
        default=8001,
        help="Port to run the API on (default: 8001)",
    )
    api_parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host to bind the API server to (default: 127.0.0.1)",
    )
    api_parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development",
    )

    gui_parser = subparsers.add_parser("gui", help="Start the GUI server")
    gui_parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to run the GUI on (default: 8000)",
    )
    gui_parser.add_argument(
        "--host",
        type=str,
        default="localhost",
        help="Host to bind the GUI server to (default: localhost)",
    )

    return parser.parse_args(args)


def generate_auth_token() -> str:
    """Generates an authentication token.

    This token is used to validate requests between the API and the GUI.

    Returns:
        A 256-bit token
    """
    random_bytes = secrets.token_hex(32)
    return hashlib.sha256(random_bytes.encode()).hexdigest()


def start_api_and_gui(token: str, args: argparse.Namespace) -> None:
    """Starts both API and GUI as concurrent processes.

    Args:
        token: Authentication token shared to api and gui
        args: The arguments taken in from invocation
    """
    api_server = api.run_server(
        token=token,
        host=args.host,
        port=args.api_port,
        frontend_host=args.host,
        frontend_port=args.gui_port,
    )
    gui_server = gui.run_server(
        host=args.host,
        port=args.gui_port,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        api_future = executor.submit(asyncio.run, gui_server.serve())
        gui_future = executor.submit(asyncio.run, api_server.serve())
        webbrowser.open(f"http://localhost:{args.gui_port}/#token={token}")
        try:
            # Blocks
            gui_future.result()
            api_future.result()
        except KeyboardInterrupt:
            print("\nShutting down FMU Settings...")
            gui_server.should_exit = True
            api_server.should_exit = True
            sys.exit(0)


def main(test_args: list[str] | None = None) -> None:
    """The main entry point."""
    args = _parse_args(test_args)

    token = generate_auth_token()
    match args.command:
        case "api":
            asyncio.run(
                api.run_server(token=token, host=args.host, port=args.port).serve()
            )
        case "gui":
            asyncio.run(gui.run_server(host=args.host, port=args.port).serve())
        case _:
            start_api_and_gui(token, args)


if __name__ == "__main__":
    main()
