"""
Standalone entry point: python -m flask_aegis.playground

Equivalent to `flask aegis playground` but doesn't require FLASK_APP to
be set -- useful for a quick spin-up without an existing Flask project.
"""
import argparse

from . import create_app


def main():
    parser = argparse.ArgumentParser(description="Flask-Aegis interactive playground")
    parser.add_argument("--host", default="127.0.0.1",
                         help="Bind address. Never use 0.0.0.0 or expose this publicly.")
    parser.add_argument("--port", type=int, default=5050)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    app = create_app()
    print(f"Flask-Aegis playground running at http://{args.host}:{args.port}")
    print("Local testing only -- do not expose this publicly. Press CTRL+C to stop.")

    from werkzeug.serving import run_simple
    run_simple(args.host, args.port, app, use_reloader=args.debug, use_debugger=args.debug)


if __name__ == "__main__":
    main()
