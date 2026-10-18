"""
Cyber Guardian - Standalone Desktop Launcher
Starts Streamlit programmatically in a daemon thread and wraps it in a native pywebview window.
Supports PyInstaller frozen executable (_MEIPASS) extraction and standard Python execution.
"""

import os
import sys
import time
import socket
import threading
import multiprocessing

# Windows PyInstaller multiprocessing guard
multiprocessing.freeze_support()


def get_base_dir() -> str:
    """Resolve base directory for both frozen PyInstaller bundles and standard python runs."""
    if getattr(sys, "frozen", False):
        return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.dirname(os.path.abspath(__file__))


# Set up paths and sys.path
BASE_DIR = get_base_dir()
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Ensure UTF-8 IO encoding on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure persistent database location and environment variables
if getattr(sys, "frozen", False):
    exe_dir = os.path.dirname(sys.executable)
    if not os.getenv("CYBER_GUARDIAN_DB_PATH"):
        os.environ["CYBER_GUARDIAN_DB_PATH"] = os.path.join(exe_dir, "cyber_guardian.db")
    exe_env = os.path.join(exe_dir, ".env")
    if os.path.exists(exe_env):
        try:
            from dotenv import load_dotenv
            load_dotenv(exe_env)
        except ImportError:
            pass
else:
    try:
        from dotenv import load_dotenv
        load_dotenv(os.path.join(BASE_DIR, ".env"))
    except ImportError:
        pass

# Streamlit thread safety: disable signal handling in non-main threads
import signal
_orig_signal = signal.signal


def _safe_signal(sig, handler):
    try:
        return _orig_signal(sig, handler)
    except ValueError:
        return None


signal.signal = _safe_signal

try:
    import streamlit.web.bootstrap as bootstrap
    bootstrap._set_up_signal_handler = lambda server: None
except Exception:
    pass

import webview
import streamlit.web.cli as stcli

APP_SCRIPT_PATH = os.path.join(BASE_DIR, "src", "app.py")
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8501
WINDOW_TITLE = "Cyber Guardian - Threat Intelligence & Forensics"
WINDOW_WIDTH = 1280
WINDOW_HEIGHT = 850


def run_streamlit():
    """Starts the Streamlit web server."""
    # Ensure current working directory is BASE_DIR so .streamlit/config.toml is found
    try:
        os.chdir(BASE_DIR)
    except Exception:
        pass

    sys.argv = [
        "streamlit",
        "run",
        APP_SCRIPT_PATH,
        f"--server.address={SERVER_HOST}",
        f"--server.port={SERVER_PORT}",
        "--server.headless=true",
        f"--browser.serverAddress={SERVER_HOST}",
        "--browser.gatherUsageStats=false",
        "--server.fileWatcherType=none",
        "--global.developmentMode=false",
    ]
    try:
        stcli.main()
    except SystemExit:
        pass
    except Exception as e:
        print(f"[Cyber Guardian] Server error: {e}", file=sys.stderr)


def wait_for_server(host: str, port: int, timeout: float = 30.0) -> bool:
    """Poll until the Streamlit TCP port is actively listening."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except (OSError, ConnectionRefusedError):
            time.sleep(0.15)
    return False


def main():
    print(f"[Cyber Guardian] Initializing Desktop Environment...")
    print(f"    Base Directory : {BASE_DIR}")
    print(f"    Target App     : {APP_SCRIPT_PATH}")
    print(f"    Target URL     : http://{SERVER_HOST}:{SERVER_PORT}")

    # Start Streamlit in a daemon thread
    server_thread = threading.Thread(target=run_streamlit, daemon=True, name="StreamlitServer")
    server_thread.start()

    print("[Cyber Guardian] Waiting for Streamlit server to bind...")
    is_ready = wait_for_server(SERVER_HOST, SERVER_PORT, timeout=30.0)
    if is_ready:
        print("[Cyber Guardian] Server ready! Launching native application window...")
    else:
        print("[Cyber Guardian] Warning: Server response timed out; attempting window launch...", file=sys.stderr)

    # Create pywebview native window
    window = webview.create_window(
        title=WINDOW_TITLE,
        url=f"http://{SERVER_HOST}:{SERVER_PORT}",
        width=WINDOW_WIDTH,
        height=WINDOW_HEIGHT,
        resizable=True,
        text_select=True,
        background_color="#090a0f",
    )

    # Optional automated close for CI / automated testing
    auto_close_sec = os.getenv("CYBER_GUARDIAN_AUTO_CLOSE")
    if auto_close_sec:
        def _on_loaded():
            print("[Cyber Guardian] Webview window loaded and rendered Streamlit successfully!")
            def _delayed_close():
                try:
                    delay = float(auto_close_sec)
                    print(f"[Cyber Guardian] Running in test mode: auto-closing in {delay}s...")
                    time.sleep(delay)
                    print("[Cyber Guardian] Auto-closing test window now...")
                    window.destroy()
                except Exception as e:
                    print(f"[Cyber Guardian] Auto-closer error: {e}", file=sys.stderr)

            threading.Thread(target=_delayed_close, daemon=True, name="AutoCloser").start()

        window.events.loaded += _on_loaded

    # Start webview GUI event loop (blocks until window is closed)
    webview.start()
    print("[Cyber Guardian] Application window closed. Shutting down...")


if __name__ == "__main__":
    main()
