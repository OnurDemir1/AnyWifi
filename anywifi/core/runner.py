"""Safe subprocess wrapper: timeouts, dry-run and timed captures."""

from __future__ import annotations

import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from typing import Optional, Sequence


@dataclass
class Result:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class Runner:
    """Runs external commands. When dry_run=True it only prints them."""

    def __init__(self, dry_run: bool = False, log=None):
        self.dry_run = dry_run
        # log(msg, style) — injected by the reporter/console
        self._log = log or (lambda msg, style="dim": None)

    # --- discovery ---
    @staticmethod
    def which(tool: str) -> Optional[str]:
        return shutil.which(tool)

    def has(self, tool: str) -> bool:
        return self.which(tool) is not None

    # --- synchronous run ---
    def run(
        self,
        cmd: Sequence[str],
        timeout: Optional[int] = None,
        capture: bool = True,
        input_text: Optional[str] = None,
    ) -> Result:
        printable = " ".join(cmd)
        self._log(f"$ {printable}", "dim")
        if self.dry_run:
            return Result(0, "", "")
        try:
            proc = subprocess.run(
                list(cmd),
                capture_output=capture,
                text=True,
                timeout=timeout,
                input=input_text,
            )
            return Result(
                proc.returncode,
                proc.stdout or "",
                proc.stderr or "",
            )
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout or ""
            err = exc.stderr or ""
            if isinstance(out, bytes):
                out = out.decode(errors="replace")
            if isinstance(err, bytes):
                err = err.decode(errors="replace")
            return Result(124, out, err)
        except FileNotFoundError:
            return Result(127, "", f"command not found: {cmd[0]}")

    # --- timed background capture (airodump / hcxdumptool) ---
    def run_timed(
        self,
        cmd: Sequence[str],
        duration: int,
        capture: bool = True,
    ) -> Result:
        """Start the command, run it for `duration` seconds, then stop it gracefully."""
        printable = " ".join(cmd)
        self._log(f"$ {printable}   (~{duration}s)", "dim")
        if self.dry_run:
            return Result(0, "", "")
        try:
            proc = subprocess.Popen(
                list(cmd),
                stdout=subprocess.PIPE if capture else None,
                stderr=subprocess.PIPE if capture else None,
                text=True,
            )
        except FileNotFoundError:
            return Result(127, "", f"command not found: {cmd[0]}")

        deadline = time.time() + duration
        try:
            while time.time() < deadline:
                if proc.poll() is not None:
                    break
                time.sleep(0.5)
        except KeyboardInterrupt:
            self._terminate(proc)
            raise
        self._terminate(proc)
        out, err = "", ""
        try:
            out, err = proc.communicate(timeout=5)
        except Exception:
            pass
        return Result(proc.returncode or 0, out or "", err or "")

    # --- concurrent background processes (capture + injection) ---
    def spawn(self, cmd: Sequence[str]) -> Optional[subprocess.Popen]:
        """Start the command in the background and return the Popen (None on dry-run)."""
        self._log(f"$ {' '.join(cmd)}   (background)", "dim")
        if self.dry_run:
            return None
        try:
            return subprocess.Popen(
                list(cmd),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            self._log(f"command not found: {cmd[0]}", "red")
            return None

    def stop(self, proc: Optional[subprocess.Popen]) -> None:
        if proc is not None:
            self._terminate(proc)

    @staticmethod
    def _terminate(proc: subprocess.Popen) -> None:
        if proc.poll() is not None:
            return
        try:
            proc.send_signal(signal.SIGINT)
            time.sleep(1)
        except Exception:
            pass
        if proc.poll() is None:
            try:
                proc.terminate()
                time.sleep(1)
            except Exception:
                pass
        if proc.poll() is None:
            try:
                proc.kill()
            except Exception:
                pass
