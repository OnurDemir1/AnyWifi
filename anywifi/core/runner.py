"""Safe subprocess wrapper: timeouts, dry-run and timed captures."""

from __future__ import annotations

import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from typing import Callable, Optional, Sequence


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

    def __init__(self, dry_run: bool = False, verbose: bool = False, log=None):
        self.dry_run = dry_run
        self.verbose = verbose
        # log(msg, style) — injected by the reporter/console
        self._log = log or (lambda msg, style="dim": None)

    def _echo(self, text: str) -> None:
        """Echo the raw command line — only in verbose or dry-run mode.

        By default the user sees a clean, phase-oriented view instead of a
        stream of `$ tool ...` lines."""
        if self.verbose or self.dry_run:
            self._log(text, "dim")

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
        self._echo(f"$ {printable}")
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
        self._echo(f"$ {printable}   (~{duration}s)")
        if self.dry_run:
            return Result(0, "", "")
        try:
            proc = subprocess.Popen(
                list(cmd),
                stdout=subprocess.PIPE if capture else None,
                stderr=subprocess.PIPE if capture else None,
                # Detach stdin so airodump-ng/wash can't switch the terminal to
                # raw mode and corrupt the next input() prompt (target picker).
                stdin=subprocess.DEVNULL,
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

    # --- streaming run (live progress from long-running crackers) ---
    def run_stream(
        self,
        cmd: Sequence[str],
        on_line: Optional[Callable[[str], None]] = None,
        timeout: Optional[int] = None,
    ) -> Result:
        """Run a command, feeding each output line to `on_line` as it arrives.

        stderr is merged into stdout so progress lines from tools like hashcat
        and aircrack-ng (which update in place with '\\r') are streamed live.
        The full combined output is still returned in Result.stdout.
        """
        self._echo(f"$ {' '.join(cmd)}")
        if self.dry_run:
            return Result(0, "", "")
        try:
            proc = subprocess.Popen(
                list(cmd),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError:
            return Result(127, "", f"command not found: {cmd[0]}")

        collected: list[str] = []
        deadline = (time.time() + timeout) if timeout else None
        try:
            # Universal-newline mode treats '\r', '\n' and '\r\n' as line breaks,
            # so carriage-return progress updates arrive one at a time.
            for line in proc.stdout:  # type: ignore[union-attr]
                collected.append(line)
                if on_line:
                    on_line(line.rstrip("\r\n"))
                if deadline and time.time() > deadline:
                    self._terminate(proc)
                    break
        except KeyboardInterrupt:
            self._terminate(proc)
            raise
        try:
            proc.wait(timeout=5)
        except Exception:
            pass
        return Result(proc.returncode or 0, "".join(collected), "")

    # --- concurrent background processes (capture + injection) ---
    def spawn(self, cmd: Sequence[str]) -> Optional[subprocess.Popen]:
        """Start the command in the background and return the Popen (None on dry-run)."""
        self._echo(f"$ {' '.join(cmd)}   (background)")
        if self.dry_run:
            return None
        try:
            return subprocess.Popen(
                list(cmd),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,  # keep the terminal sane for input()
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
