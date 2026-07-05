"""Live scan loop: ticks fire, stop is graceful, Ctrl-C keeps partial results."""

from anywifi.core.runner import Result
from anywifi.scan.scanner import Scanner


class FakeProc:
    def __init__(self, done_after=1):
        self.n = 0
        self.done_after = done_after

    def poll(self):
        self.n += 1
        return 0 if self.n >= self.done_after else None


class LiveRunner:
    dry_run = False
    verbose = False

    def __init__(self, proc):
        self._proc = proc
        self.stopped = False

    def has(self, tool):
        return False  # no wash → _apply_wps is a no-op

    def spawn(self, cmd):
        return self._proc

    def stop(self, proc):
        self.stopped = True

    def run_timed(self, *a, **k):
        return Result(0, "", "")


def test_scan_live_ticks_and_stops():
    runner = LiveRunner(FakeProc(done_after=1))
    ticks = []
    nets = Scanner(runner).scan_live(
        "wlan0", max_seconds=5, on_tick=lambda n, e: ticks.append(e), poll=0.01)
    assert nets == []           # no CSV written by the fake
    assert len(ticks) >= 1      # the view was updated at least once
    assert runner.stopped       # airodump was stopped


def test_scan_live_ctrl_c_keeps_going():
    runner = LiveRunner(FakeProc(done_after=99))

    def boom(networks, elapsed):
        raise KeyboardInterrupt  # user pressed Ctrl-C

    # Must not propagate — scan_live swallows it and returns cleanly.
    nets = Scanner(runner).scan_live("wlan0", max_seconds=5, on_tick=boom, poll=0.01)
    assert nets == []
    assert runner.stopped
