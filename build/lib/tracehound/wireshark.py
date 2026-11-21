"""Bridge to Wireshark: find its tools, list interfaces, capture live traffic, open a capture at a frame."""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import threading
import time

# Where Wireshark installs its programs when they are not on PATH
APP_DIRS = {
    "Darwin": ["/Applications/Wireshark.app/Contents/MacOS"],
    "Windows": [r"C:\Program Files\Wireshark", r"C:\Program Files (x86)\Wireshark"],
    "Linux": ["/usr/bin", "/usr/local/bin"],
}


PERMISSION_HINT = ("macOS blocks packet capture by default. Open the Wireshark disk image (.dmg) you installed from, "
                   "double-click 'Install ChmodBPF.pkg', then log out and back in (or restart). "
                   "Check with: ls -l /dev/bpf0  (group should be access_bpf).")


class WiresharkError(RuntimeError):
    pass


def find_binary(name: str) -> str | None:
    # Look on PATH first, then in the default install folders for this OS
    found = shutil.which(name)
    if found:
        return found
    exe = name + (".exe" if platform.system() == "Windows" else "")
    for d in APP_DIRS.get(platform.system(), []):
        for candidate in (exe, name.capitalize() + (".exe" if platform.system() == "Windows" else "")):
            path = os.path.join(d, candidate)
            if os.path.isfile(path):
                return path
    return None


def status() -> dict:
    """Which Wireshark pieces are available on this machine."""
    return {"tshark": find_binary("tshark"), "wireshark": find_binary("wireshark")}


def list_interfaces() -> list[dict]:
    """Capture interfaces from `tshark -D`, e.g. [{'id': 'en0', 'label': 'en0 (Wi-Fi)'}]."""
    tshark = find_binary("tshark")
    if not tshark:
        raise WiresharkError("tshark not found. Install Wireshark (it includes tshark).")
    out = subprocess.run([tshark, "-D"], capture_output=True, text=True, timeout=20)
    if out.returncode != 0:
        raise WiresharkError(out.stderr.strip() or "tshark -D failed")
    interfaces = []
    for line in out.stdout.splitlines():
        if ". " not in line:
            continue
        rest = line.split(". ", 1)[1].strip()
        interfaces.append({"id": rest.split(" ", 1)[0], "label": rest})
    return interfaces


def capture(interface: str, seconds: int, out_path: str, bpf_filter: str | None = None, max_packets: int | None = None) -> str:
    """Record live traffic with tshark for a fixed time and save it as a pcapng file."""
    tshark = find_binary("tshark")
    if not tshark:
        raise WiresharkError("tshark not found. Install Wireshark (it includes tshark).")
    cmd = [tshark, "-i", interface, "-a", f"duration:{int(seconds)}", "-w", out_path, "-q"]
    if bpf_filter:
        cmd += ["-f", bpf_filter]
    if max_packets:
        cmd += ["-c", str(int(max_packets))]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=int(seconds) + 60)
    if out.returncode != 0 or not os.path.isfile(out_path):
        msg = out.stderr.strip()
        if "permission" in msg.lower():
            msg += "\n\n" + PERMISSION_HINT
        raise WiresharkError(msg or "capture failed")
    return out_path


class LiveMonitor:
    """Continuous capture: tshark keeps writing one pcapng file in the background until stopped or max_seconds."""

    def __init__(self, interface: str, out_path: str, bpf_filter: str | None = None, max_seconds: int = 1800):
        tshark = find_binary("tshark")
        if not tshark:
            raise WiresharkError("tshark not found. Install Wireshark (it includes tshark).")
        self.path, self.interface, self.started, self.stopped = out_path, interface, time.time(), False
        self.log_path = out_path + ".log"
        cmd = [tshark, "-i", interface, "-w", out_path, "-F", "pcapng", "-a", f"duration:{int(max_seconds)}", "-q"]
        if bpf_filter:
            cmd += ["-f", bpf_filter]
        self._log = open(self.log_path, "w")
        # tshark streams pcapng to a pipe (flushed per packet); a thread copies it into the file
        cmd[cmd.index("-w") + 1] = "-"
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=self._log, start_new_session=True)
        self._out = open(out_path, "wb")
        self._pump = threading.Thread(target=self._copy, daemon=True)
        self._pump.start()

    def _copy(self):
        # Copy captured bytes to disk as they arrive
        fd = self.proc.stdout.fileno()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            self._out.write(chunk)
            self._out.flush()
        self._out.close()

    def running(self) -> bool:
        return self.proc.poll() is None

    def error(self) -> str | None:
        # tshark's own message if it exited with an error (permissions, bad interface, bad filter)
        if self.stopped or self.running() or self.proc.returncode == 0:
            return None
        if not self._log.closed:
            self._log.flush()
        msg = open(self.log_path).read().strip()
        if "permission" in msg.lower():
            msg += "\n\n" + PERMISSION_HINT
        return msg or f"tshark exited with code {self.proc.returncode}"

    def size(self) -> int:
        return os.path.getsize(self.path) if os.path.exists(self.path) else 0

    def snapshot(self, dest: str) -> str:
        """Copy what has been captured so far, so analysis and Wireshark see one consistent file."""
        shutil.copyfile(self.path, dest)
        return dest

    def stop(self) -> None:
        self.stopped = True  # a user stop is not an error
        if self.running():
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self._pump.join(timeout=5)
        if not self._log.closed:
            self._log.close()


def open_in_wireshark(pcap_path: str, frame: int | None = None, display_filter: str | None = None) -> None:
    """Launch the Wireshark app on this capture, jumping to a frame and/or applying a display filter."""
    wireshark = find_binary("wireshark")
    if not wireshark:
        raise WiresharkError("Wireshark app not found. Open the file manually and use the filter shown.")
    cmd = [wireshark, "-r", os.path.abspath(pcap_path)]
    if frame:
        cmd += ["-g", str(int(frame))]
    if display_filter:
        cmd += ["-Y", display_filter]
    subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)


def frame_filter(frames: list[int]) -> str:
    # Display filter that shows exactly these frames, e.g. "frame.number in {262 416}"
    return "frame.number in {" + " ".join(str(int(f)) for f in sorted(set(frames))) + "}"
