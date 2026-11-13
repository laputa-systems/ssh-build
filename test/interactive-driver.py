#!/usr/bin/env python3
"""PTY driver for test/e2e-interactive.sh.

Runs inside the client container. It starts the client under test on a pseudo-terminal, plays the
part of the terminal emulator (a small VT screen model that also answers the queries tmux sends), and
walks the phase 4 scenario of docs/interactive.md:

  attach to `tmux new-session -A -s work`, wait for the ish prompt, print a marker, start a counter
  pane, break the network path and restore it, assert the same tmux session returns with the marker
  on screen, a running counter and a clean prompt, resize, exit, and compare the terminal attributes.

Everything that touches the client binary is the argv after `--`. The network is broken by the host
script; this driver asks for it through request files in --ctl (`NAME.req` -> `NAME.done`).

Python standard library only. Run it with `python3 -I`.
"""
import argparse
import codecs
import fcntl
import os
import random
import re
import select
import struct
import subprocess
import sys
import termios
import time

# Terminal-reply fragments that must never reach a shell prompt (the replies this driver sends to
# tmux's queries, focus reports, and mouse reports).
GARBAGE = [
    r"\d+;\d+c", r"\?\d+(;\d+)*c", r"rgb:", r"\[[IO]", r"\[M", r"<\d+;\d+;\d+[Mm]",
    r"\d+;\d+R", r"\^\[", r"\]1[012];", r">\|", r"\d+;\d+;\d+t",
]
GARBAGE_RE = re.compile("|".join(GARBAGE))
PROMPT_RE = re.compile(r"^\S+@\S+ .*\$ ?$")  # ish prompt: user@host dir [branch] $
ACS = {"q": "-", "x": "|", "l": "+", "k": "+", "m": "+", "j": "+", "t": "+", "u": "+",
       "v": "+", "w": "+", "n": "+", "a": "#", "`": "+"}


class Screen:
    """A VT100/xterm subset sufficient for tmux: cursor addressing, erase, scroll regions, insert and
    delete, wrapping. Answers terminal queries through `reply`."""

    def __init__(self, rows, cols, reply):
        self.reply = reply
        self.decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self.resize(rows, cols, reset=True)
        self.state = "ground"
        self.buf = ""
        self.last = " "
        self.graphics = False
        self.replies = 0

    def resize(self, rows, cols, reset=False):
        self.rows, self.cols = rows, cols
        self.grid = [[" "] * cols for _ in range(rows)]
        self.row = self.col = 0
        self.top, self.bottom = 0, rows - 1
        self.wrap_pending = False
        self.saved = (0, 0)

    def lines(self):
        return ["".join(r).rstrip() for r in self.grid]

    def text(self):
        return "\n".join(self.lines())

    def feed(self, data):
        for ch in self.decoder.decode(data):
            self.char(ch)

    def send(self, data):
        self.replies += 1
        self.reply(data.encode())

    # -- character level -------------------------------------------------------------------
    def char(self, ch):
        s = self.state
        if s == "ground":
            if ch == "\x1b":
                self.state = "esc"
            elif ch == "\x07":
                pass
            elif ch == "\x08":
                self.col = max(0, self.col - 1)
                self.wrap_pending = False
            elif ch == "\t":
                self.col = min(self.cols - 1, (self.col // 8 + 1) * 8)
                self.wrap_pending = False
            elif ch in "\n\x0b\x0c":
                self.index()
            elif ch == "\r":
                self.col = 0
                self.wrap_pending = False
            elif ch == "\x0e":
                self.graphics = True
            elif ch == "\x0f":
                self.graphics = False
            elif ch >= " ":
                self.put(ch)
        elif s == "esc":
            self.escape(ch)
        elif s == "csi":
            self.buf += ch
            if "@" <= ch <= "~":
                self.state = "ground"
                self.csi(self.buf)
            elif ch == "\x1b":
                self.state = "esc"
        elif s == "osc":
            if ch == "\x07":
                self.osc(self.buf)
                self.state = "ground"
            elif ch == "\x1b":
                self.state = "osc_esc"
            else:
                self.buf += ch
        elif s == "osc_esc":
            self.osc(self.buf)
            self.state = "ground" if ch == "\\" else "esc"
            if ch != "\\":
                self.escape(ch)
        elif s == "str":
            if ch == "\x1b":
                self.state = "str_esc"
        elif s == "str_esc":
            self.state = "ground" if ch == "\\" else "str"
        elif s == "charset":
            self.graphics = ch == "0"
            self.state = "ground"
        elif s == "skip1":
            self.state = "ground"

    def escape(self, ch):
        self.state = "ground"
        if ch == "[":
            self.state, self.buf = "csi", ""
        elif ch == "]":
            self.state, self.buf = "osc", ""
        elif ch in "PX^_":
            self.state = "str"
        elif ch == "(":
            self.state = "charset"
        elif ch in ")*+-./#%":
            self.state = "skip1"
        elif ch == "7":
            self.saved = (self.row, self.col)
        elif ch == "8":
            self.row, self.col = self.saved
        elif ch == "M":
            self.reverse_index()
        elif ch == "D":
            self.index()
        elif ch == "E":
            self.col = 0
            self.index()
        elif ch == "c":
            self.resize(self.rows, self.cols)

    # -- screen operations -------------------------------------------------------------------
    def put(self, ch):
        if self.graphics:
            ch = ACS.get(ch, ch)
        if self.wrap_pending:
            self.col = 0
            self.index()
            self.wrap_pending = False
        self.grid[self.row][self.col] = ch
        self.last = ch
        if self.col == self.cols - 1:
            self.wrap_pending = True
        else:
            self.col += 1

    def index(self):
        if self.row == self.bottom:
            del self.grid[self.top]
            self.grid.insert(self.bottom, [" "] * self.cols)
        elif self.row < self.rows - 1:
            self.row += 1

    def reverse_index(self):
        if self.row == self.top:
            del self.grid[self.bottom]
            self.grid.insert(self.top, [" "] * self.cols)
        elif self.row > 0:
            self.row -= 1

    def erase(self, row, c0, c1):
        for c in range(c0, min(c1, self.cols)):
            self.grid[row][c] = " "

    def csi(self, seq):
        final = seq[-1]
        body = seq[:-1]
        prefix = body[:1] if body[:1] in "?><=" else ""
        inter = ""
        while body and body[-1] in " !\"#$%&'()*+,-./":
            inter = body[-1] + inter
            body = body[:-1]
        body = body[len(prefix):]
        nums = [int(p) if p.isdigit() else 0 for p in re.split(r"[;:]", body)] if body else []

        def arg(i, default=1):
            return nums[i] if i < len(nums) and nums[i] > 0 else default

        self.wrap_pending = False
        if prefix == "" and inter == "":
            if final in "Hf":
                self.row = min(self.rows - 1, arg(0) - 1)
                self.col = min(self.cols - 1, arg(1) - 1)
            elif final == "A":
                self.row = max(self.top if self.row >= self.top else 0, self.row - arg(0))
            elif final == "B":
                self.row = min(self.bottom if self.row <= self.bottom else self.rows - 1, self.row + arg(0))
            elif final in "Ca":
                self.col = min(self.cols - 1, self.col + arg(0))
            elif final == "D":
                self.col = max(0, self.col - arg(0))
            elif final == "E":
                self.row = min(self.rows - 1, self.row + arg(0))
                self.col = 0
            elif final == "F":
                self.row = max(0, self.row - arg(0))
                self.col = 0
            elif final in "G`":
                self.col = min(self.cols - 1, arg(0) - 1)
            elif final == "d":
                self.row = min(self.rows - 1, arg(0) - 1)
            elif final == "J":
                mode = nums[0] if nums else 0
                if mode == 0:
                    self.erase(self.row, self.col, self.cols)
                    for r in range(self.row + 1, self.rows):
                        self.erase(r, 0, self.cols)
                elif mode == 1:
                    self.erase(self.row, 0, self.col + 1)
                    for r in range(self.row):
                        self.erase(r, 0, self.cols)
                else:
                    for r in range(self.rows):
                        self.erase(r, 0, self.cols)
            elif final == "K":
                mode = nums[0] if nums else 0
                if mode == 0:
                    self.erase(self.row, self.col, self.cols)
                elif mode == 1:
                    self.erase(self.row, 0, self.col + 1)
                else:
                    self.erase(self.row, 0, self.cols)
            elif final == "X":
                self.erase(self.row, self.col, self.col + arg(0))
            elif final == "@":
                n = min(arg(0), self.cols - self.col)
                self.grid[self.row][self.col:self.col] = [" "] * n
                del self.grid[self.row][self.cols:]
            elif final == "P":
                n = min(arg(0), self.cols - self.col)
                del self.grid[self.row][self.col:self.col + n]
                self.grid[self.row].extend([" "] * n)
            elif final == "L" and self.top <= self.row <= self.bottom:
                for _ in range(min(arg(0), self.bottom - self.row + 1)):
                    del self.grid[self.bottom]
                    self.grid.insert(self.row, [" "] * self.cols)
            elif final == "M" and self.top <= self.row <= self.bottom:
                for _ in range(min(arg(0), self.bottom - self.row + 1)):
                    del self.grid[self.row]
                    self.grid.insert(self.bottom, [" "] * self.cols)
            elif final == "S":
                for _ in range(arg(0)):
                    del self.grid[self.top]
                    self.grid.insert(self.bottom, [" "] * self.cols)
            elif final == "T":
                for _ in range(arg(0)):
                    del self.grid[self.bottom]
                    self.grid.insert(self.top, [" "] * self.cols)
            elif final == "r":
                top, bottom = arg(0) - 1, (nums[1] if len(nums) > 1 and nums[1] else self.rows) - 1
                if 0 <= top < bottom < self.rows:
                    self.top, self.bottom = top, bottom
                self.row = self.col = 0
            elif final == "s":
                self.saved = (self.row, self.col)
            elif final == "u":
                self.row, self.col = self.saved
            elif final == "b":
                for _ in range(arg(0)):
                    self.put(self.last)
            elif final == "c":
                self.send("\x1b[?1;2c")
            elif final == "n":
                if nums[:1] == [5]:
                    self.send("\x1b[0n")
                elif nums[:1] == [6]:
                    self.send("\x1b[%d;%dR" % (self.row + 1, self.col + 1))
            elif final == "t":
                if nums[:1] == [18]:
                    self.send("\x1b[8;%d;%dt" % (self.rows, self.cols))
                elif nums[:1] == [14]:
                    self.send("\x1b[4;%d;%dt" % (self.rows * 16, self.cols * 8))
        elif prefix == ">" and final == "c":
            self.send("\x1b[>0;276;0c")
        elif prefix == ">" and final == "q":
            self.send("\x1bP>|XTerm(370)\x1b\\")
        elif prefix == "?" and final == "n" and nums[:1] == [6]:
            self.send("\x1b[?%d;%dR" % (self.row + 1, self.col + 1))
        # SGR (m), modes (h/l), cursor style and the rest change nothing this model needs.

    def osc(self, body):
        if body.startswith("10;?"):
            self.send("\x1b]10;rgb:cccc/cccc/cccc\x1b\\")
        elif body.startswith("11;?"):
            self.send("\x1b]11;rgb:0000/0000/0000\x1b\\")
        elif body.startswith("12;?"):
            self.send("\x1b]12;rgb:cccc/cccc/cccc\x1b\\")


class Failure(Exception):
    pass


class Driver:
    def __init__(self, args):
        self.args = args
        self.deadline = time.time() + args.timeout
        self.master, self.slave = os.openpty()
        self.screen = None
        self.child = None
        self.child_pids = []
        self.respawns = 0
        self.exits = []  # (status, time) of every client process that ended
        self.finished = False
        self.transcript = bytearray()
        self.set_window(args.rows, args.cols)
        self.screen = Screen(args.rows, args.cols, lambda b: os.write(self.master, b))
        attrs = termios.tcgetattr(self.slave)
        # A deliberately unusual but valid cooked-mode state the client must give back exactly.
        attrs[3] &= ~termios.ECHOK
        attrs[6][termios.VERASE] = b"\x08"
        attrs[6][termios.VEOL] = b"\x1e"
        termios.tcsetattr(self.slave, termios.TCSANOW, attrs)
        self.cooked = termios.tcgetattr(self.slave)

    # -- plumbing ------------------------------------------------------------------------------
    def say(self, kind, message):
        print("%s: %s" % (kind, message), flush=True)

    def ok(self, message):
        self.say("ok", message)

    def info(self, message):
        self.say("INFO", message)

    def fail(self, message):
        raise Failure(message)

    def set_window(self, rows, cols):
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    def spawn(self):
        env = {"TERM": "xterm-256color", "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/tmp"}

        def attach():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        self.child = subprocess.Popen(
            self.args.client, stdin=self.slave, stdout=self.slave, stderr=self.slave, env=env,
            preexec_fn=attach, close_fds=True)
        self.child_pids.append(self.child.pid)

    def pump(self, seconds=0.1):
        end = time.time() + seconds
        while True:
            left = max(0.0, end - time.time())
            ready, _, _ = select.select([self.master], [], [], left)
            if ready:
                try:
                    data = os.read(self.master, 65536)
                except OSError:
                    data = b""
                if data:
                    self.transcript += data
                    del self.transcript[:-200000]
                    self.screen.feed(data)
                    continue
            break
        self.watch_child()

    def watch_child(self):
        if self.child is None or self.child.poll() is None:
            return
        status = self.child.returncode
        self.exits.append((status, time.time()))
        self.child = None
        if self.finished:
            return
        if not self.args.standin_reconnect:
            self.fail("the client exited with status %s before the scenario ended" % status)
        # ---- STAND-IN ONLY: OpenSSH has no reconnection, so the harness plays the part of the
        # reconnect loop that `oxish --attach` implements itself (docs/interactive.md phase 2). ----
        self.respawns += 1
        termios.tcsetattr(self.slave, termios.TCSANOW, self.cooked)
        termios.tcflush(self.slave, termios.TCIFLUSH)
        time.sleep(0.5)
        self.spawn()

    def wait_for(self, what, predicate, timeout=30):
        end = min(time.time() + timeout, self.deadline)
        while True:
            self.pump(0.1)
            value = predicate()
            if value:
                return value
            if time.time() >= end:
                self.fail("timed out waiting for %s" % what)

    def type(self, text):
        os.write(self.master, text.encode())

    def command(self, line):
        self.type(line + "\r")

    def row_equal(self, text):
        return lambda: any(r.strip() == text for r in self.screen.lines())

    def prompt_row(self):
        for row in range(self.screen.rows):
            line = self.screen.lines()[row]
            if PROMPT_RE.match(line.strip()) and row == self.screen.row:
                return line
        return None

    def prompt_ready(self):
        # The cursor sits on a prompt line and nothing follows the "$ ".
        line = self.screen.lines()[self.screen.row]
        return line if PROMPT_RE.match(line.strip()) else None

    def counter(self):
        values = [int(m) for m in re.findall(r"COUNTER=(\d+)", self.screen.text())]
        return max(values) if values else None

    def request(self, name, timeout=60):
        path = os.path.join(self.args.ctl, name)
        for suffix in (".req", ".done"):
            try:
                os.unlink(path + suffix)
            except FileNotFoundError:
                pass
        open(path + ".req", "w").close()
        end = time.time() + timeout
        while not os.path.exists(path + ".done"):
            self.pump(0.1)
            if time.time() > end:
                self.fail("the host did not complete the %s request" % name)

    def identity(self):
        tag = "%08x" % random.getrandbits(32)
        self.command('tmux display-message -p "SESS=#{session_id}:#{session_created}:#{pid}:%s"' % tag)
        pattern = re.compile(r"SESS=(\$\d+:\d+:\d+):%s" % tag)

        def found():
            m = pattern.search(self.screen.text())
            return m.group(1) if m else None
        return self.wait_for("the tmux session identity", found)

    def attrs(self):
        return termios.tcgetattr(self.slave)

    def dump(self):
        print("---- screen (%dx%d, cursor %d,%d) ----" % (self.screen.cols, self.screen.rows,
                                                          self.screen.row, self.screen.col))
        print(self.screen.text())
        print("---- last output bytes ----")
        print(bytes(self.transcript[-1500:]))
        print("---- client exits: %s, respawns: %d ----" % (self.exits, self.respawns))

    # -- the scenario -----------------------------------------------------------------------------
    def run(self):
        a = self.args
        self.spawn()
        first_pid = self.child.pid
        self.wait_for("the ish prompt inside tmux", lambda: self.prompt_ready() and
                      ("[%s]" % a.session) in self.screen.text(), a.attach_timeout)
        self.ok("attached: tmux status line shows [%s] and the ish prompt is up" % a.session)

        raw = self.attrs()
        if raw[3] & (termios.ICANON | termios.ECHO):
            self.fail("the client left the terminal in cooked/echo mode while attached")
        if raw == self.cooked:
            self.fail("terminal attributes did not change while attached")
        self.ok("the client owns raw mode while attached (ICANON and ECHO off)")

        self.command("tput cols")
        self.wait_for("`tput cols` = %d" % a.cols, self.row_equal(str(a.cols)))
        self.ok("tput cols reports %d" % a.cols)

        before = self.identity()
        self.ok("tmux session identity %s" % before)

        marker = "E2E-MARK-%08x" % random.getrandbits(32)
        counter_cmd = ("n=0; while :; do n=$((n+1)); echo COUNTER=$n; echo $n > /tmp/e2e-counter; "
                       "sleep 1; done")
        self.command("echo %s; tmux split-window -d -v -l 4 '%s'" % (marker, counter_cmd))
        self.wait_for("the marker line", self.row_equal(marker))
        first = self.wait_for("the counter pane", self.counter)
        advanced = self.wait_for("the counter to advance", lambda: (self.counter() or 0) >= first + 2)
        self.ok("marker %s on screen; counter running (COUNTER=%d)" % (marker, advanced))
        self.wait_for("the prompt below the marker", self.prompt_ready)

        # ---- break the TCP path --------------------------------------------------------------
        at_break = self.counter()
        self.request("break")
        broke = time.time()
        self.ok("network path broken (counter on screen was %d)" % at_break)
        if not a.standin_reconnect:
            self.type(a.lost_keys)
        self.pump(a.outage)
        if a.standin_reconnect:
            self.wait_for("the stand-in client to notice the outage", lambda: self.respawns >= 1, 30)
        self.info("%.1fs into the outage: client exits so far %s" % (time.time() - broke, self.exits))
        self.request("restore")
        restored = time.time()
        self.ok("network path restored after %.1fs" % (restored - broke))

        self.wait_for("reattach with the marker, a prompt and an advanced counter", lambda: (
            self.prompt_ready() and ("[%s]" % a.session) in self.screen.text()
            and any(r.strip() == marker for r in self.screen.lines())
            and (self.counter() or 0) > at_break + 3), a.reconnect_timeout)
        self.ok("reattached %.1fs after the restore; marker still on screen; counter %d > %d" % (
            time.time() - restored, self.counter(), at_break))
        if a.standin_reconnect:
            if self.respawns < 1:
                self.fail("the stand-in loop never reconnected")
            self.ok("reconnected by the stand-in loop (%d respawn(s))" % self.respawns)
        else:
            if self.child is None or self.child.pid != first_pid:
                self.fail("the client process changed; --attach must reconnect in place")
            self.ok("the same client process (pid %d) reconnected by itself" % first_pid)

        # Terminals report focus changes when the user returns to the window.
        self.type("\x1b[I")
        self.pump(1.5)
        after = self.identity()
        if after != before:
            self.fail("tmux session identity changed: %s -> %s" % (before, after))
        self.ok("same tmux session and server after the outage (%s)" % after)
        if a.show_screen:
            print(self.screen.text())

        if a.inject:
            self.type(a.inject)  # harness self-test: the garbage checks below must fail the run
            self.pump(1.0)
        self.request("capture")
        pane = open(os.path.join(a.ctl, "capture.txt"), errors="replace").read()
        if marker not in pane:
            self.fail("tmux's own copy of the pane lost the marker")
        for source, text in (("screen", self.screen.text()), ("pane", pane)):
            m = GARBAGE_RE.search(text)
            if m:
                self.fail("terminal-reply garbage %r in the %s after reconnect" % (m.group(0), source))
        if not a.standin_reconnect and a.lost_keys in self.screen.text() + pane:
            self.fail("input typed while disconnected was replayed (%s)" % a.lost_keys)
        if not a.standin_reconnect:
            self.ok("input typed during the outage (%s) was not replayed" % a.lost_keys)
        prompt = self.prompt_ready()
        if prompt is None:
            self.fail("no clean prompt on the cursor line: %r" % self.screen.lines()[self.screen.row])
        self.ok("prompt line %r is free of terminal-reply fragments" % prompt.strip())

        token = "ALIVE-%08x" % random.getrandbits(32)
        self.command("echo %s" % token)
        self.wait_for("the shell to answer after reattach", self.row_equal(token))
        self.ok("typed input reaches the shell after reattach")

        # ---- resize ---------------------------------------------------------------------------
        self.set_window(a.resize_rows, a.resize_cols)
        self.screen.resize(a.resize_rows, a.resize_cols)
        self.pump(1.0)
        self.command("tput cols")
        self.wait_for("`tput cols` = %d after the resize" % a.resize_cols,
                      self.row_equal(str(a.resize_cols)))
        self.ok("after resizing to %dx%d, tput cols reports %d" % (a.resize_rows, a.resize_cols,
                                                                    a.resize_cols))

        # ---- exit ----------------------------------------------------------------------------
        self.finished = True
        self.command("tmux kill-session -t %s" % a.session)
        end = time.time() + 30
        while self.child is not None and time.time() < end:
            self.pump(0.1)
        if self.child is not None:
            self.fail("the client did not exit after the tmux session ended")
        status = self.exits[-1][0]
        if status != 0:
            self.fail("the client exited with status %d, wanted the remote status 0" % status)
        self.ok("the client exited with the remote status 0")
        restored_attrs = self.attrs()
        if restored_attrs != self.cooked:
            self.fail("terminal attributes differ after exit:\n  before %s\n  after  %s" % (
                self.cooked, restored_attrs))
        self.ok("terminal attributes are byte-identical after exit")
        if a.standin_reconnect:
            self.info("stand-in run: the client was restarted %d time(s); attributes checked after the last" %
                      self.respawns)

    def close(self):
        if self.child is not None and self.child.poll() is None:
            self.child.kill()
            self.child.wait()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ctl", required=True, help="directory shared with the host for requests")
    p.add_argument("--session", default="work")
    p.add_argument("--rows", type=int, default=24)
    p.add_argument("--cols", type=int, default=80)
    p.add_argument("--resize-rows", type=int, default=30)
    p.add_argument("--resize-cols", type=int, default=100)
    p.add_argument("--outage", type=float, default=8.0, help="seconds to stay disconnected")
    p.add_argument("--attach-timeout", type=float, default=30)
    p.add_argument("--reconnect-timeout", type=float, default=90)
    p.add_argument("--timeout", type=float, default=240)
    p.add_argument("--lost-keys", default="LOSTKEYS")
    p.add_argument("--inject", default="", help="self-test: type this at the prompt after reattach")
    p.add_argument("--show-screen", action="store_true", help="print the screen after reattach")
    p.add_argument("--standin-reconnect", action="store_true",
                   help="STAND-IN: restart the client when it exits instead of relying on it")
    p.add_argument("client", nargs=argparse.REMAINDER)
    args = p.parse_args()
    if args.client[:1] == ["--"]:
        args.client = args.client[1:]
    if not args.client:
        p.error("give the client command after --")
    driver = Driver(args)
    try:
        driver.run()
    except Failure as error:
        driver.dump()
        print("FAIL: %s" % error, file=sys.stderr)
        return 1
    finally:
        driver.close()
    print("interactive scenario passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
