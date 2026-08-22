#!/usr/bin/env python3
"""Record the narrated end-to-end demo video.

Owner: Member 7 (UI + QA + Docs).

    python demo/record_demo.py                # record everything
    python demo/record_demo.py --no-audio     # silent video
    python demo/record_demo.py --only 10_gate # one scene, for iterating

What it does, in order:

1. Health-checks the API, the dashboard and DefectDojo. It refuses to record
   against a service that is down -- a demo video of an error page is worse
   than no video, because it looks finished.
2. Synthesises the narration for every scene up front (demo/narrate.py) and
   measures each clip, so the picture can be held for as long as the words
   take.
3. Drives ONE browser page through every scene, recording continuously:
   the terminal player replaying real captured output, then the real
   dashboard, then the real DefectDojo UI. One page means one continuous
   video with no cuts to stitch.
4. Times every scene against the wall clock while recording, then places
   each narration clip at the offset the scene really started at.
5. Muxes voice onto picture and writes MP4 and WebM with Playwright's own
   bundled ffmpeg -- no system ffmpeg needed.

The honest bit: the terminal segments are a styled HTML terminal replaying
text that `demo/capture.py` really captured from real commands. The numbers
on screen are genuine; the typing animation is not. Everything else in the
video is the live application.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

DEMO_DIR = Path(__file__).resolve().parent
ROOT = DEMO_DIR.parent
sys.path.insert(0, str(ROOT))

from demo import narrate                                  # noqa: E402
from demo.scenes import API, DASHBOARD, DEFECTDOJO, SCENES  # noqa: E402
from engine import config                                 # noqa: E402

config.load_dotenv()

CAPTURE_DIR = DEMO_DIR / "captures"
NARRATION_DIR = DEMO_DIR / "narration"
OUTPUT_DIR = DEMO_DIR / "output"
STILLS_DIR = OUTPUT_DIR / "stills"
RAW_DIR = OUTPUT_DIR / "raw"

WIDTH, HEIGHT = 1280, 720


# --------------------------------------------------------------- preflight

def http_ok(url: str, timeout: int = 6) -> tuple[bool, str]:
    """True when the URL answers at all. A 403 still means 'it is running'."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return True, f"HTTP {response.status}"
    except urllib.error.HTTPError as error:
        return error.code < 500, f"HTTP {error.code}"
    except Exception as error:                      # noqa: BLE001
        return False, str(error)[:70]


def preflight(want_defectdojo: bool) -> list[str]:
    """Check every service the video films. Returns the list of problems."""
    problems = []
    checks = [
        ("API", f"{API}/api/health", True),
        ("dashboard", DASHBOARD, True),
        ("DefectDojo", f"{DEFECTDOJO}/login", want_defectdojo),
    ]
    for name, url, required in checks:
        ok, detail = http_ok(url)
        mark = "ok " if ok else "DOWN"
        print(f"  [{mark}] {name:<11} {url}  ({detail})")
        if not ok and required:
            problems.append(f"{name} is not reachable at {url}")

    missing = [scene.capture for scene in SCENES
               if scene.kind == "terminal"
               and not (CAPTURE_DIR / f"{scene.capture}.txt").exists()]
    if missing:
        problems.append(
            f"missing captures: {', '.join(missing)} -- run: python demo/capture.py")
    return problems


def find_ffmpeg() -> str | None:
    """Find an ffmpeg that can actually write an MP4 with sound.

    Playwright ships an ffmpeg, but it is a cut-down build: VP8 video, WebM
    muxer, and no audio encoders at all. It records fine and can do nothing
    else. `imageio-ffmpeg` is a pip package that carries a full static build
    (libx264 + AAC + Opus) and needs no root, so prefer it, then anything on
    PATH, and only fall back to Playwright's for a silent WebM.
    """
    try:
        import imageio_ffmpeg
        return imageio_ffmpeg.get_ffmpeg_exe()
    except Exception:                               # noqa: BLE001
        pass

    system = shutil.which("ffmpeg")
    if system:
        return system

    cache = Path.home() / ".cache" / "ms-playwright"
    for candidate in sorted(cache.glob("ffmpeg-*/ffmpeg-linux"), reverse=True):
        if candidate.exists():
            return str(candidate)
    return None


# ------------------------------------------------------------ scene drivers

def load_capture(name: str) -> dict:
    """Read one captured command's real output and its metadata."""
    text = (CAPTURE_DIR / f"{name}.txt").read_text()
    meta_file = CAPTURE_DIR / f"{name}.json"
    meta = json.loads(meta_file.read_text()) if meta_file.exists() else {}
    return {
        "output": text,
        "command": meta.get("command", name),
        "note": meta.get("note", ""),
        "seconds": meta.get("seconds"),
    }


def observed_validator() -> str:
    """Which validator actually answered in the scan the video shows.

    Read out of the captured output rather than out of the config, because
    the config only says which key is present. `scan.py` prints the provider
    that really ran, after any fallback.
    """
    capture = CAPTURE_DIR / "02_scan.txt"
    if not capture.exists():
        return "unknown"
    for line in capture.read_text().splitlines():
        if "validated by" in line:
            return line.split(":", 1)[1].strip()
    return "unknown"


SUBTITLES = {
    "00_title": "A static analysis pipeline that reasons about exploitability, "
                "not just pattern matches.",
    "01_problem": "A scanner that reports everything reports nothing.",
    "15_close": "17 suspicious paths in, 11 real vulnerabilities out, "
                "6 false positives explained away.",
}


def run_title_scene(page, scene) -> None:
    page.evaluate(
        "([title, sub]) => window.showTitle(title, sub)",
        [scene.title, SUBTITLES.get(scene.id, "")],
    )


def run_terminal_scene(page, scene, duration_ms: float) -> None:
    payload = load_capture(scene.capture)
    payload["title"] = scene.title
    payload["requirement"] = scene.requirement
    page.evaluate(
        "([scene, ms]) => window.playCapture(scene, ms)",
        [payload, duration_ms],
    )


def reset_approval_gate(log) -> None:
    """Put every confirmed finding back to 'pending approval' before filming.

    The gate scene films a refusal, then an approval, then a successful apply.
    That story only works if the finding starts out unapproved, and the
    previous recording left it applied. Recording has to be repeatable.

    Two deliberate choices here:

    * It resets ALL confirmed findings, not just one. The recorder clicks the
      first row of the dashboard's own sorted table, which is not necessarily
      the first finding in the store -- resetting only one leaves the demo
      dependent on those two orderings agreeing.
    * It writes `fix_status` through the store rather than calling
      `approvals.reopen()`, because `applied` is a terminal state in the
      workflow and reopening it is not a transition a reviewer is allowed to
      make. This is resetting a fixture before a recording, not performing a
      workflow action, and it must not pretend to be one.
    """
    from engine import approvals, store

    findings = store.all_findings(status="confirmed", latest_only=True)
    if not findings:
        log("      ! no confirmed finding to reset the gate on")
        return

    reset = 0
    for finding in findings:
        if finding.get("fix_status", approvals.PENDING) != approvals.PENDING:
            store.update_finding(finding["id"], {
                "fix_status": approvals.PENDING,
                "fix_history": [],
                "approved_by": None,
                "approved_at": None,
            })
            reset += 1
    log(f"      gate reset: {reset} finding(s) back to pending")


def run_browser_scene(page, scene, player_url: str, log) -> None:
    """Execute one browser scene's steps against the live application."""
    for step in scene.steps:
        action = step["do"]
        try:
            if action == "goto":
                page.goto(step["url"], wait_until="domcontentloaded", timeout=45000)

            elif action == "wait":
                page.wait_for_timeout(step["ms"])

            elif action == "scroll":
                page.mouse.wheel(0, step["y"])
                page.wait_for_timeout(700)

            elif action == "scroll_to_text":
                page.get_by_text(step["text"], exact=False).first.scroll_into_view_if_needed(
                    timeout=6000)

            elif action == "click_tab":
                page.locator("nav button", has_text=step["text"]).first.click(timeout=8000)

            elif action == "click_button":
                # `has_text` is a substring match, and "Approve" is a substring
                # of "Apply approved fix" -- so the gate scene needs exact
                # names or it clicks the wrong button and proves nothing.
                if step.get("exact"):
                    page.get_by_role("button", name=step["text"],
                                     exact=True).first.click(timeout=8000)
                else:
                    page.locator("button", has_text=step["text"]).first.click(timeout=8000)

            elif action == "click_text":
                page.get_by_text(step["text"], exact=False).first.click(timeout=8000)

            elif action == "click_row":
                page.locator("tbody tr").nth(step["index"]).click(timeout=8000)

            elif action == "login_defectdojo":
                page.fill("#id_username", os.environ.get("DEFECTDOJO_USER", "admin"))
                page.fill("#id_password", os.environ.get("DEFECTDOJO_PASSWORD", ""))
                page.locator("button[type=submit], input[type=submit]").first.click()

        except Exception as error:                  # noqa: BLE001
            # A missing button must not end the recording. Losing one step
            # costs a few seconds of picture; aborting costs the whole video.
            if not step.get("optional"):
                log(f"      ! step '{action}' failed: {str(error).splitlines()[0][:90]}")


# ------------------------------------------------------------------- record

def record(only: str | None, with_audio: bool) -> int:
    from playwright.sync_api import sync_playwright

    scenes = [s for s in SCENES if not only or s.id == only]
    if not scenes:
        print(f"no scene matches --only {only}")
        return 2

    print("Preflight")
    problems = preflight(any(s.id == "13_defectdojo_ui" for s in scenes))
    if problems:
        print("\nRefusing to record:")
        for problem in problems:
            print(f"  - {problem}")
        print("\nStart the missing services, then run this again:")
        print("  python server.py &            # API      :8000")
        print("  cd ui && npm run dev &        # dashboard:5173")
        print(f"  (DefectDojo expected at {DEFECTDOJO})")
        return 1

    ffmpeg = find_ffmpeg()
    if not ffmpeg:
        print("\n! no ffmpeg found -- will produce WebM only, no MP4, no audio")

    print("\nNarration")
    timings = (narrate.narrate_all(scenes, NARRATION_DIR)
               if with_audio else
               {s.id: {"path": None, "seconds": narrate.estimate_seconds(s.narration)}
                for s in scenes})

    for directory in (OUTPUT_DIR, STILLS_DIR, RAW_DIR):
        directory.mkdir(parents=True, exist_ok=True)
    for old in RAW_DIR.glob("*.webm"):
        old.unlink()

    player_url = (DEMO_DIR / "terminal_player.html").as_uri()
    offsets: list[tuple[Path | None, float]] = []
    timeline: list[dict] = []

    print("\nRecording")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(args=["--force-device-scale-factor=1"])
        context = browser.new_context(
            viewport={"width": WIDTH, "height": HEIGHT},
            record_video_dir=str(RAW_DIR),
            record_video_size={"width": WIDTH, "height": HEIGHT},
            ignore_https_errors=True,
        )
        page = context.new_page()
        # Recording starts the instant the page exists, so this -- not the
        # first scene -- is frame zero of the video. Timing scenes from the
        # first scene instead would put every narration clip early by however
        # long the player took to load.
        video_started = time.time()

        page.goto(player_url, wait_until="domcontentloaded")
        page.wait_for_function("window.PLAYER_READY === true", timeout=15000)
        page.evaluate("() => window.showTitle('', '')")
        page.wait_for_timeout(600)
        started = time.time()

        for index, scene in enumerate(scenes, start=1):
            offset = time.time() - video_started
            entry = timings[scene.id]
            duration = entry["seconds"] + scene.pad_seconds
            print(f"  {index:>2}/{len(scenes)}  {scene.id:<22} "
                  f"@{offset:6.1f}s  for {duration:4.1f}s   {scene.requirement}")

            if scene.kind in ("title", "terminal"):
                # A previous browser scene may have navigated away, and
                # window.showTitle only exists on the player page. Come back
                # to it before trying to drive it.
                if not page.url.startswith("file://"):
                    page.goto(player_url, wait_until="domcontentloaded")
                    page.wait_for_function("window.PLAYER_READY === true",
                                           timeout=15000)
                if scene.kind == "title":
                    run_title_scene(page, scene)
                else:
                    run_terminal_scene(page, scene, duration * 1000)
                page.wait_for_timeout(int(duration * 1000))
            else:
                if scene.id == "10_gate":
                    reset_approval_gate(print)
                if page.url.startswith("file://") or scene.steps[0]["do"] != "goto":
                    page.goto(scene.url, wait_until="domcontentloaded", timeout=45000)
                    page.wait_for_timeout(1200)
                budget_start = time.time()
                run_browser_scene(page, scene, player_url, print)
                # Hold the finished screen until the narration has caught up.
                spent = time.time() - budget_start
                if spent < duration:
                    page.wait_for_timeout(int((duration - spent) * 1000))

            try:
                page.screenshot(path=str(STILLS_DIR / f"{scene.id}.png"))
            except Exception:                       # noqa: BLE001
                pass

            offsets.append((entry["path"], offset))
            timeline.append({
                "scene": scene.id,
                "title": scene.title,
                "requirement": scene.requirement,
                "start_seconds": round(offset, 1),
                "timestamp": f"{int(offset) // 60}:{int(offset) % 60:02d}",
                "narration": scene.narration,
            })

        page.wait_for_timeout(900)
        measured = time.time() - video_started
        video = page.video
        context.close()
        raw_path = Path(video.path())
        browser.close()

    print(f"\n  raw video: {raw_path.name} "
          f"({raw_path.stat().st_size / 1e6:.1f} MB, {measured:.0f}s of scenes)")

    silent = OUTPUT_DIR / "sast-engine-demo.webm"
    shutil.move(str(raw_path), str(silent))

    # Chrome finishes flushing the video a moment after the context closes, so
    # the file is usually a little longer than the span we timed. That is a
    # constant tail, not a clock running at a different rate -- so correct it
    # by SHIFTING the audio, never by scaling it. Scaling would stretch the
    # gaps between scenes and desynchronise progressively down the video.
    real = narrate.probe_duration(ffmpeg, silent) if ffmpeg else None
    if real and measured > 1:
        lag = real - measured
        print(f"  video {real:.1f}s vs timed {measured:.1f}s "
              f"({lag:+.1f}s at the tail)")
        if abs(lag) > 0.35:
            shift = lag / 2          # split the difference: half lead, half tail
            offsets = [(path, max(0.0, start + shift)) for path, start in offsets]
            for entry in timeline:
                start = max(0.0, entry["start_seconds"] + shift)
                entry["start_seconds"] = round(start, 1)
                entry["timestamp"] = f"{int(start) // 60}:{int(start) % 60:02d}"

    total = real or measured
    outputs = {"webm": silent}

    if with_audio and any(path for path, _ in offsets) and ffmpeg:
        track = narrate.build_track(offsets, total, OUTPUT_DIR / "narration.wav")
        print(f"  narration track: {track.stat().st_size / 1e6:.1f} MB")
        outputs.update(mux(ffmpeg, silent, track, print))
    elif ffmpeg:
        outputs.update(mux(ffmpeg, silent, None, print))

    (OUTPUT_DIR / "timeline.json").write_text(json.dumps({
        "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "duration_seconds": round(total, 1),
        # Two different facts, and conflating them would be a lie. The first
        # is which provider was configured; the second is which one actually
        # answered. A key can be present and still be rejected -- ours is --
        # and then Stage 3 falls back to the offline validator. The video is
        # only honest if the document records what really ran.
        "validator_configured": config.detect_provider(),
        "validator_used": observed_validator(),
        "narrated": bool(with_audio and any(path for path, _ in offsets)),
        "defectdojo_url": DEFECTDOJO,
        "scenes": timeline,
    }, indent=2))

    print("\nDone")
    for kind, path in outputs.items():
        print(f"  {kind:<5} {path}  ({path.stat().st_size / 1e6:.1f} MB)")
    print(f"  stills {STILLS_DIR}  ({len(list(STILLS_DIR.glob('*.png')))} PNGs)")
    print(f"  timeline {OUTPUT_DIR / 'timeline.json'}")
    return 0


def mux(ffmpeg: str, video: Path, audio: Path | None, log) -> dict[str, Path]:
    """Write the MP4 (and a narrated WebM when there is audio)."""
    outputs: dict[str, Path] = {}
    mp4 = video.with_suffix(".mp4")

    command = [ffmpeg, "-y", "-i", str(video)]
    if audio:
        command += ["-i", str(audio)]
    command += [
        "-c:v", "libx264", "-preset", "medium", "-crf", "22",
        # Chrome's WebM is variable-frame-rate; forcing 25fps and yuv420p is
        # what makes the MP4 play in PowerPoint, QuickTime and every browser.
        "-r", "25", "-pix_fmt", "yuv420p",
        "-vf", f"scale={WIDTH}:{HEIGHT}:force_original_aspect_ratio=decrease,"
               f"pad={WIDTH}:{HEIGHT}:(ow-iw)/2:(oh-ih)/2",
    ]
    if audio:
        command += ["-c:a", "aac", "-b:a", "128k", "-shortest"]
    command.append(str(mp4))

    proc = subprocess.run(command, capture_output=True, text=True)
    if proc.returncode == 0 and mp4.exists():
        outputs["mp4"] = mp4
    else:
        log(f"  ! mp4 transcode failed: {proc.stderr.strip().splitlines()[-1][:120]}")

    if audio:
        narrated = video.with_name("sast-engine-demo-narrated.webm")
        proc = subprocess.run(
            [ffmpeg, "-y", "-i", str(video), "-i", str(audio),
             "-c:v", "copy", "-c:a", "libopus", "-b:a", "96k", "-shortest",
             str(narrated)],
            capture_output=True, text=True)
        if proc.returncode == 0 and narrated.exists():
            outputs["webm"] = narrated
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser(description="Record the E2E demo video")
    parser.add_argument("--only", help="record a single scene by id")
    parser.add_argument("--no-audio", action="store_true",
                        help="skip narration and record a silent video")
    parser.add_argument("--list", action="store_true", help="list the scenes")
    args = parser.parse_args()

    if args.list:
        for scene in SCENES:
            words = len(scene.narration.split())
            print(f"  {scene.id:<22} {scene.kind:<9} {scene.requirement:<18} "
                  f"{words:>3} words")
        return 0

    return record(args.only, not args.no_audio)


if __name__ == "__main__":
    raise SystemExit(main())
