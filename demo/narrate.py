"""Turn each scene's narration text into a WAV file, using Piper.

Owner: Member 7 (UI + QA + Docs).

Piper is a small neural text-to-speech model that runs entirely on this
machine -- no API key, no network, no per-word cost. The voice model is a
single .onnx file downloaded once.

Why the voice matters for the video: the narration length is what sets each
scene's duration. Write the words first, synthesise them, measure the WAV,
and only then decide how long to hold the picture. Doing it the other way
round -- guessing a duration and hoping the words fit -- is how demo videos
end up with a sentence cut in half at a scene change.

If Piper is missing or the voice file is not downloaded, this module returns
`None` for the audio and reports a duration estimated from the word count.
The video still records; it is simply silent. A missing voice must not stop
the demo from being made.
"""

from __future__ import annotations

import subprocess
import wave
from pathlib import Path

VOICE_DIR = Path.home() / ".local" / "share" / "piper-voices"
VOICE_NAME = "en-us-lessac-medium"
VOICE_ONNX = VOICE_DIR / f"{VOICE_NAME}.onnx"

# Piper's default rate is a little brisk for a technical walkthrough where the
# viewer is also reading a terminal, so slow it slightly. `length_scale` is
# the only pacing control this version of Piper exposes -- sentence pauses
# come from the model's own prosody.
LENGTH_SCALE = 1.06

# Used only when Piper is unavailable. 150 words per minute is a normal
# speaking pace; it is an estimate and the doc says so.
WORDS_PER_MINUTE = 150


def voice_available() -> bool:
    """True when we can actually synthesise speech."""
    if not VOICE_ONNX.exists():
        return False
    try:
        import piper  # noqa: F401
    except ImportError:
        return False
    return True


def estimate_seconds(text: str) -> float:
    """Fallback duration when there is no voice to measure."""
    words = len(text.split())
    return max(3.0, words / WORDS_PER_MINUTE * 60.0)


def wav_seconds(path: Path) -> float:
    """The true length of a WAV file, read from its own header."""
    with wave.open(str(path), "rb") as handle:
        return handle.getnframes() / float(handle.getframerate())


def synthesise(text: str, out_path: Path) -> float | None:
    """Write `text` to `out_path` as a WAV. Returns its length in seconds.

    Returns None when no voice is installed, so the caller can fall back to
    a silent video rather than failing.
    """
    if not voice_available():
        return None

    from piper import PiperVoice, SynthesisConfig

    out_path.parent.mkdir(parents=True, exist_ok=True)
    voice = PiperVoice.load(str(VOICE_ONNX))
    config = SynthesisConfig(length_scale=LENGTH_SCALE)
    with wave.open(str(out_path), "wb") as wav:
        voice.synthesize_wav(text, wav, syn_config=config)
    return wav_seconds(out_path)


def narrate_all(scenes, out_dir: Path, log=print) -> dict[str, dict]:
    """Synthesise every scene's narration once, up front.

    Returns {scene_id: {"path": Path|None, "seconds": float}}. Loading the
    voice model costs about a second, so we load it once here rather than
    per scene.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    have_voice = voice_available()
    if not have_voice:
        log(f"  ! no Piper voice at {VOICE_ONNX} -- the video will be silent")

    result: dict[str, dict] = {}
    voice = None
    config = None
    if have_voice:
        from piper import PiperVoice, SynthesisConfig
        voice = PiperVoice.load(str(VOICE_ONNX))
        config = SynthesisConfig(length_scale=LENGTH_SCALE)

    for scene in scenes:
        path = out_dir / f"{scene.id}.wav"
        if have_voice:
            with wave.open(str(path), "wb") as wav:
                voice.synthesize_wav(scene.narration, wav, syn_config=config)
            seconds = wav_seconds(path)
            result[scene.id] = {"path": path, "seconds": seconds}
        else:
            seconds = estimate_seconds(scene.narration)
            result[scene.id] = {"path": None, "seconds": seconds}
        log(f"  {scene.id:<22} {seconds:5.1f}s  {scene.requirement}")

    total = sum(entry["seconds"] for entry in result.values())
    log(f"  narration total: {total / 60:.1f} min across {len(result)} scenes")
    return result


def build_track(entries: list[tuple[Path | None, float]],
                total_seconds: float, out_path: Path) -> Path:
    """Lay each narration WAV onto one silent track at its measured offset.

    `entries` is [(wav_path_or_None, start_offset_seconds)].

    The offsets are the times each scene ACTUALLY started during recording,
    not the times we planned for it. That distinction is the whole point:
    a browser step can take 300ms longer than expected, and if the audio were
    built by concatenating clips end to end, that 300ms would push every
    later scene further out of sync until the closing narration played over
    the wrong picture. Placing each clip at its own measured offset means an
    error in one scene stays in that scene.
    """
    rate, width, channels = 22050, 2, 1
    for path, _ in entries:
        if path and path.exists():
            with wave.open(str(path), "rb") as handle:
                rate, width = handle.getframerate(), handle.getsampwidth()
                channels = handle.getnchannels()
            break

    frame_size = width * channels
    total_frames = int(total_seconds * rate) + rate       # +1s tail
    track = bytearray(total_frames * frame_size)

    for path, start in entries:
        if not (path and path.exists()):
            continue
        with wave.open(str(path), "rb") as handle:
            audio = handle.readframes(handle.getnframes())
        at = int(start * rate) * frame_size
        end = min(at + len(audio), len(track))
        if at < len(track):
            track[at:end] = audio[:end - at]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with wave.open(str(out_path), "wb") as out:
        out.setnchannels(channels)
        out.setsampwidth(width)
        out.setframerate(rate)
        out.writeframes(bytes(track))
    return out_path


def probe_duration(ffmpeg: str, path: Path) -> float | None:
    """Ask ffmpeg how long a media file is. None if it cannot tell."""
    proc = subprocess.run(
        [ffmpeg, "-i", str(path)], capture_output=True, text=True
    )
    for line in proc.stderr.splitlines():
        if "Duration:" not in line:
            continue
        stamp = line.split("Duration:")[1].split(",")[0].strip()
        try:
            hours, minutes, seconds = stamp.split(":")
            return int(hours) * 3600 + int(minutes) * 60 + float(seconds)
        except ValueError:
            return None
    return None
