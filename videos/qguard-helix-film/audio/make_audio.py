"""Build both stereo mixes and English SRTs from the local Kokoro cache."""

import argparse
from functools import lru_cache
import json
import math
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import wave

import numpy as np


SOURCE = Path(__file__).resolve().parent
FILM = SOURCE.parent
WORK = FILM.parents[1] / "output/qguard-ad-work"
FFMPEG = WORK / "deps/imageio_ffmpeg/binaries/ffmpeg-win-x86_64-v7.1.exe"
MIX_RATE = 48000
VOICE_RATE = 24000
SCRIPT = json.loads((SOURCE / "narration.json").read_text(encoding="utf-8"))
ASPECTS = {"landscape": "16x9", "portrait": "9x16"}


def frame(seconds, rate=MIX_RATE):
    return round(seconds * rate)


def stamp(seconds):
    ms = round(seconds * 1000)
    return f"{ms // 3600000:02}:{ms // 60000 % 60:02}:{ms // 1000 % 60:02},{ms % 1000:03}"


def seconds(stamp):
    hours, minutes, seconds, millis = map(int, re.split("[:,]", stamp))
    return hours * 3600 + minutes * 60 + seconds + millis / 1000


def wrap(line):
    if len(line) <= 44:
        return line
    words = line.split()
    splits = [(" ".join(words[:i]), " ".join(words[i:])) for i in range(1, len(words))]
    left, right = min(splits, key=lambda parts: abs(len(parts[0]) - len(parts[1])))
    return f"{left}\n{right}"


@lru_cache(maxsize=1)
def voice_engine():
    sys.path.append(str(WORK / "kokoro"))
    from kokoro_onnx import Kokoro
    import onnxruntime

    options = onnxruntime.SessionOptions()
    options.intra_op_num_threads = 4
    options.inter_op_num_threads = 1
    session = onnxruntime.InferenceSession(
        str(WORK / "kokoro.onnx"),
        sess_options=options,
        providers=["CPUExecutionProvider"],
    )
    return Kokoro.from_session(session, str(WORK / "voices.bin"))


@lru_cache(maxsize=64)
def voice_take(line):
    aliases = {
        "AES-256-GCM": "AES two fifty six G C M",
        "ML-KEM": "M L Kem",
        "ML-DSA": "M L D S A",
        "NIST": "Nist",
        "Offgrid": "Off grid",
        "QGuard": "Q Guard",
        "RSA": "R S A",
        "XFER": "X Fer",
    }
    for spelling, spoken in aliases.items():
        line = line.replace(spelling, spoken)
    samples, rate = voice_engine().create(line, voice="af_heart", speed=0.97, lang="en-us")
    if rate != VOICE_RATE:
        raise RuntimeError(f"Unexpected Kokoro sample rate {rate}")
    active = np.flatnonzero(np.abs(samples) > 0.004)
    if not len(active):
        raise RuntimeError(f"Empty Kokoro take for {line}")
    head = max(0, active[0] - frame(0.023, rate))
    tail = min(len(samples), active[-1] + frame(0.085, rate))
    return samples[head:tail]


def fit_take(samples, max_seconds):
    tempo = len(samples) / VOICE_RATE / max_seconds
    if tempo > 1.28:
        raise RuntimeError(f"Voice line needs a longer cue. Speed ratio {tempo:.2f}")
    audio_filter = "highpass=f=72,acompressor=threshold=0.095:ratio=3:attack=12:release=115:makeup=1.13"
    if tempo > 1:
        audio_filter += f",atempo={tempo * 1.016:.5f}"
    result = subprocess.run(
        [
            str(FFMPEG), "-hide_banner", "-loglevel", "error", "-f", "f32le",
            "-ar", str(VOICE_RATE), "-ac", "1", "-i", "pipe:0",
            "-af", audio_filter, "-f", "f32le", "-ar", str(MIX_RATE), "pipe:1",
        ],
        input=samples.astype("<f4").tobytes(),
        capture_output=True,
        check=True,
    )
    fitted = np.frombuffer(result.stdout, dtype="<f4").copy()
    taper = frame(0.010)
    fitted[:taper] *= np.linspace(0, 1, taper)
    fitted[-taper:] *= np.linspace(1, 0, taper)
    gain = min(2.2, 0.086 / np.sqrt(np.mean(fitted**2)))
    return fitted * gain


def narration(spec, cut):
    voice = np.zeros(frame(spec["duration"]), dtype=np.float32)
    captions = []
    cues = spec["cues"]
    for index, (start, limit, line) in enumerate(cues, 1):
        samples = fit_take(voice_take(line), limit - start - 0.03)
        end = start + len(samples) / MIX_RATE
        if end > limit:
            raise RuntimeError(f"Voice line exceeded its cue. {cut} {start:g}–{limit:g} {line}")
        voice[frame(start):frame(start) + len(samples)] = samples
        caption_start = max(0, start - 0.06)
        next_start = cues[index][0] if index < len(cues) else spec["duration"]
        caption_end = min(next_start - 0.09, max(start + 1.0, end + 0.16))
        captions.append(f"{index}\n{stamp(caption_start)} --> {stamp(caption_end)}\n{wrap(line)}")
        print(f"{cut:9} {start:6.2f}–{end:6.2f}  {line}", flush=True)
    return voice, "\n\n".join(captions) + "\n"


def hz(midi):
    return 440 * 2 ** ((midi - 69) / 12)


def score(spec):
    """A dark opening, expanding harmonies, and a resolved four-note signature."""
    duration = spec["duration"]
    scenes = spec["scenes"]
    music = np.zeros((frame(duration), 2), dtype=np.float32)
    rng = np.random.default_rng(762)

    def add(start, length, tone, pan=0):
        first = frame(start)
        last = min(len(music), first + frame(length))
        t = np.arange(last - first, dtype=np.float32) / MIX_RATE
        signal = tone(t)
        left = math.sqrt((1 - pan) / 2)
        right = math.sqrt((1 + pan) / 2)
        music[first:last, 0] += signal * left
        music[first:last, 1] += signal * right

    dark = ((38, 45, 50, 53, 57), (34, 41, 48, 50, 57), (31, 43, 50, 53, 57), (33, 45, 52, 55, 61))
    light = ((41, 48, 53, 57, 64), (36, 43, 48, 52, 62), (38, 45, 50, 53, 60), (34, 41, 46, 50, 57))
    colors = ((41, 48, 53, 57, 65), (34, 41, 46, 53, 60))
    product_start = scenes[2]
    final_start = scenes[-1]

    def harmony(starts, progression, interval):
        duration = interval + 1.3
        for index, start in enumerate(starts):
            notes = progression[index % len(progression)]
            for layer, note in enumerate(notes):
                f = hz(note)
                pan = (0, -0.42, 0.39, -0.58, 0.59)[layer]

                def pad(t, f=f, layer=layer):
                    phase = math.tau * f * t
                    attack = np.clip(t / (0.7 + layer * 0.15), 0, 1)
                    tail = np.clip((duration - t) / 1.5, 0, 1)
                    bow = (
                        np.sin(phase + .36 * np.sin(math.tau * .24 * t))
                        + .25 * np.sin(phase * 2.0012)
                        + .13 * np.sin(phase * 2.995)
                        + .045 * np.sin(phase * 4.013)
                    )
                    return (0.040 / (1 + layer * .14)) * bow * attack * tail

                add(start, duration, pad, pan)

            for step in range(6):
                hit = start + step * interval / 6 + 0.055
                if hit >= spec["duration"] - .8:
                    break
                f = hz(notes[(1, 2, 4, 2, 3, 4)[step]] + 12)
                add(
                    hit, 1.5,
                    lambda t, f=f: .024 * (np.sin(math.tau * f * t) + .24 * np.sin(math.tau * f * t * 2.006))
                    * np.clip(t / .016, 0, 1) * np.exp(-4.2 * t),
                    (-1) ** step * .55,
                )

    harmony(np.arange(0, product_start, 3.75), dark, 3.75)
    harmony(np.arange(product_start, final_start, 3.75), light, 3.75)
    harmony(np.arange(final_start, duration, (duration - final_start) / 2), colors, (duration - final_start) / 2)

    def bloom(t):
        noise = rng.standard_normal(len(t), dtype=np.float32)
        texture = np.diff(noise, prepend=noise[0]) * .006
        phase = math.tau * (45 * t + 10 * (1 - np.exp(-t * 6)))
        return (np.sin(phase) * .22 + texture * np.exp(-t * 9)) * np.clip(t / .013, 0, 1) * np.exp(-3.15 * t)

    def sweep(t):
        noise = rng.standard_normal(len(t), dtype=np.float32)
        alpha = np.clip(t / 1.65, 0, 1) ** 3 * np.clip((1.75 - t) / 0.2, 0, 1)
        return .015 * alpha * (noise + np.sin(math.tau * (75 * t + 220 * t**2)))

    for pair, start in enumerate(scenes):
        add(start, 2.0, bloom)
        if start > 1.75:
            add(start - 1.68, 1.75, sweep, (-1) ** pair * .45)
    for start, volume in ((product_start + 0.06, .025), (final_start + 0.95, .043), (duration - 3.6, .033)):
        for voice, note in enumerate((65, 72, 76, 79)):
            f = hz(note)
            add(
                start + voice * .12, 3.15,
                lambda t, f=f: volume * (np.sin(math.tau * f * t) + .15 * np.sin(math.tau * f * t * 2.997))
                * np.clip(t / .045, 0, 1) * np.exp(-1.8 * t),
                (voice - 1.5) * .32,
            )

    music[:frame(.22)] *= np.linspace(0, 1, frame(.22))[:, None]
    music[-frame(1.3):] *= np.linspace(1, 0, frame(1.3))[:, None]
    return music


def write_wav(path, audio):
    with wave.open(str(path), "wb") as handle:
        handle.setnchannels(2)
        handle.setsampwidth(2)
        handle.setframerate(MIX_RATE)
        handle.writeframes(np.rint(np.clip(audio, -1, 1) * 32767).astype("<i2").tobytes())


def master(target, voice, music):
    # A short attack and longer release leave the transitional impacts audible.
    block = frame(.05)
    samples = voice.reshape(-1, block)
    levels = np.sqrt(np.mean(samples**2, axis=1))
    driven = np.clip(levels / .066, 0, 1)
    envelope = np.zeros_like(driven)
    previous = 0
    for index, level in enumerate(driven):
        alpha = 0.7 if level > previous else 0.16
        previous += (level - previous) * alpha
        envelope[index] = previous
    duck = np.interp(np.arange(len(voice)), np.arange(len(envelope)) * block, 1 - .46 * envelope)
    mixed = (music * duck[:, None] + voice[:, None]).astype(np.float32)
    with tempfile.TemporaryDirectory() as temp:
        source = Path(temp) / "mix.wav"
        final = Path(temp) / "master.wav"
        peak = float(np.max(np.abs(mixed)))
        if peak > .98:
            mixed *= .98 / peak
        write_wav(source, mixed)
        probe = [
            str(FFMPEG), "-hide_banner", "-nostats", "-i", str(source), "-af",
            "loudnorm=I=-15:TP=-1.5:LRA=10",
        ]
        check = subprocess.run(
            [*probe[:-1], probe[-1] + ":print_format=json", "-f", "null", "-"],
            check=True, capture_output=True, text=True,
        )
        result = json.loads(re.search(r"\{\s*\"input_i\".*?\}", check.stderr, flags=re.S).group())
        values = (
            f":measured_I={result['input_i']}:measured_TP={result['input_tp']}"
            f":measured_LRA={result['input_lra']}:measured_thresh={result['input_thresh']}"
            f":offset={result['target_offset']}:linear=false"
        )
        runtime = len(voice) / MIX_RATE
        subprocess.run(
            [
                *probe[:-1], probe[-1] + values + f",aresample={MIX_RATE},apad=whole_len={len(voice)},atrim=duration={runtime}",
                "-loglevel", "error", "-y", str(final),
            ],
            check=True,
        )
        final.replace(target)
        print(f"Master {target.name} source analysis {result}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cuts", nargs="*", default=list(SCRIPT))
    parser.add_argument("--refresh-subtitles", action="store_true", help="Read the existing SRTs and update the composition.")
    args = parser.parse_args()
    audio_out = FILM / "public/audio"
    caption_out = FILM / "output"
    audio_out.mkdir(parents=True, exist_ok=True)
    caption_out.mkdir(parents=True, exist_ok=True)
    if not args.refresh_subtitles:
        for cut in args.cuts:
            spec = SCRIPT[cut]
            audio, captions = narration(spec, cut)
            master(audio_out / f"{cut}.wav", audio, score(spec))
            (caption_out / f"QGUARD-HELIX-{ASPECTS[cut]}.en.srt").write_text(captions, encoding="utf-8")

    subtitle_data = {}
    for cut, ratio in ASPECTS.items():
        path = caption_out / f"QGUARD-HELIX-{ratio}.en.srt"
        if not path.is_file():
            continue
        subtitle_data[cut] = []
        for cue in path.read_text(encoding="utf-8").strip().split("\n\n"):
            _, timecode, *lines = cue.splitlines()
            start, end = map(seconds, timecode.split(" --> "))
            subtitle_data[cut].append({"start": start, "end": end, "text": "\n".join(lines)})
    subtitle_path = FILM / "src/subtitles.json"
    subtitle_path.parent.mkdir(exist_ok=True)
    subtitle_path.write_text(json.dumps(subtitle_data, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
