"""Create the 180-second stereo mix and its time-aligned English captions."""

import importlib.util
import json
import math
from pathlib import Path
import sys

import numpy as np


SOURCE = Path(__file__).resolve().parent
FILM = SOURCE.parent
SHARED = FILM.with_name("qguard-helix-film") / "audio/make_audio.py"
shared_spec = importlib.util.spec_from_file_location("messaging_audio", SHARED)
shared = importlib.util.module_from_spec(shared_spec)
shared_spec.loader.exec_module(shared)

SCRIPT = json.loads((SOURCE / "narration.json").read_text(encoding="utf-8"))
SPOKEN = {
    "ML-KEM": "M L Kem",
    "ML-DSA": "M L D S A",
    "SLH-DSA": "S L H, D S A",
    "QKMS": "Q K M S",
    "PKI": "P K I",
    "PQAuth": "P Q Auth",
    "QGuard": "Q Guard",
    "AI-assisted": "A I assisted",
}


def speak(line):
    for spelling, spoken in SPOKEN.items():
        line = line.replace(spelling, spoken)
    return line


def voice_take(original):
    rate = shared.VOICE_RATE
    samples, actual_rate = shared.voice_engine().create(
        speak(original), voice="af_heart", speed=0.96, lang="en-us"
    )
    if actual_rate != rate:
        raise RuntimeError(f"Unexpected voice sample rate {actual_rate}")
    active = np.flatnonzero(np.abs(samples) > 0.004)
    if not len(active):
        raise RuntimeError(f"Silent voice cue {original!r}")
    head = max(0, active[0] - shared.frame(0.025, rate))
    tail = min(len(samples), active[-1] + shared.frame(0.090, rate))
    return samples[head:tail]


def narration():
    voice = np.zeros(shared.frame(SCRIPT["duration"]), dtype=np.float32)
    cues = SCRIPT["cues"]
    captions = []
    for index, (start, limit, line) in enumerate(cues):
        take = voice_take(line)
        available = limit - start - 0.025
        if len(take) / shared.VOICE_RATE / available > 1.15:
            raise RuntimeError(f"Narration needs a wider cue at {start:.2f}: {line}")
        samples = shared.fit_take(take, available)
        first = shared.frame(start)
        voice[first:first + len(samples)] = samples
        next_cue = cues[index + 1][0] if index + 1 < len(cues) else SCRIPT["duration"]
        end = start + len(samples) / shared.MIX_RATE
        if end > limit:
            raise RuntimeError(f"Narration exceeded the cue at {start:.2f}: {line}")
        captions.append({
            "start": round(start - 0.06, 3),
            "end": round(min(next_cue - 0.09, max(start + 1.0, end + 0.17)), 3),
            "text": shared.wrap(line),
        })
        print(f"{start:6.2f}–{end:6.2f}  {line}", flush=True)
    return voice, captions


def score():
    """Move from suspended low strings into a bright, restrained four-note motif."""
    total = SCRIPT["duration"]
    layout = SCRIPT["chapters"]
    stereo = np.zeros((shared.frame(total), 2), dtype=np.float32)
    rng = np.random.default_rng(18024)

    def add(start, length, render, pan=0):
        first = shared.frame(start)
        last = min(len(stereo), first + shared.frame(length))
        t = np.arange(last - first, dtype=np.float32) / shared.MIX_RATE
        wave = render(t)
        stereo[first:last, 0] += wave * math.sqrt((1 - pan) * .5)
        stereo[first:last, 1] += wave * math.sqrt((1 + pan) * .5)

    tension = (
        (33, 45, 52, 55, 62), (29, 41, 48, 55, 60), (31, 43, 50, 55, 62),
    )
    cadence = (
        (36, 48, 55, 60, 64), (31, 43, 55, 59, 62),
        (33, 45, 52, 57, 64), (29, 41, 53, 57, 60),
    )
    release = ((36, 48, 55, 60, 67), (36, 48, 55, 64, 72))
    product = layout[2]
    finale = layout[-1]

    def bed(starts, progression, interval, level):
        duration = interval + 1.5
        pans = (0, -.43, .43, -.65, .65)
        for index, begin in enumerate(starts):
            chord = progression[index % len(progression)]
            for layer, note in enumerate(chord):
                frequency = shared.hz(note)

                def bow(t, layer=layer, frequency=frequency):
                    attack = np.sin(.5 * math.pi * np.clip(t / (1.35 + layer * .12), 0, 1))
                    tail = np.clip((duration - t) / 2.05, 0, 1)
                    phase = math.tau * frequency * t
                    vibration = .19 * np.sin(math.tau * (.28 + layer * .025) * t)
                    return (level / (1 + .17 * layer)) * attack * tail * (
                        np.sin(phase + vibration)
                        + .23 * np.sin(phase * 1.998 + vibration)
                        + .09 * np.sin(phase * 3.007)
                        + .027 * np.sin(phase * 5.01)
                    )

                add(begin, duration, bow, pans[layer])
            for beat, offset in enumerate((0.28, 1.30, 2.42, 3.46)):
                if begin + offset > total - 1.8:
                    break
                tone = shared.hz(chord[(1, 2, 4, 3)[beat]] + 12)

                def pulse(t, tone=tone):
                    return .0115 * (np.sin(math.tau * tone * t) + .2 * np.sin(math.tau * tone * 2.01 * t)) \
                        * np.clip(t / .025, 0, 1) * np.exp(-2.9 * t)

                add(begin + offset, 1.7, pulse, .47 * (-1) ** beat)

    bed(np.arange(0, product, 5), tension, 5, .028)
    bed(np.arange(product, finale, 4.25), cadence, 4.25, .034)
    bed(np.arange(finale, total, 9.5), release, 9.5, .038)

    def impact(t):
        phase = math.tau * (30 * t + 8.5 * (1 - np.exp(-t * 6.1)))
        noise = rng.standard_normal(len(t), dtype=np.float32)
        return (.21 * np.sin(phase) + .012 * np.diff(noise, prepend=noise[0])) \
            * np.clip(t / .022, 0, 1) * np.exp(-4.15 * t)

    def transition(t):
        noise = rng.standard_normal(len(t), dtype=np.float32)
        alpha = np.clip(t / 1.23, 0, 1) ** 2.8 * np.clip((1.45 - t) / .2, 0, 1)
        return .010 * alpha * (
            .46 * np.diff(noise, prepend=noise[0])
            + np.sin(math.tau * (53 * t + 175 * t**2))
        )

    for index, mark in enumerate(layout):
        add(mark, 1.8, impact)
        if mark:
            add(mark - 1.43, 1.45, transition, .32 * (-1) ** index)
    for mark, intensity in ((product, .036), (finale, .026), (169.38, .042), (175.0, .037)):
        for index, note in enumerate((60, 67, 72, 76)):
            frequency = shared.hz(note)

            def chime(t, frequency=frequency):
                phase = math.tau * frequency * t
                return intensity * (np.sin(phase) + .19 * np.sin(phase * 2.999)) \
                    * np.clip(t / .043, 0, 1) * np.exp(-1.76 * t)

            add(mark + index * .115, 3.2, chime, (index - 1.5) * .31)

    stereo[:shared.frame(.16)] *= np.linspace(0, 1, shared.frame(.16))[:, None]
    stereo[-shared.frame(1.38):] *= np.linspace(1, 0, shared.frame(1.38))[:, None]
    return stereo


def write_captions(captions):
    caption_out = FILM / "output/QGUARD-HELIX-PLATFORM.en.srt"
    caption_out.parent.mkdir(parents=True, exist_ok=True)
    blocks = []
    for index, cue in enumerate(captions, 1):
        start, end = (shared.stamp(cue[key]) for key in ("start", "end"))
        blocks.append(f"{index}\n{start} --> {end}\n{cue['text']}")
    caption_out.write_text("\n\n".join(blocks) + "\n", encoding="utf-8")
    subtitle_path = FILM / "src/subtitles.json"
    subtitle_path.parent.mkdir(exist_ok=True)
    payload = json.dumps({"landscape": captions}, ensure_ascii=False, indent=2) + "\n"
    pending = subtitle_path.with_suffix(".json.tmp")
    pending.write_text(payload, encoding="utf-8")
    pending.replace(subtitle_path)


def main():
    audio_out = FILM / "public/audio/enterprise.wav"
    audio_out.parent.mkdir(parents=True, exist_ok=True)
    voice, captions = narration()
    write_captions(captions)
    shared.master(audio_out, voice, score())


if __name__ == "__main__":
    if sys.argv[1:] == ["--phonemes"]:
        engine = shared.voice_engine()
        for raw, _ in SPOKEN.items():
            phonemes = engine.tokenizer.phonemize(speak(raw), "en-us")
            print(raw, phonemes)
    else:
        main()
