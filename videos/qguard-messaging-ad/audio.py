"""Generate American English narration, synced SRT, and a stereo score."""

import json
from pathlib import Path
import sys
import wave

import numpy as np


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
WORK = ROOT / 'output/qguard-ad-work'
OUT = ROOT / 'output/qguard-messaging-ad'
sys.path.append(str(WORK / 'kokoro'))

VOICE_RATE = 24000
SCORE_RATE = 48000


def wav(path, samples, rate):
    with wave.open(str(path), 'wb') as f:
        f.setnchannels(1 if samples.ndim == 1 else samples.shape[1])
        f.setsampwidth(2)
        f.setframerate(rate)
        f.writeframes((np.clip(samples, -1, 1)*32767).astype('<i2').tobytes())


def stamp(seconds):
    ms = round(seconds * 1000)
    return f'{ms//3600000:02d}:{ms//60000%60:02d}:{ms//1000%60:02d},{ms%1000:03d}'


def pronounce(line):
    pairs = {
        'QGuard': 'Q Guard', 'RSA': 'R S A', 'ECDSA': 'E C D S A',
        'NIST': 'Nist', 'ML-KEM': 'M L Kem', 'ML-DSA': 'M L D S A',
        'AES-256-GCM': 'A E S two fifty-six G C M',
    }
    for word, speech in pairs.items():
        line = line.replace(word, speech)
    return line


def caption_text(line):
    if len(line) <= 55:
        return line
    words = line.split()
    candidates = [(' '.join(words[:i]), ' '.join(words[i:])) for i in range(1, len(words))]
    first, second = min(candidates, key=lambda p: abs(len(p[0])-len(p[1])) - (7 if p[0].endswith((',', '.')) else 0))
    return first + '\n' + second


def narration():
    from kokoro_onnx import Kokoro

    engine = Kokoro(str(WORK / 'kokoro.onnx'), str(WORK / 'voices.bin'))
    voice = np.zeros(120*VOICE_RATE, dtype=np.float32)
    captions = []

    def synth(line, speed):
        samples, rate = engine.create(pronounce(line), voice='af_heart', speed=speed, lang='en-us')
        assert rate == VOICE_RATE
        active = np.flatnonzero(np.abs(samples) > .005)
        if not len(active):
            raise RuntimeError(f'Empty narration: {line}')
        a, b = max(0, active[0]-420), min(len(samples), active[-1]+1300)
        return samples[a:b]

    script = json.loads((HERE / 'script.json').read_text(encoding='utf-8'))
    for block in script:
        lines = block['lines']
        width = block['end'] - block['start']
        items = [synth(line, .93) for line in lines]
        spoken = sum(map(len, items))/VOICE_RATE
        if spoken > width-.6:
            speed = .93 * spoken/(width-.75)
            items = [synth(line, speed) for line in lines]
            spoken = sum(map(len, items))/VOICE_RATE
        gap = min(.66, (width-spoken-.45)/(len(lines)-1))
        assert gap > .02, (block['start'], spoken, gap)
        start = block['start'] + .26
        for line, samples in zip(lines, items):
            offset = round(start*VOICE_RATE)
            voice[offset:offset+len(samples)] = samples
            end = start+len(samples)/VOICE_RATE
            wrap = caption_text(line)
            captions.append((max(0, start-.08), min(block['end'], end+.12, end+gap-.02), wrap))
            start = end+gap
        print(f"Narration {block['start']:3d}s to {start-gap:6.2f}s", flush=True)
    wav(WORK / 'narration.wav', voice, VOICE_RATE)
    (OUT / 'QGuard-Messaging-English.srt').write_text('\n\n'.join(
        f'{i}\n{stamp(start)} --> {stamp(end)}\n{line}'
        for i, (start, end, line) in enumerate(captions, 1)
    )+'\n', encoding='utf-8')


def score():
    music = np.zeros((120*SCORE_RATE, 2), dtype=np.float32)

    def add(start, duration, tone, pan=0):
        lo = round(start*SCORE_RATE)
        hi = min(len(music), lo+round(duration*SCORE_RATE))
        t = np.arange(hi-lo, dtype=np.float32)/SCORE_RATE
        signal = tone(t)
        music[lo:hi, 0] += signal*np.sqrt((1-pan)/2)
        music[lo:hi, 1] += signal*np.sqrt((1+pan)/2)

    def hz(midi):
        return 440*2**((midi-69)/12)

    # A minor opening gives way to open major voicings at the product reveal.
    chords = [(38, 45, 53, 57), (34, 41, 48, 53), (41, 48, 53, 57), (36, 43, 50, 55),
              (41, 48, 57, 60), (36, 43, 52, 55), (38, 45, 53, 57), (34, 41, 48, 53)]
    for bar, start in enumerate(np.arange(0, 120, 3.75)):
        section = 0 if start < 46.8 else 4
        notes = chords[section + bar%4]
        if start >= 112:
            notes = chords[4]
        for n, note in enumerate(notes):
            f = hz(note)
            add(start, 5.7, lambda t, f=f, n=n: (
                .039*np.sin(2*np.pi*f*t+.34*np.sin(2*np.pi*.16*t))
                + .010*np.sin(2*np.pi*f*2.001*t)
                + .005*np.sin(2*np.pi*f*3*t)
            ) * np.minimum(t/.84, 1) * np.clip((5.7-t)/2.15, 0, 1) / (1+.2*n), [-.3, .32, -.48, .49][n])
        for step, n in enumerate((1, 2, 3, 2)):
            f = hz(notes[n]+12)
            add(start + step*.9375 + .2, 1.3, lambda t, f=f: (
                np.sin(2*np.pi*f*t) + .26*np.sin(2*np.pi*f*2.002*t)
            ) * .023 * np.minimum(t/.02, 1)*np.exp(-t*3.5), (-1)**step*.52)
    for start in (0, 12, 21, 32, 39, 47, 66, 87, 107):
        add(start, 2.35, lambda t: .097*np.sin(2*np.pi*(41*t+4*(1-np.exp(-t*8))))
            * np.minimum(t/.018, 1)*np.exp(-t*3.25))
    for start in (47, 66, 87, 107):
        for n, note in enumerate((65, 69, 72, 79)):
            f = hz(note)
            add(start + n*.065, 3.2, lambda t, f=f: .030*np.sin(2*np.pi*f*t)
                * np.minimum(t/.04, 1)*np.exp(-t*1.8), (n-1.5)*.22)
    ramp = np.ones(len(music), dtype=np.float32)
    ramp[:SCORE_RATE//2] = np.linspace(0, 1, SCORE_RATE//2)
    ramp[-3*SCORE_RATE:] = np.linspace(1, 0, 3*SCORE_RATE)
    wav(WORK / 'score.wav', music*ramp[:, None], SCORE_RATE)


if __name__ == '__main__':
    OUT.mkdir(parents=True, exist_ok=True)
    if sys.argv[1:] == ['--rewrap']:
        path = OUT / 'QGuard-Messaging-English.srt'
        cues = [cue.splitlines() for cue in path.read_text(encoding='utf-8').strip().split('\n\n')]
        path.write_text('\n\n'.join('\n'.join(cue[:2] + [caption_text(' '.join(cue[2:]))]) for cue in cues)+'\n', encoding='utf-8')
    else:
        narration()
        score()
