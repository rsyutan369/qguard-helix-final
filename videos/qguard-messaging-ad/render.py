"""Deterministic local render for the 120-second QGuard Messaging ad."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from pathlib import Path
import math
import random
import subprocess

import numpy as np
from PIL import Image, ImageDraw, ImageFont, ImageFilter, ImageOps


ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / 'output/qguard-ad-work'
DELIVERY = ROOT / 'output/qguard-messaging-ad'
PREVIOUS = ROOT / 'videos/qguard-messaging-promo'
W, H, FPS = 1920, 1080, 30
INK = '#071224'
PAPER = '#eff3fe'
WHITE = '#f1f6ff'
CYAN = '#83e8ff'
INDIGO = '#3449d2'
MUTED = '#a7b7cf'
ROSE = '#ffa9b3'
PRODUCT_SHOTS = {
    9: (13.0, 16.5, 'crop=1090:790:810:165', (954, 230, 1803, 845)),
    10: (26.85, 29.3, 'crop=1670:745:95:310', (854, 337, 1816, 766)),
    11: (19.0, 21.5, 'crop=790:875:1000:115', (1058, 160, 1724, 891)),
    15: (31.0, 33.35, 'crop=1020:620:855:255', (939, 293, 1808, 819)),
}


@lru_cache(maxsize=None)
def font(size, style='display'):
    names = {'display': 'Aptos Display Bold.ttf', 'body': 'Aptos.ttf', 'mono': 'consola.ttf'}
    fallbacks = {'display': 'segoeuib.ttf', 'body': 'segoeui.ttf', 'mono': 'consola.ttf'}
    home = Path('C:/Windows/Fonts')
    path = home / names[style]
    return ImageFont.truetype(str(path if path.exists() else home / fallbacks[style]), size)


def text(draw, x, y, value, size, color=WHITE, style='display', anchor='lt'):
    draw.text((x, y), value, font=font(size, style), fill=color, anchor=anchor)


def tag(draw, x, y, value, color=CYAN):
    text(draw, x, y, ' '.join(value), 21, color, 'mono')


@lru_cache(maxsize=None)
def gradient(light):
    y, x = np.mgrid[0:H:2, 0:W:2].astype(np.float32)
    glow = np.exp(-(((x - 1470) / 830) ** 2 + ((y - 465) / 640) ** 2))
    beam = np.exp(-((x + y * 1.18 - 1600) / 210) ** 2) * .13
    tone = np.clip(glow + beam, 0, 1)[..., None]
    base = np.array([233, 239, 250] if light else [4, 9, 21])
    delta = np.array([16, 13, 5] if light else [13, 28, 56])
    grain = np.random.default_rng(21).normal(0, .7 if light else .95, (H // 2, W // 2, 1))
    pixels = np.uint8(np.clip(base + tone * delta + grain, 0, 255))
    return Image.fromarray(pixels).resize((W, H), Image.Resampling.BICUBIC)


def stage(index, label, light=False):
    bg = gradient(light).copy()
    d = ImageDraw.Draw(bg)
    rule = '#c6d1e7' if light else '#263951'
    soft = '#425879' if light else '#93a9c8'
    for x in range(120, 1820, 56):
        for y in range(130, 960, 56):
            d.point((x, y), fill=rule)
    d.line((106, 105, 1814, 105), fill=rule)
    d.line((106, 977, 1814, 977), fill=rule)
    tag(d, 106, 63, 'QGUARD MESSAGING', soft)
    text(d, 1814, 63, f'{index:02d} / {label.upper()}', 22, soft, 'mono', 'rt')
    text(d, 106, 1002, 'PRIVATE COMMUNICATIONS', 19, soft, 'mono')
    for i in range(12):
        x = 1542 + i * 23
        d.line((x, 1008, x + 14, 1008), fill=(INDIGO if light else CYAN) if i < index else rule, width=2)
    return bg, d


def heading(d, kicker, title, sub='', light=False, top=285, size=114):
    tag(d, 107, top - 60, kicker, INDIGO if light else CYAN)
    for i, line in enumerate(title.split('|')):
        text(d, 101, top + i * int(size * .99), line, size, INK if light else WHITE)
    for i, line in enumerate(sub.split('|')):
        if line:
            text(d, 108, top + len(title.split('|')) * int(size * .99) + 36 + i * 42,
                 line, 32, '#354e73' if light else MUTED, 'body')


def layer_card(bg, box, fill, border, radius=32, glow=None):
    if glow:
        shadow = Image.new('RGBA', bg.size)
        ImageDraw.Draw(shadow).rounded_rectangle(box, radius=radius, fill=glow)
        bg.paste(shadow.filter(ImageFilter.GaussianBlur(34)), (0, 0), shadow.filter(ImageFilter.GaussianBlur(34)))
    ImageDraw.Draw(bg).rounded_rectangle(box, radius=radius, fill=fill, outline=border, width=2)


def clipped(bg, picture, box, radius=20):
    x, y, right, bottom = box
    size = (right-x, bottom-y)
    asset = ImageOps.fit(picture.convert('RGB'), size, Image.Resampling.LANCZOS)
    mask = Image.new('L', size)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, size[0]-1, size[1]-1), radius=radius, fill=255)
    bg.paste(asset, (x, y), mask)


def icon(d, kind, x, y, color=CYAN):
    if kind == 'chat':
        d.rounded_rectangle((x, y, x+64, y+48), radius=13, outline=color, width=4)
        d.line((x+14, y+47, x+13, y+60, x+30, y+47), fill=color, width=4)
        for i in range(3):
            d.ellipse((x+15+i*14, y+20, x+21+i*14, y+26), fill=color)
    elif kind == 'video':
        d.rounded_rectangle((x, y, x+47, y+49), radius=12, outline=color, width=4)
        d.line((x+48, y+18, x+67, y+8, x+67, y+42, x+48, y+32), fill=color, width=4)
    elif kind == 'folder':
        d.line((x, y+53, x, y+8, x+27, y+8, x+35, y+17, x+67, y+17, x+67, y+53, x, y+53), fill=color, width=4, joint='curve')
    else:
        d.rounded_rectangle((x+6, y+23, x+59, y+64), radius=9, outline=color, width=4)
        d.arc((x+16, y, x+49, y+42), 180, 360, fill=color, width=4)
        d.line((x+32, y+38, x+32, y+50), fill=color, width=4)


def lattice(d, x, y, radius, phase, rose=False):
    colors = ['#203a64', '#2f5680', '#427bab', '#75c9f3']
    if rose:
        colors[-1] = '#ed8ba9'
    for ring in range(10):
        r = radius * (.28 + ring * .077)
        d.ellipse((x-r, y-r, x+r, y+r), outline=colors[ring % 3], width=1)
        d.arc((x-r, y-r, x+r, y+r), phase+ring*29, phase+ring*29+67, fill=colors[3], width=2)
    for spoke in range(36):
        angle = spoke * math.tau / 36
        dx, dy = math.cos(angle), math.sin(angle)
        d.line((x+dx*radius*.27, y+dy*radius*.27, x+dx*radius, y+dy*radius), fill=colors[0])
        if spoke % 3 == 0:
            d.ellipse((x+dx*radius*.83-3, y+dy*radius*.83-3, x+dx*radius*.83+3, y+dy*radius*.83+3), fill=colors[3])


def capture(ff, label, sec, crop):
    out = WORK / f'product-{label}.png'
    subprocess.run([ff, '-hide_banner', '-loglevel', 'error', '-y', '-ss', str(sec), '-i',
                    str(PREVIOUS / 'renders/proof-1080p.mp4'), '-vf', crop, '-frames:v', '1', str(out)], check=True)
    return Image.open(out).copy()


def shots(ff, logo_path):
    product = {
        'devices': capture(ff, 'devices', 16, 'crop=1090:790:810:165'),
        'chat': capture(ff, 'chat', 21, 'crop=790:875:1000:115'),
        'calls': capture(ff, 'calls', 29.1, 'crop=1670:745:95:310'),
        'vault': capture(ff, 'vault', 33, 'crop=1020:620:855:255'),
    }
    logo = Image.open(logo_path).convert('RGB')
    out = []

    def save(bg, seconds, zoom=.032, transition=.24):
        target = WORK / f'shot-{len(out):02d}.png'
        bg.save(target)
        out.append((target, seconds, zoom, transition))

    for n, (title, asset, kind) in enumerate([
        ('A private|conversation.', 'Private message', 'chat'),
        ('A video of|your family.', 'Family video', 'video'),
        ('A contract|about to be signed.', 'Contract draft', 'folder'),
    ]):
        bg, d = stage(1, 'What you share')
        heading(d, 'THE THINGS WE SEND', title, top=335, size=105)
        lattice(d, 1386, 522, 341, 30+n*38)
        for i in range(2, -1, -1):
            x, y = 1100 + i*27, 394 - i*28
            layer_card(bg, (x, y, x+567, y+260), '#101d35', '#355575', glow=(49, 122, 183, 62) if i == 0 else None)
        icon(d, kind, 1142, 447)
        text(d, 1144, 548, asset, 46)
        text(d, 1144, 607, 'READY TO SEND', 20, MUTED, 'mono')
        d.ellipse((1558, 551, 1631, 624), fill=CYAN)
        d.line((1580, 588, 1607, 588, 1597, 578), fill=INK, width=4)
        d.line((1607, 588, 1597, 599), fill=INK, width=4)
        save(bg, [1.6, 2.13, 2.27][n], .036)

    bg, d = stage(2, 'Public-key cryptography')
    heading(d, 'THE FOUNDATION', 'Digital trust|runs on math.', 'Widely used public-key protections', top=325, size=112)
    for i, (name, detail) in enumerate([('RSA', 'PUBLIC-KEY CRYPTOGRAPHY'), ('ECC', 'ELLIPTIC-CURVE CRYPTOGRAPHY'), ('ECDSA', 'ELLIPTIC-CURVE SIGNATURES')]):
        y = 250+i*191
        layer_card(bg, (1037, y, 1773, y+151), '#0e1b32', '#304967', radius=21)
        text(d, 1077, y+29, name, 68)
        text(d, 1324, y+66, detail, 21, CYAN, 'mono')
    save(bg, 11.47, .025)

    bg, d = stage(3, 'Quantum risk')
    heading(d, 'A FUTURE CAPABILITY', 'The math|can break.', 'A sufficiently powerful quantum computer|could break widely used RSA and ECC.', top=320, size=110)
    lattice(d, 1400, 528, 340, 38, True)
    lattice(d, 1400, 528, 260, 102, True)
    d.ellipse((1296, 424, 1504, 632), fill='#101c34', outline='#ed8ba9', width=2)
    text(d, 1400, 520, 'Q', 113, WHITE, anchor='mm')
    save(bg, 4.83, .055)

    for i, (title, label, sub) in enumerate([
        ('Someone can|collect it today.', 'CAPTURE', 'An encrypted copy is still a copy.'),
        ('Harvest now.', 'CAPTURE', 'Intercept encrypted traffic and keep it.'),
        ('Decrypt later.', 'FUTURE ACCESS', 'Try to unlock the same data years later.'),
    ]):
        bg, d = stage(4, 'Harvest now, decrypt later')
        heading(d, 'THE THREAT MODEL', title, sub, top=343, size=103)
        layer_card(bg, (1004, 255, 1784, 765), '#0b182d', '#36597d', 26, (32, 91, 136, 58))
        text(d, 1044, 302, 'ENCRYPTED TRAFFIC', 25, CYAN, 'mono')
        rng = random.Random(83)
        for row in range(7):
            data = '   '.join(''.join(rng.choice('0123456789ABCDEF') for _ in range(4)) for _ in range(7))
            text(d, 1046, 378+37*row, data, 23, '#8da9c7' if row == i+2 else '#4c6789', 'mono')
        d.line((1047, 672, 1722, 672), fill='#3b5f82', width=2)
        text(d, 1046, 697, 'TODAY', 22, CYAN, 'mono')
        text(d, 1720, 697, label, 22, ROSE if i == 2 else CYAN, 'mono', 'rt')
        px = [1090, 1120, 1685][i]
        d.ellipse((px-8, 664, px+8, 680), fill=ROSE if i == 2 else CYAN)
        save(bg, [3.7, 7, 8][i], .037)

    bg, d = stage(5, 'The reveal', True)
    clipped(bg, logo, (1048, 158, 1748, 858), 35)
    d.rounded_rectangle((1048, 158, 1748, 858), 35, outline='#c4d2ed', width=2)
    heading(d, 'INTRODUCING', 'QGuard|Messaging.', 'Windows desktop and Android', True, top=306, size=139)
    save(bg, 3.93, .026, .36)

    for index, (kind, title, sub, duration, box) in enumerate([
        ('devices', 'Send it|privately.', 'Messages, video clips and documents.', 4, (954, 230, 1803, 845)),
        ('calls', 'Talk|face to face.', 'End-to-end encrypted voice and video calls.', 2.4, (854, 337, 1816, 766)),
        ('chat', 'Secure Chat.', 'Post-quantum key protection built in.', 8.67, (1058, 160, 1724, 891)),
    ]):
        bg, d = stage(6, 'Secure Chat', True)
        heading(d, 'SECURE CHAT', title, sub, True, top=316, size=109)
        x, y, right, bottom = box
        layer_card(bg, (x-10, y-10, right+10, bottom+10), '#d2e1f5', '#b2c3dd', radius=31)
        clipped(bg, product[kind], box, 24)
        text(d, x, bottom+25, 'ILLUSTRATIVE PRODUCT VIEW', 19, '#476183', 'mono')
        save(bg, duration, .022)

    for i, (alg, title, detail, standard, sec) in enumerate([
        ('ML-KEM-1024', 'Establish|the keys.', 'Combined with X25519 in a hybrid design.', 'NIST FIPS 203', 10),
        ('ML-DSA', 'Verify|the sender.', 'A post-quantum digital signature.', 'NIST FIPS 204', 5.7),
        ('AES-256-GCM', 'Encrypt|the content.', 'Authenticated symmetric encryption.', 'AES · GCM', 5.3),
    ]):
        bg, d = stage(7+i, 'Cryptography')
        heading(d, 'BEHIND THE SCENES', title, detail, top=326, size=114)
        lattice(d, 1402, 536, 333, 42+i*62)
        layer_card(bg, (1032, 413, 1770, 664), '#0c172e', '#49749f', 26, (74, 147, 204, 70))
        text(d, 1401, 484, alg, 74, WHITE, anchor='mt')
        text(d, 1401, 586, standard, 24, CYAN, 'mono', 'mt')
        save(bg, sec, .032)

    bg, d = stage(10, 'Quantum Vault', True)
    heading(d, 'QUANTUM VAULT', 'Keep it|to yourself.', 'Encrypt sensitive files on your device.', True, top=317, size=118)
    layer_card(bg, (927, 281, 1820, 831), '#d2e1f5', '#b2c3dd', 31)
    clipped(bg, product['vault'], (939, 293, 1808, 819), 24)
    text(d, 941, 858, 'ILLUSTRATIVE PRODUCT VIEW', 19, '#476183', 'mono')
    save(bg, 10.4, .025, .34)

    bg, d = stage(11, 'Vault controls', True)
    heading(d, 'QUANTUM VAULT', 'Local|by default.', 'Encrypted backup and sharing are optional.', True, top=312, size=119)
    for i, (label, sub, mark) in enumerate([
        ('Android', 'Encrypt individual files', 'lock'),
        ('Windows desktop', 'Seal files or entire folders', 'folder'),
        ('Optional', 'Encrypted backup and sharing', 'lock'),
    ]):
        y = 240+i*191
        layer_card(bg, (1006, y, 1779, y+145), '#f9fbff', '#c1cfe7', 23)
        icon(d, mark, 1045, y+37, INDIGO)
        text(d, 1152, y+26, label, 43, INK)
        text(d, 1154, y+85, sub, 27, '#425879', 'body')
    save(bg, 9.6, .024)

    bg, d = stage(12, 'Explore QGuard', True)
    clipped(bg, logo, (1086, 143, 1793, 850), 35)
    d.rounded_rectangle((1086, 143, 1793, 850), 35, outline='#bdcce8', width=2)
    heading(d, 'QGUARD MESSAGING', 'Share today.|Stay private|tomorrow.', light=True, top=247, size=110)
    d.rounded_rectangle((108, 687, 832, 780), 46, fill=INK)
    text(d, 470, 735, 'qguardhelix.com/qguard-messaging', 34, WHITE, 'body', 'mm')
    text(d, 108, 813, 'WINDOWS DESKTOP  /  ANDROID', 25, '#344f7b', 'mono')
    save(bg, 13, .012, .34)

    bg, d = stage(1, 'What you share')
    lattice(d, 1404, 531, 358, 37)
    for i, kind in enumerate(('chat', 'video', 'folder')):
        x = 1257+i*101
        layer_card(bg, (x-15, 465, x+75, 560), '#0d1e38', '#3a5d82', 19)
        icon(d, kind, x-1, 480)
    heading(d, 'PRIVACY OVER TIME', 'What you share|still matters.', top=312, size=117)
    save(bg, 6, .062)
    return out


def encode(ff, i, shot):
    path, seconds, zoom, fade = shot
    frames = round(seconds*FPS)
    target = WORK / f'clip-{i:02d}.mp4'
    # Upsampling before zoom avoids visible subpixel jitter in fine type.
    live = i in PRODUCT_SHOTS or i in (5, 6, 7)
    motion = f"scale=3840:2160,zoompan=z='1+{zoom}*(1-cos(PI*on/{frames}))/2':x='iw/2-iw/zoom/2':y='ih/2-ih/zoom/2':d={1 if live else frames}:s=1920x1080:fps={FPS},setsar=1"
    if i in (0, 3, 4, 5, 8, 12, 15, 17):
        fade_color = '0xe9effa' if i in (8, 15, 17) else '0x040915'
        motion += f',fade=t=in:d={fade}:color={fade_color}'
    cmd = [ff, '-hide_banner', '-loglevel', 'error', '-y', '-filter_threads', '2', '-filter_complex_threads', '2']
    if i in PRODUCT_SHOTS:
        start, end, crop, (x, y, right, bottom) = PRODUCT_SHOTS[i]
        width, height = right-x, bottom-y
        mask = Image.new('L', (width, height))
        ImageDraw.Draw(mask).rounded_rectangle((0, 0, width-1, height-1), radius=24, fill=255)
        mask_file = WORK / f'mask-{i:02d}.png'
        mask.save(mask_file)
        stretch = (seconds+.08)/(end-start)
        media = PREVIOUS / 'renders/proof-1080p.mp4'
        cmd.extend(['-loop', '1', '-framerate', str(FPS), '-i', str(path), '-ss', str(start), '-t', str(end-start), '-i', str(media),
                    '-loop', '1', '-framerate', str(FPS), '-i', str(mask_file), '-filter_complex',
                    f'[1:v]{crop},scale={width}:{height},setpts={stretch}*PTS,fps={FPS},format=rgba[media];'
                    f'[media][2:v]alphamerge[panel];[0:v][panel]overlay={x}:{y},{motion}[video]', '-map', '[video]'])
    elif live:
        beam = Image.new('RGBA', (138, 504))
        b = ImageDraw.Draw(beam)
        for x in range(138):
            opacity = int(22 * math.exp(-((x-66)/28)**2))
            b.line((x, 0, x, 503), fill=(106, 218, 255, opacity))
        b.line((65, 0, 65, 503), fill=(131, 223, 255, 100), width=2)
        beam_file = WORK / f'beam-{i:02d}.png'
        beam.save(beam_file)
        sweep = f"[0:v][1:v]overlay=x='1040+570*(1-cos(PI*clip((t-.28)/{seconds*.70},0,1)))/2':y=258:enable='between(t,.28,{.28+seconds*.70})',{motion}[video]"
        cmd.extend(['-loop', '1', '-framerate', str(FPS), '-i', str(path), '-loop', '1', '-framerate', str(FPS), '-i', str(beam_file),
                    '-filter_complex', sweep, '-map', '[video]'])
    else:
        cmd.extend(['-i', str(path), '-vf', motion])
    subprocess.run([*cmd, '-frames:v', str(frames), '-an', '-c:v', 'libx264', '-threads', '3',
                    '-preset', 'veryfast', '-crf', '17', '-pix_fmt', 'yuv420p', str(target)], check=True)
    print(f'Encoded shot {i+1:02d} ({seconds:g}s)', flush=True)
    return target


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ffmpeg', required=True)
    parser.add_argument('--logo', type=Path, required=True)
    parser.add_argument('--stills-only', action='store_true')
    parser.add_argument('--reuse-stills', action='store_true')
    parser.add_argument('--rebuild', help='Comma-separated zero-based shot indexes to encode again')
    args = parser.parse_args()
    WORK.mkdir(parents=True, exist_ok=True)
    DELIVERY.mkdir(parents=True, exist_ok=True)
    manifest = WORK / 'shots.txt'
    if args.reuse_stills:
        sequence = [(Path(path), float(seconds), float(zoom), float(fade)) for path, seconds, zoom, fade in (line.split('|') for line in manifest.read_text().splitlines())]
    else:
        sequence = shots(args.ffmpeg, args.logo)
        manifest.write_text('\n'.join('|'.join(map(str, row)) for row in sequence))
    assert sum(round(seconds*FPS) for _, seconds, _, _ in sequence) == 120*FPS
    if args.stills_only:
        return
    rebuild = set(map(int, args.rebuild.split(','))) if args.rebuild else set(range(len(sequence)))
    with ThreadPoolExecutor(max_workers=3) as pool:
        clips = list(pool.map(lambda item: encode(args.ffmpeg, *item) if item[0] in rebuild else WORK / f'clip-{item[0]:02d}.mp4', enumerate(sequence)))
    clips.insert(3, clips.pop())
    (WORK / 'concat.txt').write_text('\n'.join(f"file '{path.name}'" for path in clips))
    subprocess.run([args.ffmpeg, '-hide_banner', '-loglevel', 'error', '-y', '-f', 'concat', '-safe', '0',
                    '-i', str(WORK / 'concat.txt'), '-c', 'copy', str(WORK / 'picture.mp4')], check=True)


if __name__ == '__main__':
    main()
