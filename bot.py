import os
import io
import asyncio
import datetime
import tempfile
import re
import json
import math
import time
import traceback
import aiohttp
import discord
from collections import Counter
from discord.ext import commands
from aiohttp import web

import antigrab

TOKEN = os.environ.get("DISCORD_TOKEN")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEOBF_DIR = os.environ.get("DEOBF_DIR", "./Prometheus-Deobfuscator-main")
MOONSEC_V2_DIR = os.path.join(BASE_DIR, "moonsec-v2-deobfuscator")
MOONVEIL_DIR = os.path.join(BASE_DIR, "moonveil-deobf")
LUAOBFUSCATOR_DIR = os.path.join(BASE_DIR, "luaobfuscator-deobf", "luaobfuscator")
LURAPH_DIR = os.path.join(BASE_DIR, "luraph-deobf")
LURAPH_CMD = [os.environ.get("NODE", "node"), "deob.js", "{in}", "-o", "{out}"]
LURAPH_TIMEOUT = int(os.environ.get("LURAPH_TIMEOUT", "300"))
ENVLOG_PATH = os.path.join(BASE_DIR, "envlog.luau")
ENVLOG2_PATH = os.environ.get("ENVLOG2_PATH", os.path.join(BASE_DIR, "envlog2.luau"))
NODE = os.environ.get("NODE", "node")
LUNE = os.environ.get("LUNE", "/usr/local/bin/lune")
DEOBF_TIMEOUT = int(os.environ.get("DEOBF_TIMEOUT", "180"))
CONFIG_FILE = os.environ.get("CONFIG_FILE", "config.json")

HEADER = "Deobfuscate By DropX :)\n\n"
BOT_NAME = "DropX"
MAX_FILE = 5 * 1024 * 1024

# Quanto tempo o resultado fica no chat antes de ser apagado (segundos)
DELETE_AFTER = int(os.environ.get("DELETE_AFTER", "600"))
# Quanto tempo a mensagem do utilizador (com o link/ficheiro) fica no chat antes de ser apagada
USER_MSG_DELETE_AFTER = int(os.environ.get("USER_MSG_DELETE_AFTER", "60"))
# Anti-grabber: 3 tentativas bloqueadas => bloqueio temporário
STRIKE_LIMIT = 3
STRIKE_LOCK_SECONDS = 30 * 60
# Quem enviar um grabber fica em timeout (mute) durante este tempo
MUTE_DURATION = datetime.timedelta(days=1)

# Emoji da marca (substitui a lua). O bot tem de estar no servidor do emoji.
BRAND_EMOJI_ID = 1569037087439724644
BRAND = f"<:dropx:{BRAND_EMOJI_ID}>"
BRAND_PARTIAL = discord.PartialEmoji(name="dropx", id=BRAND_EMOJI_ID)

WEAREDEVS_EMOJI_ID = 1565837351769481216
MOONSEC_EMOJI_ID = 1566041038852718692
MOONVEIL_EMOJI_ID = 1566062539962323085
LUAOBF_EMOJI_ID = 1566411737727770714
LURAPH_EMOJI_ID = 1570064264285392986

WEAREDEVS_ICON = "https://www.google.com/s2/favicons?domain=wearedevs.net&sz=128"
MOONSEC_ICON = f"https://cdn.discordapp.com/emojis/{MOONSEC_EMOJI_ID}.png"
MOONVEIL_ICON = f"https://cdn.discordapp.com/emojis/{MOONVEIL_EMOJI_ID}.png"
LUAOBF_ICON = f"https://cdn.discordapp.com/emojis/{LUAOBF_EMOJI_ID}.png"
LURAPH_ICON = f"https://cdn.discordapp.com/emojis/{LURAPH_EMOJI_ID}.png"
BRAND_ICON = f"https://cdn.discordapp.com/emojis/{BRAND_EMOJI_ID}.png"

# ---------- ESTILO ----------
C_BRAND = 0x2ECC71
C_OK = 0x2ECC71
C_WORK = 0xF1C40F
C_WARN = 0xE67E22
C_ERR = 0xE74C3C
C_DARK = 0x2B2D31

OBF_STYLE = {
    "Prometheus": (0xE67E22, WEAREDEVS_ICON),
    "MoonSec V2": (0x3498DB, MOONSEC_ICON),
    "MoonVeil": (0x9B59B6, MOONVEIL_ICON),
    "LuaObfuscator VM": (0xF1C40F, LUAOBF_ICON),
    "Luraph": (0xE91E63, LURAPH_ICON),
    "Custom / Unknown": (0x95A5A6, None),
}


def bar(score10: int) -> str:
    score10 = max(0, min(10, score10))
    return "▰" * score10 + "▱" * (10 - score10)


def progress_bar(pct: float, width: int = 16) -> str:
    pct = max(0.0, min(100.0, pct))
    filled = int(round(width * pct / 100))
    return "▰" * filled + "▱" * (width - filled)


def fmt_bytes(n: float) -> str:
    if n < 1024:
        return f"{int(n)} B"
    n /= 1024
    if n < 1024:
        return f"{n:.1f} KB"
    return f"{n / 1024:.1f} MB"


def fmt_uptime(sec: int) -> str:
    d, r = divmod(sec, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    parts = []
    if d: parts.append(f"{d}d")
    if h: parts.append(f"{h}h")
    if m: parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)


def brand_footer(extra: str = "") -> str:
    return f"Made by {BOT_NAME}" + (f" · {extra}" if extra else "")


def make_embed(title, description=None, color=C_BRAND, footer=True):
    e = discord.Embed(title=title, description=description, color=color)
    if bot.user:
        e.set_author(name=BOT_NAME, icon_url=BRAND_ICON)
    if footer:
        e.set_footer(text=brand_footer())
    return e


def progress_embed(title: str, pct: float, stage: str, who_id: int = None, color=C_WORK):
    """Barra de progresso a encher (substitui a antiga lista de passos)."""
    desc = f"**{stage}**\n`{progress_bar(pct)}`  **{int(pct)}%**"
    if who_id:
        desc += f"\n\nRequested by <@{who_id}>"
    return make_embed(title, desc, color)


async def _animate(editor, title: str, who_id: int, stage: str, start: float, end: float,
                   est: float = 10.0, interval: float = 2.5, first_delay: float = 0.0):
    """Faz a barra avançar de forma suave até ~90% (usa a duração típica `est` da ferramenta)."""
    try:
        if first_delay:
            await asyncio.sleep(first_delay)
        t0 = time.time()
        while True:
            pct = start + (end - start) * (1 - math.exp(-3.0 * (time.time() - t0) / max(est, 2.0)))
            try:
                await editor(progress_embed(title, pct, stage, who_id))
            except Exception:
                pass
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        return


async def run_with_progress(editor, label: str, who_id: int, runner, source: bytes, already_shown: bool = False):
    """Corre a ferramenta enquanto anima a barra. Devolve (resultado, erro, segundos_da_ferramenta)."""
    anim = asyncio.create_task(
        _animate(editor, label, who_id, "Running tool", 15, 92,
                 est=_tool_avg.get(label, 10.0), first_delay=1.5 if already_shown else 0.0)
    )
    started = time.time()
    try:
        res, err = await runner(source)
    finally:
        anim.cancel()
        # espera pelo fim da animação para que nenhuma edição antiga chegue depois do resultado
        await asyncio.gather(anim, return_exceptions=True)
    took = time.time() - started
    print(f"[deliver] {label}: tool finished in {took:.1f}s ok={bool(res)}"
          + ("" if res else f" err={(err or '')[-300:]!r}"), flush=True)
    if res:
        old = _tool_avg.get(label)
        _tool_avg[label] = took if old is None else 0.6 * old + 0.4 * took
    return res, err, took


async def finish_and_scan(editor, label: str, who_id: int, res: bytes):
    """Mostra a barra a 100% enquanto o scan do resultado corre em paralelo."""
    async def _full():
        try:
            await asyncio.wait_for(editor(progress_embed(label, 100, "Delivering", who_id, C_OK)), 4)
        except Exception:
            pass

    async def _scan():
        try:
            return await finalize_output(res)
        except Exception:
            # o scan nunca pode impedir a entrega: entrega o resultado tal como está
            traceback.print_exc()
            return res, antigrab.ScanResult()

    out_scan, _, _ = await asyncio.gather(_scan(), _full(), asyncio.sleep(0.4))
    print(f"[deliver] {label}: scan done, {len(out_scan[0])} bytes", flush=True)
    return out_scan


async def deliver_result(edit_fn, channel, embed, out: bytes, filename: str) -> bool:
    """Entrega o ficheiro editando a mensagem; se falhar, envia como mensagem nova no canal."""
    try:
        await asyncio.wait_for(
            edit_fn(embed=embed, attachments=[discord.File(fp=io.BytesIO(out), filename=filename)]), 90)
        print(f"[deliver] {filename}: delivered by edit", flush=True)
        return True
    except Exception:
        traceback.print_exc()
        print(f"[deliver] {filename}: edit failed, sending a new message", flush=True)
    try:
        await channel.send(embed=embed, file=discord.File(fp=io.BytesIO(out), filename=filename))
        try:
            await edit_fn(embed=embed)  # tira a barra presa da mensagem original
        except Exception:
            pass
        print(f"[deliver] {filename}: delivered by new message", flush=True)
        return True
    except Exception:
        traceback.print_exc()
        return False


def error_embed(tool_label: str, err: str, who_id: int = None):
    e = make_embed("❌ Failed", f"**{tool_label}** could not finish." + (f"\nRequested by <@{who_id}>" if who_id else ""), C_ERR)
    e.add_field(name="Details", value=f"```\n{(err or 'no details')[-900:]}\n```", inline=False)
    e.set_footer(text=brand_footer("this message will be deleted in 60s"))
    return e


def security_text(res: "antigrab.ScanResult") -> str:
    lvl = res.level
    if lvl == "clean":
        return "✅ No grabber patterns found"
    if lvl == "info":
        return "ℹ️ " + ", ".join(f.label for f in res.findings[:2])
    if lvl == "suspicious":
        return "⚠️ Suspicious: " + ", ".join(f.label for f in res.findings[:3])
    return "🚫 Grabber patterns: " + ", ".join(f.label for f in res.findings[:3])


def result_embed(tool_label: str, size: int, elapsed: float, scan_res, who_id: int, color=C_OK, detail: str = None):
    warn = scan_res is not None and scan_res.level in ("suspicious", "blocked")
    e = discord.Embed(
        title="Done" if not warn else "Done · ⚠️ review the output",
        description=f"Requested by <@{who_id}>",
        color=C_WARN if warn else color,
    )
    e.set_author(name=BOT_NAME, icon_url=BRAND_ICON)
    e.add_field(name="🛠️ Tool", value=tool_label, inline=True)
    e.add_field(name="📦 Size", value=fmt_bytes(size), inline=True)
    e.add_field(name="⏱️ Time", value=f"{elapsed:.1f}s" + (f"\n`{detail}`" if detail else ""), inline=True)
    # só mostra o Anti-Grabber quando há algo a avisar
    if scan_res is not None and scan_res.level != "clean":
        e.add_field(name="🛡️ Anti-Grabber", value=security_text(scan_res), inline=False)
    e.set_footer(text=brand_footer())
    return e


def blocked_embed(res, who_id: int, size: int, punish: str = None):
    e = discord.Embed(
        title="🛡️ Anti-Grabber · Blocked",
        description=(
            f"<@{who_id}>, this script looks like a **token / credential grabber** and was **not processed**.\n"
            "If you pasted your own token by mistake, reset it right now."
        ),
        color=C_ERR,
    )
    e.set_author(name=BOT_NAME, icon_url=BRAND_ICON)
    e.add_field(name="Risk", value=f"`{bar(res.score // 10)}` {res.score}/100", inline=True)
    e.add_field(name="Size", value=fmt_bytes(size), inline=True)
    if punish:
        e.add_field(name="Punishment", value=punish, inline=False)
    lines = [f"• **{f.label}**" + (f"\n  `{f.sample}`" if f.sample else "") for f in res.findings[:6]]
    e.add_field(name="Findings", value="\n".join(lines)[:1000] or "-", inline=False)
    e.set_footer(text=brand_footer("your message was removed"))
    return e


# ---------- CONFIG ----------
DEFAULT_CONFIG = {"channel_id": None, "antigrab": True, "log_channel_id": None}


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                cfg.update(json.load(f))
        except Exception:
            pass
    return cfg


def save_config(cfg):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f)


config = load_config()

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix=".", intents=intents)
bot.remove_command("help")

_moonsec_lock = asyncio.Lock()
_moonveil_lock = asyncio.Lock()
_luraph_sem = asyncio.Semaphore(2)
_bg_tasks = set()
_strikes = {}  # user_id -> {"count": int, "until": float}
_tool_avg = {}  # label -> duração média (s) da ferramenta, para calibrar a barra

# ---------- MENSAGENS: apagar / agendar ----------
async def safe_delete(msg, delay: float = 0):
    try:
        if delay:
            await asyncio.sleep(delay)
        await msg.delete()
    except Exception:
        pass


def schedule_delete(msg, delay: float):
    task = asyncio.create_task(safe_delete(msg, delay))
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)


async def send(ctx: commands.Context, **kwargs):
    """Envia para o canal (sem 'reply', porque a mensagem do utilizador é apagada)."""
    return await ctx.channel.send(**kwargs)


# ---------- DETECTOR DE OFUSCADOR ----------
class _OrderedFind:
    """Equivalente a `a.*b.*c` (DOTALL) mas em tempo linear (sem backtracking catastrófico)."""

    def __init__(self, *needles: str):
        self.needles = needles

    def search(self, code: str):
        pos = 0
        for n in self.needles:
            i = code.find(n, pos)
            if i < 0:
                return None
            pos = i + len(n)
        return True


SIGNATURES = {
    "Prometheus": [
        (20, re.compile(r'return\s*\(function\s*\(\.\.\.\)\s*local\s+\w\s*=\s*\{')),
        (45, re.compile(r"=\{\s*(?:'[A-Za-z0-9]+'\s*,\s*){4,}'[A-Za-z0-9]+'\s*\}")),
        (20, re.compile(r'\b\d{4,7}-\(-?\d{4,7}\)')),
        (15, re.compile(r'math\.floor')),
        (10, _OrderedFind("string.char", "table.concat", "string.sub")),
        (15, re.compile(r'for\s+\w+,\w+\s+in\s+ipairs\s*\(')),
        (10, re.compile(r'getfenv\s+and\s+getfenv\(\)\s+or\s+_ENV')),
        (20, re.compile(r'local\s+function\s+\w\s*\(\w\)\s*return\s+\w\[\w\+')),
        (12, re.compile(r'bit32\.rrotate')),
        (8, re.compile(r'bit32\.rshift')),
        (35, re.compile(r"^return\s*\(\s*function\s*\(\s*\.\.\.\s*\)\s*local\s+\w\s*=\s*\{\s*'", re.MULTILINE)),
    ],
    "MoonSec V2": [
        (25, re.compile(r'Protected_by_MoonSecV2')),
        (50, re.compile(r'[\u3480-\u34c0]{5,}')),
        (25, re.compile(r'_msec\s*=')),
        (20, re.compile(r'#\[\[[^\]]{3,}\]\]')),
        (15, re.compile(r'\(0x[0-9a-f]+/\d+\)')),
        (10, re.compile(r'discord\.gg/gQEH')),
    ],
    "MoonVeil": [
        (50, re.compile(r'--\s*This script was generated using (?:the )?MoonVeil')),
        (40, re.compile(r'moonveil\.cc')),
        (35, re.compile(r'local\s+\w+,\w+,\w+,\w+=getmetatable,bit32\.bxor,pairs,type')),
        (25, re.compile(r'bit32\s*\.\s*lshift\s*,\s*bit32\s*\.\s*rshift\s*,\s*bit32\s*\.\s*band')),
    ],
    "LuaObfuscator VM": [
        (50, re.compile(r'local\s+v0\s*=\s*tonumber\s*;\s*local\s+v1\s*=\s*string\.byte')),
        (35, re.compile(r'local\s+function\s+v15\s*\(v16,v17')),
        (50, re.compile(r'return\s+v15\s*\(\s*"LOL!')),
        (15, re.compile(r'getfenv\s+or\s+function\s*\(\s*\)\s*return\s+_ENV')),
    ],
    "Luraph": [
        (60, re.compile(r'--\s*This (?:file|script) was (?:protected|generated) using Luraph Obfuscator')),
        (55, re.compile(r'"LPH\|[0-9A-Fa-f]{20,}"')),
        (35, re.compile(r'return\s*\(\s*\{[A-Z]{1,3}=bit32\.\w+')),
    ],
}
_DEFINITELY_OBF = [
    re.compile(r'Protected_by_MoonSecV2'),
    re.compile(r'This script was generated using (?:the )?MoonVeil'),
    re.compile(r'return\s+v15\s*\(\s*"LOL!'),
    re.compile(r'[\u3480-\u34c0]{5,}'),
    re.compile(r'This (?:file|script) was (?:protected|generated) using Luraph'),
]
_WEAREDEVS_SIGNALS = [
    re.compile(r'wearedevs\.net/obfuscator'),
    re.compile(r'\[\[\s*v\d+\.\d+\.\d+\s+https?://'),
]


def _any_match(patterns, code):
    for pat in patterns:
        try:
            if pat.search(code):
                return True
        except Exception:
            pass
    return False


def detect(code):
    definitely = _any_match(_DEFINITELY_OBF, code)
    wad = _any_match(_WEAREDEVS_SIGNALS, code)
    raw_scores = {}
    for obf_name, patterns in SIGNATURES.items():
        score = 0.0
        for weight, pattern in patterns:
            try:
                if pattern.search(code):
                    score += weight
            except Exception:
                pass
        if obf_name == "Prometheus" and definitely:
            score += 10
        if obf_name == "Prometheus" and wad:
            score -= 40
        raw_scores[obf_name] = max(score, 0.0)
    top = sorted(raw_scores.items(), key=lambda x: x[1], reverse=True)
    top_name, top_score = top[0]
    if top_score < 20:
        return [("Custom / Unknown", 0.0)]
    total = sum(raw_scores.values()) or 1
    out = []
    for name, sc in raw_scores.items():
        if name == top_name:
            conf = min(99.9, (sc / total) * 55 + min(sc / 120, 1) * 45)
        else:
            conf = 0.0 if sc <= 0 else min(99.9, (sc / top_score) * 20)
        out.append((name, round(conf, 1)))
    out.sort(key=lambda x: x[1], reverse=True)
    return out


def score_1_to_10(pct: float) -> int:
    return max(1, min(10, int(round(pct / 10.0))))


# ---------- WEB ----------
async def handle_ping(request):
    return web.Response(text="DropX Bot Online")


async def start_web_server():
    app = web.Application()
    app.router.add_get("/", handle_ping)
    runner = web.AppRunner(app)
    await runner.setup()
    port = int(os.environ.get("PORT", 8080))
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    print(f"Web server running on port {port}", flush=True)


# ---------- RUNNERS ----------
async def run_deobf(source: bytes):
    with tempfile.TemporaryDirectory() as tmp:
        in_path = os.path.join(tmp, "input.lua")
        out_path = os.path.join(tmp, "out.lua")
        with open(in_path, "wb") as f:
            f.write(source)
        try:
            proc = await asyncio.create_subprocess_exec(
                NODE, "bin/pdeobf.js", in_path, "-o", out_path,
                cwd=DEOBF_DIR,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=DEOBF_TIMEOUT)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return None, f"timeout ({DEOBF_TIMEOUT}s)"
        except FileNotFoundError:
            return None, "Node.js not found"
        if proc.returncode != 0 or not os.path.exists(out_path):
            return None, stderr.decode("utf-8", "replace")[-1200:]
        with open(out_path, "rb") as f:
            return (HEADER.encode("utf-8") + f.read()), ""


async def run_moonsec_v2(source: bytes):
    if not os.path.isdir(MOONSEC_V2_DIR):
        return None, "moonsec-v2-deobfuscator folder missing"
    async with _moonsec_lock:
        with tempfile.TemporaryDirectory() as tmp:
            in_path = os.path.join(tmp, "input.lua")
            with open(in_path, "wb") as f:
                f.write(source)
            try:
                proc = await asyncio.create_subprocess_exec(
                    "python", "main.py", in_path,
                    cwd=MOONSEC_V2_DIR,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:
                    pass
                return None, "timeout (300s)"
            except FileNotFoundError:
                return None, "Python/main.py not found"
            out_path = os.path.join(MOONSEC_V2_DIR, "output.lua")
            if proc.returncode != 0 or not os.path.exists(out_path):
                msg = (stdout + stderr).decode("utf-8", "replace").strip()
                return None, msg[-1200:] or "failed with no output"
            with open(out_path, "rb") as f:
                result = f.read()
            try:
                os.remove(out_path)
            except Exception:
                pass
            return result, ""


async def run_moonveil(source: bytes):
    if not os.path.isdir(MOONVEIL_DIR):
        return None, "moonveil-deobf folder missing"
    async with _moonveil_lock:
        with tempfile.TemporaryDirectory() as tmp:
            in_path = os.path.join(tmp, "input.lua")
            out_path = os.path.join(tmp, "recovered.lua")
            with open(in_path, "wb") as f:
                f.write(source)
            try:
                proc = await asyncio.create_subprocess_exec(
                    "python", "-m", "moonveil", "deobfuscate", in_path, "-o", out_path,
                    cwd=MOONVEIL_DIR,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:
                    pass
                return None, "timeout (180s)"
            except FileNotFoundError:
                return None, "Python/moonveil not found"
            if proc.returncode != 0 or not os.path.exists(out_path):
                msg = (stdout + stderr).decode("utf-8", "replace").strip()
                return None, msg[-1200:] or f"exit code {proc.returncode}"
            with open(out_path, "rb") as f:
                return f.read(), ""


async def run_luaobfuscator(source: bytes):
    if not os.path.isdir(LUAOBFUSCATOR_DIR):
        return None, "luaobfuscator folder missing"
    async with _moonveil_lock:
        with tempfile.TemporaryDirectory() as tmp:
            in_path = os.path.join(tmp, "input.lua")
            with open(in_path, "wb") as f:
                f.write(source)
            try:
                proc = await asyncio.create_subprocess_exec(
                    "node", "src/cli.js", in_path, "--stdout",
                    cwd=LUAOBFUSCATOR_DIR,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:
                    pass
                return None, "timeout (180s)"
            except FileNotFoundError:
                return None, "Node.js not found"
            if proc.returncode != 0:
                return None, stderr.decode("utf-8", "replace").strip()[-1200:] or f"exit code {proc.returncode}"
            return stdout, ""


async def run_luraph(source: bytes):
    if not os.path.isdir(LURAPH_DIR):
        return None, "luraph-deobf folder missing"
    async with _luraph_sem:
        with tempfile.TemporaryDirectory() as tmp:
            in_path = os.path.join(tmp, "input.lua")
            out_path = os.path.join(tmp, "out.lua")
            with open(in_path, "wb") as f:
                f.write(source)
            cmd = [a.replace("{in}", in_path).replace("{out}", out_path) for a in LURAPH_CMD]
            # ambiente limpo: o script de terceiros não vê o DISCORD_TOKEN
            safe_env = {
                "PATH": os.environ.get("PATH", ""),
                "HOME": os.environ.get("HOME", "/tmp"),
                "PYTHON_BIN": os.environ.get("PYTHON_BIN", "python"),
            }
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd, cwd=LURAPH_DIR, env=safe_env,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=LURAPH_TIMEOUT)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
                return None, f"timeout ({LURAPH_TIMEOUT}s)"
            except FileNotFoundError:
                return None, f"command not found: {LURAPH_CMD[0]}"
            if proc.returncode != 0:
                msg = (stdout + stderr).decode("utf-8", "replace").strip()
                return None, msg[-1200:] or f"exit code {proc.returncode}"
            if os.path.exists(out_path):
                with open(out_path, "rb") as f:
                    return f.read(), ""
            if stdout.strip():
                return stdout, ""
            return None, "no output produced"


def envlog_config_lua() -> str:
    """Config injetada no env logger através de variáveis de ambiente."""
    parts = []
    if os.environ.get("ENVLOG_TRACE_READS") == "1":
        parts.append("TRACE_GLOBAL_READS = true")
    if os.environ.get("ENVLOG_AUTO_STUB") == "1":
        parts.append("AUTO_STUB_UPPER = true")
    return "{" + ", ".join(parts) + "}"


async def _run_lune_logger(path: str, source: bytes, timeout: float):
    name = os.path.basename(path)
    if not os.path.exists(path):
        return None, f"{name} not found in project root"
    try:
        with open(path, "r", encoding="utf-8") as f:
            envlog_code = f.read()
    except Exception as e:
        return None, f"failed to read {name}: {e}"

    script_text = source.decode("utf-8", "ignore")
    eq = "=" * 5
    while (']' + eq + ']') in script_text:
        eq += "="
    safe_source = f"[{eq}[{script_text}]{eq}]"

    prelude = (
        f"local __SOURCE = {safe_source}\n"
        f"local __ENVLOG_CONFIG = {envlog_config_lua()}\n"
        f"local __CONFIG = {{}}\n"
        f"local __ROBLOX = {{ enums = '', classes = '' }}\n"
        f"local __UNICODE = {{ decomp = '', ccc = '', comp = '' }}\n"
        f"local __P2D = {{}}\n"
        f"local __CHUNKS = {{}}\n"
    )
    runner = prelude + envlog_code

    with tempfile.TemporaryDirectory() as tmp:
        runner_path = os.path.join(tmp, "envlog_runner.luau")
        with open(runner_path, "w", encoding="utf-8") as f:
            f.write(runner)
        try:
            proc = await asyncio.create_subprocess_exec(
                LUNE, "run", runner_path,
                cwd=BASE_DIR,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return None, f"timeout ({int(timeout)}s)"
        except FileNotFoundError:
            return None, f"lune not found at {LUNE}"

        if proc.returncode != 0:
            return None, f"lune exit {proc.returncode}: {stderr.decode('utf-8', 'replace')[-1200:]}"
        out = stdout.decode("utf-8", "replace")
        if not out.strip():
            return None, f"{name} produced no output"
        return out.encode("utf-8"), ""


async def run_envlog(source: bytes):
    return await _run_lune_logger(ENVLOG_PATH, source, 300)


async def run_envlog2(source: bytes):
    return await _run_lune_logger(ENVLOG2_PATH, source, float(os.environ.get("ENVLOG2_TIMEOUT", "120")))


async def fetch_url(url: str):
    if not re.match(r"^https?://", url):
        return None, "Invalid URL"
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(url, timeout=aiohttp.ClientTimeout(total=20)) as r:
                if r.status != 200:
                    return None, f"HTTP {r.status}"
                return await r.read(), ""
    except Exception as e:
        return None, str(e)


# ---------- ANTI-GRABBER ----------
def is_locked(user_id: int) -> int:
    """Devolve os segundos que faltam de bloqueio (0 = livre)."""
    s = _strikes.get(user_id)
    if not s:
        return 0
    left = int(s.get("until", 0) - time.time())
    return max(0, left)


def add_strike(user_id: int) -> int:
    s = _strikes.setdefault(user_id, {"count": 0, "until": 0})
    s["count"] += 1
    if s["count"] >= STRIKE_LIMIT:
        s["until"] = time.time() + STRIKE_LOCK_SECONDS
        s["count"] = 0
    return s["count"]


async def mute_member(member, reason: str):
    """Timeout (mute) de 1 dia. Devolve (ok, motivo_da_falha)."""
    if not isinstance(member, discord.Member):
        return False, "not a server member"
    try:
        await member.timeout(MUTE_DURATION, reason=reason)
        return True, ""
    except discord.Forbidden:
        return False, "missing permission or role above the bot"
    except Exception as e:
        return False, repr(e)


async def log_block(ctx: commands.Context, res, size: int, command: str,
                    source: bytes = None, punish: str = None):
    chan_id = config.get("log_channel_id")
    if not chan_id:
        return
    chan = bot.get_channel(chan_id)
    if chan is None:
        return
    e = discord.Embed(title="🛡️ Anti-Grabber · blocked upload", color=C_ERR)
    e.set_author(name=BOT_NAME, icon_url=BRAND_ICON)
    e.add_field(name="User", value=f"{ctx.author.mention} (`{ctx.author.id}`)", inline=True)
    e.add_field(name="Command", value=f"`.{command}`", inline=True)
    e.add_field(name="Risk", value=f"{res.score}/100 · {fmt_bytes(size)}", inline=True)
    if punish:
        e.add_field(name="Punishment", value=punish, inline=False)
    lines = [f"• {f.label}" + (f" — `{f.sample}`" if f.sample else "") for f in res.findings[:8]]
    e.add_field(name="Findings", value="\n".join(lines)[:1000] or "-", inline=False)
    e.set_footer(text=brand_footer())
    try:
        if source:
            fname = f"blocked_{ctx.author.id}_{int(time.time())}.txt"
            await chan.send(embed=e, file=discord.File(fp=io.BytesIO(source), filename=fname))
        else:
            await chan.send(embed=e)
    except Exception:
        traceback.print_exc()


# ---------- PREPARAÇÃO COMUM DOS COMANDOS ----------
async def prepare(ctx: commands.Context, url, label: str, strict_channel: bool = True):
    """
    1) valida canal e bloqueio  2) lê o ficheiro  3) mostra a barra de progresso
    4) corre o anti-grabber (em paralelo com o envio da mensagem)
    5) agenda a remoção da mensagem do utilizador (USER_MSG_DELETE_AFTER s; imediata se for bloqueado).
    Devolve (source, status_msg, scan_result) ou None se terminou aqui.
    """
    # canal
    if config.get("channel_id") is None:
        await safe_delete(ctx.message)
        m = await send(ctx, embed=make_embed("Bot not hosted", "Use `.alojar` in the channel you want to use.", C_ERR))
        schedule_delete(m, 8)
        return None
    if strict_channel and ctx.channel.id != config["channel_id"]:
        await safe_delete(ctx.message)
        m = await send(ctx, embed=make_embed("Wrong channel", f"Use <#{config['channel_id']}>.", C_ERR))
        schedule_delete(m, 6)
        return None

    # bloqueio temporário
    left = is_locked(ctx.author.id)
    if left:
        await safe_delete(ctx.message)
        m = await send(ctx, embed=make_embed(
            "🛡️ Temporarily blocked",
            f"{ctx.author.mention}, too many blocked uploads. Try again in **{left // 60 + 1} min**.", C_ERR))
        schedule_delete(m, 10)
        return None

    # ficheiro (tem de ser lido ANTES de apagar a mensagem)
    source, err = await get_source(ctx, url)
    if source is None:
        await safe_delete(ctx.message)
        m = await send(ctx, embed=make_embed("Could not read the script", f"{ctx.author.mention}: {err}", C_ERR))
        schedule_delete(m, 8)
        return None

    # envia a barra e faz o scan ao mesmo tempo (o scan corre fora do event loop)
    status_task = asyncio.create_task(send(ctx, embed=progress_embed(label, 5, "Security scan", ctx.author.id)))
    if config.get("antigrab", True):
        res = await asyncio.to_thread(antigrab.scan, source)
    else:
        res = antigrab.ScanResult()
    status = await status_task

    if res.level == "blocked":
        await safe_delete(ctx.message)  # script suspeito: remove já
        add_strike(ctx.author.id)
        ok, why = await mute_member(ctx.author, "Anti-Grabber: uploaded a token/credential grabber")
        punish = "🔇 Muted for 24 hours" if ok else f"⚠️ Could not mute ({why})"
        await status.edit(embed=blocked_embed(res, ctx.author.id, len(source), punish))
        schedule_delete(status, 90)
        await log_block(ctx, res, len(source), ctx.command.name if ctx.command else "?", source, punish)
        return None

    # mensagem do utilizador fica visível pelo menos USER_MSG_DELETE_AFTER segundos
    schedule_delete(ctx.message, USER_MSG_DELETE_AFTER)
    return source, status, res


async def get_source(ctx: commands.Context, url: str = None):
    if ctx.message.attachments:
        att = ctx.message.attachments[0]
        if not att.filename.endswith((".txt", ".lua", ".luau")):
            return None, "Attachment must be .txt/.lua/.luau"
        if att.size > MAX_FILE:
            return None, "File > 5 MiB."
        return await att.read(), ""
    elif url:
        source, err = await fetch_url(url.strip())
        if source is None:
            return None, f"Could not fetch URL: {err}"
        if len(source) > MAX_FILE:
            return None, "File > 5 MiB."
        return source, ""
    return None, "Usage: attach a file or send a URL."


def _finalize_sync(res_bytes: bytes):
    scan_res = antigrab.scan(res_bytes) if config.get("antigrab", True) else antigrab.ScanResult()
    return antigrab.redact_bytes(res_bytes), scan_res


async def finalize_output(res_bytes: bytes):
    """Anti-grabber no RESULTADO (apanha grabbers ofuscados): esconde tokens e avisa.
    Corre numa thread para não bloquear o bot em ficheiros grandes."""
    return await asyncio.to_thread(_finalize_sync, res_bytes)


# ---------- FERRAMENTAS (botões gerados a partir desta lista) ----------
TOOLS = [
    {"key": "Prometheus", "label": "Prometheus", "run": run_deobf, "file": "deobfuscated.txt",
     "emoji": discord.PartialEmoji(name="wearedevs", id=WEAREDEVS_EMOJI_ID), "row": 0,
     "match": ("Prometheus", "WeAreDevs")},
    {"key": "MoonSec V2", "label": "MoonSec V2", "run": run_moonsec_v2, "file": "deobfuscated.lua",
     "emoji": discord.PartialEmoji(name="moonsec", id=MOONSEC_EMOJI_ID), "row": 0,
     "match": ("MoonSec V2",)},
    {"key": "MoonVeil", "label": "MoonVeil", "run": run_moonveil, "file": "deobfuscated.lua",
     "emoji": discord.PartialEmoji(name="moonveil", id=MOONVEIL_EMOJI_ID), "row": 0,
     "match": ("MoonVeil",)},
    {"key": "LuaObfuscator", "label": "LuaObfuscator", "run": run_luaobfuscator, "file": "deobfuscated.lua",
     "emoji": discord.PartialEmoji(name="luaobf", id=LUAOBF_EMOJI_ID), "row": 0,
     "match": ("LuaObfuscator VM", "LuaObfuscator")},
    {"key": "Luraph", "label": "Luraph", "run": run_luraph, "file": "deobfuscated.lua",
     "emoji": discord.PartialEmoji(name="luraph", id=LURAPH_EMOJI_ID), "row": 0, "match": ("Luraph",)},
    {"key": "EnvLog", "label": "Env Logger", "run": run_envlog, "file": "envlog_output.lua",
     "emoji": "📜", "row": 1, "match": ()},
    {"key": "EnvLog2", "label": "Env Logger 2", "run": run_envlog2, "file": "envlog2_output.lua",
     "emoji": "🧪", "row": 1, "match": ()},
]

# Os env loggers só existem como comandos (.l / .l2); não aparecem nos botões do .deobf
LOGGER_KEYS = {"EnvLog", "EnvLog2"}


class ToolButton(discord.ui.Button):
    def __init__(self, tool: dict, recommended: bool = False):
        super().__init__(
            label=tool["label"],
            style=discord.ButtonStyle.success if recommended else discord.ButtonStyle.secondary,
            emoji=tool["emoji"],
            row=tool["row"],
        )
        self.tool = tool

    async def callback(self, interaction: discord.Interaction):
        label = self.tool["label"]
        who = interaction.user.id
        try:
            src = getattr(self.view, "source", None)
            if not src:
                return await interaction.response.send_message("Script not found.", ephemeral=True)
            self.view.stop()
            msg = interaction.message
            t_click = time.time()
            await interaction.response.edit_message(embed=progress_embed(label, 15, "Running tool", who), view=None)

            def editor(embed):
                return interaction.edit_original_response(embed=embed)

            res, err, tool_time = await run_with_progress(editor, label, who, self.tool["run"], src, already_shown=True)
            if not res:
                await interaction.edit_original_response(embed=error_embed(label, err, who))
                return schedule_delete(msg, 60)

            t1 = time.time()
            out, scan_res = await finish_and_scan(editor, label, who, res)
            t2 = time.time()
            detail = f"tool {tool_time:.1f}s · scan {t2 - t1:.1f}s"
            ok = await deliver_result(
                lambda **k: interaction.edit_original_response(**k),
                getattr(interaction.message, "channel", None) or interaction.channel,
                result_embed(label, len(out), t2 - t_click, scan_res, who, detail=detail),
                out, self.tool["file"],
            )
            if not ok:
                await interaction.edit_original_response(
                    embed=error_embed(label, "Could not upload the result file to Discord.", who))
                return schedule_delete(msg, 60)
            t3 = time.time()
            print(f"[timing] {label}: tool={tool_time:.1f}s finalize={t2 - t1:.2f}s upload={t3 - t2:.2f}s "
                  f"total={t3 - t_click:.1f}s in={len(src)}B out={len(out)}B", flush=True)
            schedule_delete(msg, DELETE_AFTER)
        except Exception as e:
            traceback.print_exc()
            try:
                await interaction.edit_original_response(embed=error_embed(label, repr(e), who))
                schedule_delete(interaction.message, 60)
            except Exception:
                pass


class DeobfView(discord.ui.View):
    def __init__(self, source: bytes, owner_id: int, detected: str = ""):
        super().__init__(timeout=DELETE_AFTER)
        self.source = source
        self.owner_id = owner_id
        self.message = None
        for tool in TOOLS:
            if tool["key"] in LOGGER_KEYS:
                continue
            self.add_item(ToolButton(tool, recommended=detected in tool["match"]))

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.owner_id:
            await interaction.response.send_message("Only the person who ran the command can use these buttons.", ephemeral=True)
            return False
        return True

    async def on_timeout(self):
        if self.message:
            await safe_delete(self.message)


# ---------- HELP (com menu dropdown) ----------
CATEGORIES = {
    "Utilities": {"emoji_text": "⚙️", "emoji_obj": "⚙️"},
    "Tools": {"emoji_text": "🛠️", "emoji_obj": "🛠️"},
}

COMMANDS = {
    "alojar": ("Utilities", ".alojar", "Host the bot in the current channel. Administrators only."),
    "stats": ("Utilities", ".stats", "Show uptime and latency."),
    "help": ("Utilities", ".help [command]", "Show this menu, or details about one command."),
    "antigrab": ("Utilities", ".antigrab [on|off]", "Turn the Anti-Grabber on or off, or show its status. Administrators only."),
    "setlogs": ("Utilities", ".setlogs", "Use this channel to log blocked uploads. Administrators only."),
    "deobf": ("Tools", ".deobf <url | attachment>",
              "Detects the obfuscator and shows the matching deobfuscation buttons."),
    "detector": ("Tools", ".detector <url | attachment>", "Only detects which obfuscator was used."),
    "l": ("Tools", ".l <url | attachment>", "Runs the env logger."),
    "l2": ("Tools", ".l2 <url | attachment>", "Runs env logger 2 (improved)."),
}


def category_commands(cat: str):
    return [name for name, (c, _, _) in COMMANDS.items() if c == cat]


def help_embed(cat: str, user: discord.abc.User = None):
    info = CATEGORIES[cat]
    e = discord.Embed(
        title="Helper",
        description="Use `.help <command>` for details about a specific command.",
        color=C_BRAND,
    )
    e.set_author(name=BOT_NAME, icon_url=BRAND_ICON)
    chips = " · ".join(f"`{n}`" for n in category_commands(cat))
    e.add_field(name=f"{info['emoji_text']} {cat}", value=chips, inline=False)
    e.set_thumbnail(url=BRAND_ICON)
    e.set_footer(text=brand_footer(f"requested by {user.display_name}" if user else ""))
    return e


class HelpSelect(discord.ui.Select):
    def __init__(self, current: str):
        options = [
            discord.SelectOption(
                label=cat,
                description=f"{len(category_commands(cat))} command(s)",
                emoji=info["emoji_obj"],
                default=(cat == current),
            )
            for cat, info in CATEGORIES.items()
        ]
        super().__init__(placeholder="Choose a category", options=options, min_values=1, max_values=1)

    async def callback(self, interaction: discord.Interaction):
        cat = self.values[0]
        view = HelpView(self.view.owner_id, cat)
        view.message = interaction.message
        await interaction.response.edit_message(embed=help_embed(cat, interaction.user), view=view)


class HelpView(discord.ui.View):
    def __init__(self, owner_id: int, current: str = "Tools"):
        super().__init__(timeout=180)
        self.owner_id = owner_id
        self.message = None
        self.add_item(HelpSelect(current))

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.owner_id:
            await interaction.response.send_message("Run `.help` yourself to use this menu.", ephemeral=True)
            return False
        return True

    async def on_timeout(self):
        if self.message:
            await safe_delete(self.message)


# ---------- COMANDOS ----------
@bot.command(name="alojar")
@commands.has_permissions(administrator=True)
async def alojar(ctx: commands.Context):
    await safe_delete(ctx.message)
    config["channel_id"] = ctx.channel.id
    save_config(config)
    m = await send(ctx, embed=make_embed("Hosted", f"The bot is now hosted in {ctx.channel.mention}.", C_OK))
    schedule_delete(m, 10)


@bot.command(name="setlogs")
@commands.has_permissions(administrator=True)
async def setlogs(ctx: commands.Context):
    await safe_delete(ctx.message)
    config["log_channel_id"] = ctx.channel.id
    save_config(config)
    m = await send(ctx, embed=make_embed("🛡️ Logs enabled", f"Blocked uploads will be logged in {ctx.channel.mention}.", C_OK))
    schedule_delete(m, 10)


@bot.command(name="antigrab")
@commands.has_permissions(administrator=True)
async def antigrab_cmd(ctx: commands.Context, mode: str = None):
    await safe_delete(ctx.message)
    if mode and mode.lower() in ("on", "off"):
        config["antigrab"] = mode.lower() == "on"
        save_config(config)
    state = "🟢 **active**" if config.get("antigrab", True) else "🔴 **off**"
    logs = f"<#{config['log_channel_id']}>" if config.get("log_channel_id") else "not set (`.setlogs`)"
    e = make_embed("🛡️ Anti-Grabber", None, C_OK if config.get("antigrab", True) else C_ERR)
    e.add_field(name="Status", value=state, inline=True)
    e.add_field(name="Log channel", value=logs, inline=True)
    e.add_field(name="Blocks", value="Discord tokens, token storage paths, `/users/@me` lookups, encrypted token markers, "
                                     "Roblox cookies, browser credential paths, webhook exfiltration + shell/AppData access.", inline=False)
    m = await send(ctx, embed=e)
    schedule_delete(m, 30)


@bot.command(name="deobf")
async def deobf(ctx: commands.Context, *, url: str = None):
    prep = await prepare(ctx, url, "Deobfuscator")
    if prep is None:
        return
    source, status, scan_res = prep

    results = await asyncio.to_thread(detect, source.decode("utf-8", "ignore"))
    top_name, top_pct = results[0] if results else ("Custom / Unknown", 0.0)
    color, icon = OBF_STYLE.get(top_name, (C_BRAND, None))
    score = score_1_to_10(top_pct) if top_pct > 0 else 0

    e = discord.Embed(title="DropX Deobfuscator", color=color)
    e.set_author(name=BOT_NAME, icon_url=BRAND_ICON)
    e.description = f"Requested by {ctx.author.mention}"
    e.add_field(name="🔍 Detected", value=f"**{top_name}**", inline=True)
    e.add_field(name="📊 Confidence", value=f"`{bar(score)}` {score}/10", inline=True)
    e.add_field(name="📦 Size", value=fmt_bytes(len(source)), inline=True)
    others = [f"`{n}` {score_1_to_10(p)}/10" for n, p in results[1:4] if p > 0]
    if others:
        e.add_field(name="Other matches", value=" · ".join(others), inline=False)
    if scan_res.level != "clean":  # só mostra o Anti-Grabber quando há algo a avisar
        e.add_field(name="🛡️ Anti-Grabber", value=security_text(scan_res), inline=False)
    if icon:
        e.set_thumbnail(url=icon)
    e.set_footer(text=brand_footer())

    view = DeobfView(source, ctx.author.id, top_name)
    view.message = status
    await status.edit(embed=e, view=view)


@bot.command(name="detector", aliases=["detect"])
async def detector(ctx: commands.Context, *, url: str = None):
    prep = await prepare(ctx, url, "Detector", strict_channel=False)
    if prep is None:
        return
    source, status, scan_res = prep
    results = await asyncio.to_thread(detect, source.decode("utf-8", "ignore"))
    lines = [f"**{n}**\n`{bar(score_1_to_10(p))}` {score_1_to_10(p)}/10" for n, p in results[:5] if p > 0]
    top_name = results[0][0] if results else "Custom / Unknown"
    color, icon = OBF_STYLE.get(top_name, (C_DARK, None))
    e = make_embed("Detector", "\n\n".join(lines) or "No obfuscator detected.", color)
    if scan_res.level != "clean":  # só mostra o Anti-Grabber quando há algo a avisar
        e.add_field(name="🛡️ Anti-Grabber", value=security_text(scan_res), inline=False)
    if icon and lines:
        e.set_thumbnail(url=icon)
    await status.edit(embed=e)
    schedule_delete(status, DELETE_AFTER)


@bot.command(name="stats")
async def stats(ctx: commands.Context):
    await safe_delete(ctx.message)
    uptime = int(time.time() - getattr(bot, "launch_time", time.time()))
    e = make_embed("Stats", None, C_BRAND)
    e.add_field(name="⏳ Uptime", value=fmt_uptime(uptime), inline=True)
    e.add_field(name="📶 Latency", value=f"{round(bot.latency * 1000, 1)} ms", inline=True)
    e.add_field(name="🌐 Servers", value=str(len(bot.guilds)), inline=True)
    m = await send(ctx, embed=e)
    schedule_delete(m, 60)


@bot.command(name="help")
async def help_cmd(ctx: commands.Context, *, command: str = None):
    await safe_delete(ctx.message)
    if command:
        name = command.strip().lstrip(".").lower()
        info = COMMANDS.get(name)
        if not info:
            m = await send(ctx, embed=make_embed("Unknown command", f"`{name}` does not exist. Use `.help`.", C_ERR))
            return schedule_delete(m, 8)
        cat, usage, desc = info
        e = make_embed(f"Command · {name}", desc, C_BRAND)
        e.add_field(name="Usage", value=f"`{usage}`", inline=False)
        e.add_field(name="Category", value=f"{CATEGORIES[cat]['emoji_text']} {cat}", inline=True)
        m = await send(ctx, embed=e)
        return schedule_delete(m, 90)
    start = "Tools"
    view = HelpView(ctx.author.id, start)
    view.message = await send(ctx, embed=help_embed(start, ctx.author), view=view)


async def _logger_command(ctx: commands.Context, url, runner, label, filename):
    t_start = time.time()
    prep = await prepare(ctx, url, label)
    if prep is None:
        return
    source, status, _ = prep
    who = ctx.author.id

    def editor(embed):
        return status.edit(embed=embed)

    res, err, tool_time = await run_with_progress(editor, label, who, runner, source)
    if not res:
        await status.edit(embed=error_embed(label, err, who))
        return schedule_delete(status, 60)

    t1 = time.time()
    out, scan_res = await finish_and_scan(editor, label, who, res)
    t2 = time.time()
    detail = f"tool {tool_time:.1f}s · scan {t2 - t1:.1f}s"
    ok = await deliver_result(
        lambda **k: status.edit(**k),
        status.channel,
        result_embed(label, len(out), t2 - t_start, scan_res, who, detail=detail),
        out, filename,
    )
    if not ok:
        await status.edit(embed=error_embed(label, "Could not upload the result file to Discord.", who))
        return schedule_delete(status, 60)
    t3 = time.time()
    print(f"[timing] {label}: tool={tool_time:.1f}s finalize={t2 - t1:.2f}s upload={t3 - t2:.2f}s "
          f"total={t3 - t_start:.1f}s in={len(source)}B out={len(out)}B", flush=True)
    schedule_delete(status, DELETE_AFTER)


@bot.command(name="l")
async def env_logger_cmd(ctx: commands.Context, *, url: str = None):
    await _logger_command(ctx, url, run_envlog, "Env Logger", "envlog_output.lua")


@bot.command(name="l2")
async def env_logger_2_cmd(ctx: commands.Context, *, url: str = None):
    await _logger_command(ctx, url, run_envlog2, "Env Logger 2", "envlog2_output.lua")


# ---------- HANDLERS ----------
@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    await safe_delete(ctx.message)
    if isinstance(error, commands.MissingPermissions):
        msg = "You need administrator permission for this command."
    else:
        msg = f"`{error!r}`"
    try:
        m = await send(ctx, embed=make_embed("Error", msg, C_ERR))
        schedule_delete(m, 10)
    except Exception:
        pass


@bot.event
async def on_ready():
    bot.launch_time = time.time()
    print(f"Bot online: {bot.user}", flush=True)
    await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name=".help · DropX"))
    try:
        await bot.tree.sync()
    except Exception:
        pass


async def main():
    print(f">>> LUNE={LUNE} exists={os.path.exists(LUNE)}", flush=True)
    print(f">>> ENVLOG_PATH={ENVLOG_PATH} exists={os.path.exists(ENVLOG_PATH)}", flush=True)
    print(f">>> ENVLOG2_PATH={ENVLOG2_PATH} exists={os.path.exists(ENVLOG2_PATH)}", flush=True)
    print(f">>> LURAPH_DIR={LURAPH_DIR} exists={os.path.isdir(LURAPH_DIR)}", flush=True)
    print(f">>> CONFIG_FILE={CONFIG_FILE}", flush=True)
    await start_web_server()
    await bot.start(TOKEN)


if __name__ == "__main__":
    asyncio.run(main())
