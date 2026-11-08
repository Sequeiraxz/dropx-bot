import os
import io
import asyncio
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
# Anti-grabber: 3 tentativas bloqueadas => bloqueio temporário
STRIKE_LIMIT = 3
STRIKE_LOCK_SECONDS = 30 * 60

# Emoji da marca (substitui a lua). O bot tem de estar no servidor do emoji.
BRAND_EMOJI_ID = 1569037087439724644
BRAND = f"<:dropx:{BRAND_EMOJI_ID}>"
BRAND_PARTIAL = discord.PartialEmoji(name="dropx", id=BRAND_EMOJI_ID)

WEAREDEVS_EMOJI_ID = 1565837351769481216
MOONSEC_EMOJI_ID = 1566041038852718692
MOONVEIL_EMOJI_ID = 1566062539962323085
LUAOBF_EMOJI_ID = 1566411737727770714

WEAREDEVS_ICON = "https://www.google.com/s2/favicons?domain=wearedevs.net&sz=128"
MOONSEC_ICON = f"https://cdn.discordapp.com/emojis/{MOONSEC_EMOJI_ID}.png"
MOONVEIL_ICON = f"https://cdn.discordapp.com/emojis/{MOONVEIL_EMOJI_ID}.png"
LUAOBF_ICON = f"https://cdn.discordapp.com/emojis/{LUAOBF_EMOJI_ID}.png"
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
    "Custom / Unknown": (0x95A5A6, None),
}


def bar(score10: int) -> str:
    score10 = max(0, min(10, score10))
    return "▰" * score10 + "▱" * (10 - score10)


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


def pipeline_embed(title: str, steps: list, active: int, who_id: int = None, color=C_WORK):
    lines = []
    for i, s in enumerate(steps):
        if i < active:
            lines.append(f"✅ {s}")
        elif i == active:
            lines.append(f"⏳ **{s}**")
        else:
            lines.append(f"▫️ {s}")
    desc = "\n".join(lines)
    if who_id:
        desc += f"\n\nRequested by <@{who_id}>"
    return make_embed(title, desc, color)


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


def result_embed(tool_label: str, size: int, elapsed: float, scan_res, who_id: int, color=C_OK):
    deletes_at = int(time.time()) + DELETE_AFTER
    warn = scan_res is not None and scan_res.level in ("suspicious", "blocked")
    e = discord.Embed(
        title="Done" if not warn else "Done · ⚠️ review the output",
        description=f"Requested by <@{who_id}>",
        color=C_WARN if warn else color,
    )
    e.set_author(name=BOT_NAME, icon_url=BRAND_ICON)
    e.add_field(name="🛠️ Tool", value=tool_label, inline=True)
    e.add_field(name="📦 Size", value=fmt_bytes(size), inline=True)
    e.add_field(name="⏱️ Time", value=f"{elapsed:.1f}s", inline=True)
    if scan_res is not None:
        e.add_field(name="🛡️ Anti-Grabber", value=security_text(scan_res), inline=False)
    e.add_field(name="🗑️ Auto-delete", value=f"<t:{deletes_at}:R>", inline=False)
    e.set_footer(text=brand_footer())
    return e


def blocked_embed(res, who_id: int, size: int):
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
_bg_tasks = set()
_strikes = {}  # user_id -> {"count": int, "until": float}

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
SIGNATURES = {
    "Prometheus": [
        (20, re.compile(r'return\s*\(function\s*\(\.\.\.\)\s*local\s+\w\s*=\s*\{')),
        (45, re.compile(r"=\{\s*(?:'[A-Za-z0-9]+'\s*,\s*){4,}'[A-Za-z0-9]+'\s*\}")),
        (20, re.compile(r'\b\d{4,7}-\(-?\d{4,7}\)')),
        (15, re.compile(r'math\.floor')),
        (10, re.compile(r'string\.char.*table\.concat.*string\.sub', re.DOTALL)),
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
}
_DEFINITELY_OBF = [
    re.compile(r'Protected_by_MoonSecV2'),
    re.compile(r'This script was generated using (?:the )?MoonVeil'),
    re.compile(r'return\s+v15\s*\(\s*"LOL!'),
    re.compile(r'[\u3480-\u34c0]{5,}'),
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
                return None, "timeout (180s)"
            except FileNotFoundError:
                return None, "Node.js not found"
            if proc.returncode != 0:
                return None, stderr.decode("utf-8", "replace").strip()[-1200:] or f"exit code {proc.returncode}"
            return stdout, ""


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


async def log_block(ctx: commands.Context, res, size: int, command: str):
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
    lines = [f"• {f.label}" + (f" — `{f.sample}`" if f.sample else "") for f in res.findings[:8]]
    e.add_field(name="Findings", value="\n".join(lines)[:1000] or "-", inline=False)
    e.set_footer(text=brand_footer())
    try:
        await chan.send(embed=e)
    except Exception:
        pass


# ---------- PREPARAÇÃO COMUM DOS COMANDOS ----------
async def prepare(ctx: commands.Context, url, label: str, steps: list, strict_channel: bool = True):
    """
    1) valida canal e bloqueio  2) lê o ficheiro  3) APAGA a mensagem do utilizador
    4) mostra o estado  5) corre o anti-grabber.
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
    await safe_delete(ctx.message)
    if source is None:
        m = await send(ctx, embed=make_embed("Could not read the script", f"{ctx.author.mention}: {err}", C_ERR))
        schedule_delete(m, 8)
        return None

    status = await send(ctx, embed=pipeline_embed(label, steps, 0, ctx.author.id))

    res = antigrab.scan(source) if config.get("antigrab", True) else antigrab.ScanResult()
    if res.level == "blocked":
        add_strike(ctx.author.id)
        await status.edit(embed=blocked_embed(res, ctx.author.id, len(source)))
        schedule_delete(status, 90)
        await log_block(ctx, res, len(source), ctx.command.name if ctx.command else "?")
        return None
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


def finalize_output(res_bytes: bytes):
    """Anti-grabber no RESULTADO (apanha grabbers ofuscados): esconde tokens e avisa."""
    scan_res = antigrab.scan(res_bytes) if config.get("antigrab", True) else antigrab.ScanResult()
    return antigrab.redact_bytes(res_bytes), scan_res


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
    {"key": "EnvLog", "label": "Env Logger", "run": run_envlog, "file": "envlog_output.lua",
     "emoji": "📜", "row": 1, "match": ()},
    {"key": "EnvLog2", "label": "Env Logger 2", "run": run_envlog2, "file": "envlog2_output.lua",
     "emoji": "🧪", "row": 1, "match": ()},
]

STEPS_RUN = ["Security scan", "Running tool", "Sending result"]


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
            await interaction.response.edit_message(embed=pipeline_embed(label, STEPS_RUN, 1, who), view=None)
            started = time.time()
            res, err = await self.tool["run"](src)
            elapsed = time.time() - started
            if not res:
                await interaction.edit_original_response(embed=error_embed(label, err, who))
                return schedule_delete(msg, 60)
            await interaction.edit_original_response(embed=pipeline_embed(label, STEPS_RUN, 2, who))
            out, scan_res = finalize_output(res)
            file = discord.File(fp=io.BytesIO(out), filename=self.tool["file"])
            await interaction.edit_original_response(
                embed=result_embed(label, len(out), elapsed, scan_res, who),
                attachments=[file],
            )
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
              "Detects the obfuscator and shows the matching deobfuscation buttons plus the env loggers."),
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
    prep = await prepare(ctx, url, "Deobfuscator", ["Security scan", "Detecting obfuscator", "Ready"])
    if prep is None:
        return
    source, status, scan_res = prep

    results = detect(source.decode("utf-8", "ignore"))
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
    e.add_field(name="🛡️ Anti-Grabber", value=security_text(scan_res), inline=False)
    if any(top_name in t["match"] for t in TOOLS):
        hint = "The green button is the recommended tool for this script."
    else:
        hint = "No obfuscator recognised. Try any deobfuscator or the Env Loggers."
    e.add_field(name="➡️ Next step", value=hint, inline=False)
    e.add_field(name="🗑️ Auto-delete", value=f"<t:{int(time.time()) + DELETE_AFTER}:R>", inline=False)
    if icon:
        e.set_thumbnail(url=icon)
    e.set_footer(text=brand_footer())

    view = DeobfView(source, ctx.author.id, top_name)
    view.message = status
    await status.edit(embed=e, view=view)


@bot.command(name="detector")
async def detector(ctx: commands.Context, *, url: str = None):
    prep = await prepare(ctx, url, "Detector", ["Security scan", "Detecting obfuscator", "Ready"], strict_channel=False)
    if prep is None:
        return
    source, status, scan_res = prep
    results = detect(source.decode("utf-8", "ignore"))
    lines = [f"**{n}**\n`{bar(score_1_to_10(p))}` {score_1_to_10(p)}/10" for n, p in results[:5] if p > 0]
    top_name = results[0][0] if results else "Custom / Unknown"
    color, icon = OBF_STYLE.get(top_name, (C_DARK, None))
    e = make_embed("Detector", "\n\n".join(lines) or "No obfuscator detected.", color)
    e.add_field(name="🛡️ Anti-Grabber", value=security_text(scan_res), inline=False)
    e.add_field(name="🗑️ Auto-delete", value=f"<t:{int(time.time()) + DELETE_AFTER}:R>", inline=False)
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
    state = "🟢 active" if config.get("antigrab", True) else "🔴 off"
    e.add_field(name="🛡️ Anti-Grabber", value=f"{state} · scripts with token-grabber patterns are blocked", inline=False)
    e.add_field(name="🗑️ Cleanup", value=f"Your command is removed and results disappear after {DELETE_AFTER // 60} min.", inline=False)
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
    prep = await prepare(ctx, url, label, STEPS_RUN)
    if prep is None:
        return
    source, status, _ = prep
    who = ctx.author.id
    await status.edit(embed=pipeline_embed(label, STEPS_RUN, 1, who))
    started = time.time()
    res, err = await runner(source)
    elapsed = time.time() - started
    if not res:
        await status.edit(embed=error_embed(label, err, who))
        return schedule_delete(status, 60)
    await status.edit(embed=pipeline_embed(label, STEPS_RUN, 2, who))
    out, scan_res = finalize_output(res)
    await status.edit(
        embed=result_embed(label, len(out), elapsed, scan_res, who),
        attachments=[discord.File(fp=io.BytesIO(out), filename=filename)],
    )
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
    print(f">>> CONFIG_FILE={CONFIG_FILE}", flush=True)
    await start_web_server()
    await bot.start(TOKEN)


if __name__ == "__main__":
    asyncio.run(main())
