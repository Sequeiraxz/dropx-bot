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

TOKEN = os.environ.get("DISCORD_TOKEN")

DEOBF_DIR = os.environ.get("DEOBF_DIR", "./Prometheus-Deobfuscator-main")
MOONSEC_V2_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "moonsec-v2-deobfuscator")
MOONVEIL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "moonveil-deobf")
LUAOBFUSCATOR_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "luaobfuscator-deobf", "luaobfuscator")
ENVLOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "envlog.luau")
ENVLOG2_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "envlog2.luau")
NODE = os.environ.get("NODE", "node")
LUNE = os.environ.get("LUNE", "/usr/local/bin/lune")
DEOBF_TIMEOUT = int(os.environ.get("DEOBF_TIMEOUT", "180"))
CONFIG_FILE = os.environ.get("CONFIG_FILE", "config.json")

HEADER = "Deobfuscate By DropX :)\n\n"
WEAREDEVS_ICON = "https://www.google.com/s2/favicons?domain=wearedevs.net&sz=128"
WEAREDEVS_EMOJI_ID = 1565837351769481216
MOONSEC_EMOJI_ID = 1566041038852718692
MOONSEC_ICON = f"https://cdn.discordapp.com/emojis/{MOONSEC_EMOJI_ID}.png"
MOONVEIL_EMOJI_ID = 1566062539962323085
MOONVEIL_ICON = f"https://cdn.discordapp.com/emojis/{MOONVEIL_EMOJI_ID}.png"
LUAOBF_EMOJI_ID = 1566411737727770714
LUAOBF_ICON = f"https://cdn.discordapp.com/emojis/{LUAOBF_EMOJI_ID}.png"

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {"channel_id": None}

def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f)

config = load_config()

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix=".", intents=intents)
bot.remove_command("help")

_moonsec_lock = asyncio.Lock()
_moonveil_lock = asyncio.Lock()

# ---------- DETECTOR ----------
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
        (8,  re.compile(r'bit32\.rshift')),
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
        (50, re.compile(r'--\s*This script was generated using the MoonVeil Obfuscator')),
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
    re.compile(r'This script was generated using the MoonVeil'),
    re.compile(r'return\s+v15\s*\(\s*"LOL!'),
    re.compile(r'[\u3480-\u34c0]{5,}'),
]
_WEAREDEVS_SIGNALS = [
    re.compile(r'wearedevs\.net/obfuscator'),
    re.compile(r'\[\[\s*v\d+\.\d+\.\d+\s+https?://'),
]

def calc_entropy(data: str) -> float:
    if not data: return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())

def stat_features(code: str) -> dict:
    lines = code.splitlines()
    total_chars = len(code)
    if total_chars == 0: return {}
    num_esc = len(re.findall(r'\\[0-9]{2,3}', code))
    return {
        "entropy": calc_entropy(code),
        "numeric_escape_density": num_esc / max(total_chars / 1000, 1),
        "avg_line_length": (sum(len(l) for l in lines) / len(lines)) if lines else 0,
    }

def is_wearedevs(code: str) -> bool:
    for pat in _WEAREDEVS_SIGNALS:
        try:
            if pat.search(code): return True
        except: pass
    return False

def is_definitely_obfuscated(code: str) -> bool:
    for pat in _DEFINITELY_OBF:
        try:
            if pat.search(code): return True
        except: pass
    return False

def detect(code):
    stats = stat_features(code)
    definitely = is_definitely_obfuscated(code)
    wad = is_wearedevs(code)
    raw_scores = {}
    for obf_name, patterns in SIGNATURES.items():
        score = 0.0
        for weight, pattern in patterns:
            try:
                if pattern.search(code): score += weight
            except: pass
        if obf_name == "Prometheus" and definitely: score += 10
        if obf_name == "Prometheus" and wad: score -= 40
        raw_scores[obf_name] = max(score, 0.0)
    if not raw_scores:
        return [("Custom / Unknown", 0.0)]
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

# ---------- DEOBF ----------
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
            return f.read(), ""

async def run_moonsec_v2(source: bytes):
    if not os.path.isdir(MOONSEC_V2_DIR):
        return None, "moonsec-v2-deobfuscator folder missing"
    async with _moonsec_lock:
        with tempfile.TemporaryDirectory() as tmp:
            in_path = os.path.join(tmp, "input.lua")
            with open(in_path, "wb") as f: f.write(source)
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
            try: os.remove(out_path)
            except: pass
            return result, ""

async def run_moonveil(source: bytes):
    if not os.path.isdir(MOONVEIL_DIR):
        return None, "moonveil-deobf folder missing"
    async with _moonveil_lock:
        with tempfile.TemporaryDirectory() as tmp:
            in_path = os.path.join(tmp, "input.lua")
            out_path = os.path.join(tmp, "recovered.lua")
            with open(in_path, "wb") as f: f.write(source)
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
            with open(in_path, "wb") as f: f.write(source)
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

async def run_envlog(source: bytes):
    if not os.path.exists(ENVLOG_PATH):
        return None, "envlog.luau not found in project root"
    try:
        with open(ENVLOG_PATH, "r", encoding="utf-8") as f:
            envlog_code = f.read()
    except Exception as e:
        return None, f"failed to read envlog.luau: {e}"

    script_text = source.decode("utf-8", "ignore")
    eq = "=" * 5
    while (']' + eq + ']') in script_text:
        eq += "="
    safe_source = f"[{eq}[{script_text}]{eq}]"

    prelude = (
        f"local __SOURCE = {safe_source}\n"
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
                cwd=os.path.dirname(os.path.abspath(__file__)),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        except asyncio.TimeoutError:
            return None, "timeout (300s)"
        except FileNotFoundError:
            return None, f"lune not found at {LUNE}"

        if proc.returncode != 0:
            err = stderr.decode("utf-8", "replace")[-1200:]
            return None, f"lune exit {proc.returncode}: {err}"

        out = stdout.decode("utf-8", "replace")
        if not out.strip():
            return None, "envlog produced no output"
        return out.encode("utf-8"), ""

async def run_envlog2(source: bytes):
    """Segundo env logger — corre ENVLOG2_PATH via lune."""
    if not os.path.exists(ENVLOG2_PATH):
        return None, "envlog2.luau not found in project root"
    try:
        with open(ENVLOG2_PATH, "r", encoding="utf-8") as f:
            envlog_code = f.read()
    except Exception as e:
        return None, f"failed to read envlog2.luau: {e}"

    script_text = source.decode("utf-8", "ignore")
    eq = "=" * 5
    while (']' + eq + ']') in script_text:
        eq += "="
    safe_source = f"[{eq}[{script_text}]{eq}]"

    prelude = (
        f"local __SOURCE = {safe_source}\n"
        f"local __CONFIG = {{}}\n"
        f"local __ROBLOX = {{ enums = '', classes = '' }}\n"
        f"local __UNICODE = {{ decomp = '', ccc = '', comp = '' }}\n"
        f"local __P2D = {{}}\n"
        f"local __CHUNKS = {{}}\n"
    )
    runner = prelude + envlog_code

    with tempfile.TemporaryDirectory() as tmp:
        runner_path = os.path.join(tmp, "envlog2_runner.luau")
        with open(runner_path, "w", encoding="utf-8") as f:
            f.write(runner)

        try:
            proc = await asyncio.create_subprocess_exec(
                LUNE, "run", runner_path,
                cwd=os.path.dirname(os.path.abspath(__file__)),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=float(os.environ.get("ENVLOG2_TIMEOUT", "120")),
            )
        except asyncio.TimeoutError:
            return None, "timeout"
        except FileNotFoundError:
            return None, f"lune not found at {LUNE}"

        if proc.returncode != 0:
            err = stderr.decode("utf-8", "replace")[-1200:]
            return None, f"lune exit {proc.returncode}: {err}"

        out = stdout.decode("utf-8", "replace")
        if not out.strip():
            return None, "envlog2 produced no output"
        return out.encode("utf-8"), ""

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

# ---------- BOTÕES ----------
class PrometheusButton(discord.ui.Button):
    def __init__(self, enabled=True):
        super().__init__(label="Prometheus", style=discord.ButtonStyle.secondary,
                         emoji=discord.PartialEmoji(name="wearedevs", id=WEAREDEVS_EMOJI_ID),
                         disabled=not enabled, row=0)
    async def callback(self, interaction: discord.Interaction):
        try:
            src = getattr(self.view, "source", None)
            if not src:
                return await interaction.response.send_message("Script not found.", ephemeral=True)
            self.view.stop()
            await interaction.response.edit_message(content="Deobfuscating with Prometheus...", embed=None, view=None)
            res, err = await run_deobf(src)
            if not res:
                return await interaction.followup.send(f"Failed:\n```\n{err}\n```")
            final = (HEADER + res.decode("utf-8", "replace")).encode("utf-8")
            await interaction.followup.send(
                content=f"Deobfuscated — {len(final)} bytes",
                file=discord.File(fp=io.BytesIO(final), filename="deobfuscated.txt"),
            )
        except Exception as e:
            traceback.print_exc()
            await interaction.followup.send(f"Error: `{e!r}`", ephemeral=True)

class MoonSecV2Button(discord.ui.Button):
    def __init__(self, enabled=True):
        super().__init__(label="MoonSec V2", style=discord.ButtonStyle.secondary,
                         emoji=discord.PartialEmoji(name="moonsec", id=MOONSEC_EMOJI_ID),
                         disabled=not enabled, row=0)
    async def callback(self, interaction: discord.Interaction):
        try:
            src = getattr(self.view, "source", None)
            if not src:
                return await interaction.response.send_message("Script not found.", ephemeral=True)
            self.view.stop()
            await interaction.response.edit_message(content="Deobfuscating with MoonSec V2...", embed=None, view=None)
            res, err = await run_moonsec_v2(src)
            if not res:
                return await interaction.followup.send(f"Failed:\n```\n{err}\n```")
            await interaction.followup.send(
                content=f"Deobfuscated — {len(res)} bytes",
                file=discord.File(fp=io.BytesIO(res), filename="deobfuscated.lua"),
            )
        except Exception as e:
            traceback.print_exc()
            await interaction.followup.send(f"Error: `{e!r}`", ephemeral=True)

class MoonVeilButton(discord.ui.Button):
    def __init__(self, enabled=True):
        super().__init__(label="MoonVeil", style=discord.ButtonStyle.secondary,
                         emoji=discord.PartialEmoji(name="moonveil", id=MOONVEIL_EMOJI_ID),
                         disabled=not enabled, row=0)
    async def callback(self, interaction: discord.Interaction):
        try:
            src = getattr(self.view, "source", None)
            if not src:
                return await interaction.response.send_message("Script not found.", ephemeral=True)
            self.view.stop()
            await interaction.response.edit_message(content="Deobfuscating with MoonVeil...", embed=None, view=None)
            res, err = await run_moonveil(src)
            if not res:
                return await interaction.followup.send(f"Failed:\n```\n{err}\n```")
            await interaction.followup.send(
                content=f"Deobfuscated — {len(res)} bytes",
                file=discord.File(fp=io.BytesIO(res), filename="deobfuscated.lua"),
            )
        except Exception as e:
            traceback.print_exc()
            await interaction.followup.send(f"Error: `{e!r}`", ephemeral=True)

class LuaObfuscatorButton(discord.ui.Button):
    def __init__(self, enabled=True):
        super().__init__(label="LuaObfuscator", style=discord.ButtonStyle.secondary,
                         emoji=discord.PartialEmoji(name="luaobf", id=LUAOBF_EMOJI_ID),
                         disabled=not enabled, row=0)
    async def callback(self, interaction: discord.Interaction):
        try:
            src = getattr(self.view, "source", None)
            if not src:
                return await interaction.response.send_message("Script not found.", ephemeral=True)
            self.view.stop()
            await interaction.response.edit_message(content="Deobfuscating with LuaObfuscator...", embed=None, view=None)
            res, err = await run_luaobfuscator(src)
            if not res:
                return await interaction.followup.send(f"Failed:\n```\n{err}\n```")
            await interaction.followup.send(
                content=f"Deobfuscated — {len(res)} bytes",
                file=discord.File(fp=io.BytesIO(res), filename="deobfuscated.lua"),
            )
        except Exception as e:
            traceback.print_exc()
            await interaction.followup.send(f"Error: `{e!r}`", ephemeral=True)

class EnvLogButton(discord.ui.Button):
    def __init__(self, enabled=True):
        super().__init__(label="Env Logger", style=discord.ButtonStyle.secondary, disabled=not enabled, row=1)
    async def callback(self, interaction: discord.Interaction):
        try:
            src = getattr(self.view, "source", None)
            if not src:
                return await interaction.response.send_message("Script not found.", ephemeral=True)
            self.view.stop()
            await interaction.response.edit_message(content="Running env logger...", embed=None, view=None)
            res, err = await run_envlog(src)
            if not res:
                return await interaction.followup.send(f"Failed:\n```\n{err}\n```")
            await interaction.followup.send(
                content=f"Env log — {len(res)} bytes",
                file=discord.File(fp=io.BytesIO(res), filename="envlog_output.lua"),
            )
        except Exception as e:
            traceback.print_exc()
            await interaction.followup.send(f"Error: `{e!r}`", ephemeral=True)

class EnvLog2Button(discord.ui.Button):
    def __init__(self, enabled=True):
        super().__init__(label="Env Logger 2", style=discord.ButtonStyle.secondary,
                         disabled=not enabled, row=1)
    async def callback(self, interaction: discord.Interaction):
        try:
            src = getattr(self.view, "source", None)
            if not src:
                return await interaction.response.send_message("Script not found.", ephemeral=True)
            self.view.stop()
            await interaction.response.edit_message(content="Running env logger 2...", embed=None, view=None)
            res, err = await run_envlog2(src)
            if not res:
                return await interaction.followup.send(f"Failed:\n```\n{err}\n```")
            await interaction.followup.send(
                content=f"Env log 2 — {len(res)} bytes",
                file=discord.File(fp=io.BytesIO(res), filename="envlog2_output.lua"),
            )
        except Exception as e:
            traceback.print_exc()
            await interaction.followup.send(f"Error: `{e!r}`", ephemeral=True)

class DeobfView(discord.ui.View):
    def __init__(self, source: bytes, prometheus_enabled=True, moonsec_enabled=True,
                 moonveil_enabled=True, luaobf_enabled=True, envlog_enabled=True, envlog2_enabled=True):
        super().__init__(timeout=600)
        self.source = source
        self.add_item(PrometheusButton(enabled=prometheus_enabled))
        self.add_item(MoonSecV2Button(enabled=moonsec_enabled))
        self.add_item(MoonVeilButton(enabled=moonveil_enabled))
        self.add_item(LuaObfuscatorButton(enabled=luaobf_enabled))
        self.add_item(EnvLogButton(enabled=envlog_enabled))
        self.add_item(EnvLog2Button(enabled=envlog2_enabled))

async def get_source(ctx: commands.Context, url: str = None):
    if ctx.message.attachments:
        att = ctx.message.attachments[0]
        if not att.filename.endswith((".txt", ".lua", ".luau")):
            return None, "Attachment must be .txt/.lua/.luau"
        if att.size > 5 * 1024 * 1024:
            return None, "File > 5 MiB."
        return await att.read(), ""
    elif url:
        source, err = await fetch_url(url.strip())
        if source is None:
            return None, f"Could not fetch URL: {err}"
        if len(source) > 5 * 1024 * 1024:
            return None, "File > 5 MiB."
        return source, ""
    return None, "Usage: attach file or URL."

# ---------- COMANDOS ----------
@bot.command(name="alojar")
@commands.has_permissions(administrator=True)
async def alojar(ctx: commands.Context):
    config["channel_id"] = ctx.channel.id
    save_config(config)
    await ctx.reply("Bot hosted successfully in this channel.", delete_after=10)

@bot.command(name="deobf")
async def deobf(ctx: commands.Context, *, url: str = None):
    if config["channel_id"] is None:
        return await ctx.reply("Bot not hosted. Use `.alojar`.")
    if ctx.channel.id != config["channel_id"]:
        return await ctx.reply("Wrong channel.", delete_after=5)
    source, err = await get_source(ctx, url)
    if source is None:
        return await ctx.reply(err, delete_after=5)
    results = detect(source.decode("utf-8", "ignore"))
    top_name, top_pct = results[0] if results else ("Custom / Unknown", 0.0)
    is_prometheus = top_name in ("Prometheus", "WeAreDevs")
    is_moonsec = top_name == "MoonSec V2"
    is_moonveil = top_name == "MoonVeil"
    is_luaobf = top_name in ("LuaObfuscator VM", "LuaObfuscator")
    desc = f"**Detected:** {top_name} ({score_1_to_10(top_pct)}/10)\n\n"
    if is_prometheus: desc += "Click **Prometheus** to deobfuscate."
    elif is_moonsec: desc += "Click **MoonSec V2** to deobfuscate."
    elif is_moonveil: desc += "Click **MoonVeil** to deobfuscate."
    elif is_luaobf: desc += "Click **LuaObfuscator** to deobfuscate."
    else: desc += "Try any deobfuscator or the Env Logger."
    embed = discord.Embed(title="DropX Deobfuscator", description=desc, color=0x2ECC71)
    embed.set_footer(text="Made by DropX")
    await ctx.reply(embed=embed, view=DeobfView(source))

@bot.command(name="detector")
async def detector(ctx: commands.Context, *, url: str = None):
    if config["channel_id"] is None:
        return await ctx.reply("Bot not hosted.")
    source, err = await get_source(ctx, url)
    if source is None:
        return await ctx.reply(err)
    results = detect(source.decode("utf-8", "ignore"))
    lines = [f"**{n}** — {score_1_to_10(p)}/10" for n, p in results[:5] if p > 0]
    if not lines:
        lines = ["No obfuscator detected."]
    await ctx.reply(embed=discord.Embed(title="Detector", description="\n".join(lines), color=0x2B2D31))

@bot.command(name="stats")
async def stats(ctx: commands.Context):
    uptime = int(time.time() - getattr(bot, "launch_time", time.time()))
    await ctx.reply(embed=discord.Embed(
        title="Stats",
        description=f"Uptime: {uptime}s\nLatency: {round(bot.latency*1000, 1)} ms",
        color=0x2ECC71,
    ))

@bot.command(name="help")
async def help_cmd(ctx: commands.Context):
    e = discord.Embed(title="DropX Commands", description="Prefix: `.`", color=0x2ECC71)
    e.add_field(name="`.alojar`", value="Host bot in this channel", inline=False)
    e.add_field(name="`.deobf`", value="Deobfuscate (Prometheus, MoonSec V2, MoonVeil, LuaObfuscator) + Env Logger", inline=False)
    e.add_field(name="`.l`", value="Run env logger only", inline=False)
    e.add_field(name="`.l2`", value="Run second env logger (improved)", inline=False)
    e.add_field(name="`.detector`", value="Detect obfuscator only", inline=False)
    e.add_field(name="`.stats`", value="Bot stats", inline=False)
    e.set_footer(text="Made by DropX")
    await ctx.reply(embed=e)

# ---------- COMANDO .l (env logger) ----------
@bot.command(name="l")
async def env_logger_cmd(ctx: commands.Context, *, url: str = None):
    if config["channel_id"] is None:
        return await ctx.reply("Bot not hosted. Use `.alojar`.")
    if ctx.channel.id != config["channel_id"]:
        return await ctx.reply("Wrong channel.", delete_after=5)
    source, err = await get_source(ctx, url)
    if source is None:
        return await ctx.reply(err, delete_after=5)
    msg = await ctx.reply("⏳ **Running env logger...**")
    res, err = await run_envlog(source)
    if not res:
        return await msg.edit(content=f"❌ Failed:\n```\n{err}\n```")
    await msg.edit(content=f"✅ Env log — {len(res)} bytes")
    await ctx.reply(file=discord.File(fp=io.BytesIO(res), filename="envlog_output.lua"))

# ---------- COMANDO .l2 (segundo env logger) ----------
@bot.command(name="l2")
async def env_logger_2_cmd(ctx: commands.Context, *, url: str = None):
    if config["channel_id"] is None:
        return await ctx.reply("Bot not hosted. Use `.alojar`.")
    if ctx.channel.id != config["channel_id"]:
        return await ctx.reply("Wrong channel.", delete_after=5)
    source, err = await get_source(ctx, url)
    if source is None:
        return await ctx.reply(err, delete_after=5)
    msg = await ctx.reply("⏳ **Running env logger 2...**")
    res, err = await run_envlog2(source)
    if not res:
        return await msg.edit(content=f"❌ Failed:\n```\n{err}\n```")
    await msg.edit(content=f"✅ Env log 2 — {len(res)} bytes")
    await ctx.reply(file=discord.File(fp=io.BytesIO(res), filename="envlog2_output.lua"))

# ---------- HANDLERS ----------
@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    try:
        await ctx.reply(f"Error: `{error!r}`", delete_after=10)
    except:
        pass

@bot.event
async def on_ready():
    bot.launch_time = time.time()
    print(f"Bot online: {bot.user}", flush=True)
    try:
        await bot.tree.sync()
    except:
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
