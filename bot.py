import os
import io
import asyncio
import tempfile
import re
import json
import math
import aiohttp
import discord
from collections import Counter
from discord.ext import commands
from aiohttp import web

# ⚠️ Usa a variável de ambiente do Render (DISCORD_TOKEN)
TOKEN = os.environ.get("DISCORD_TOKEN")

DEOBF_DIR = os.environ.get("DEOBF_DIR", "./Prometheus-Deobfuscator-main")
NODE = os.environ.get("NODE", "node")
DEOBF_TIMEOUT = 600
CONFIG_FILE = "config.json"

HEADER = "Deobfuscate By DropX :)\n\n"
WEAREDEVS_ICON = "https://www.google.com/s2/favicons?domain=wearedevs.net&sz=128"
WEAREDEVS_EMOJI_ID = 1565837351769481216

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

# =====================================================================
# DETECTOR (Integrado — baseado no message.txt)
# =====================================================================
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
        (30, re.compile(r"local\s+\w\s*=\s*\{(?:\s*'(?:\\[0-9]{2,3}){6,}'[;,]?\s*){5,}")),
        (25, re.compile(r'local\s+function\s+\w+\s*\(\s*\w+\s*\)[\s\S]{0,300}string\.char\s*\([\s\S]{0,200}string\.byte', re.DOTALL)),
        (20, re.compile(r'\bg\s*\[\s*\d+\s*\]')),
        (18, re.compile(r'string\.byte\s*\(\s*\w+\s*,\s*\w+\s*\)\s*[-+^]\s*\w+')),
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
    "MoonSec V3": [
        (30, re.compile(r'\(\[\[This file was protected with MoonSec V3\]\]\)')),
        (30, re.compile(r'\:gsub\s*\(\s*\'\.+\'\s*,\s*\(function\s*\(a\)')),
        (20, re.compile(r'_[A-Z][a-zA-Z]{6,}\s*=\s*a\s*;')),
        (25, re.compile(r'return\s*\(function\s*\(\w,\.\.\.\)local\s+\w;local\s+\w;')),
        (15, re.compile(r'while\s+n<\s*0x[0-9a-f]+\s+and\s+e%0x[0-9a-f]+<0x[0-9a-f]+')),
        (20, re.compile(r'\bk\s*\(\s*\d{2,3}\s*,\s*"[A-Za-z0-9_()\^>?#_~!|]{20,}"')),
        (15, re.compile(r'l\.[a-zA-Z_]{6,}\s*\(')),
        (15, re.compile(r'd\s*=\s*"(?:\\[0-9]{1,3}){10,}"')),
        (12, re.compile(r'local\s+e\s*=\s*0x01\s+local\s+function\s+k')),
    ],
    "Luraph 14": [
        (50, re.compile(r'--\s*This file was protected using Luraph Obfuscator v14')),
        (35, re.compile(r'return\s*\(\s*\{[A-Z]{1,3}=bit32\.\w+')),
        (30, re.compile(r'0[Xx][0-9a-fA-F]+_+[0-9a-fA-F]*')),
        (25, re.compile(r'0[Bb][01_]{3,}')),
        (25, re.compile(r'for\s+\w\s*=\s*0[Xx][0-9a-fA-F_]+\s*,\s*0[Xx][0-9a-fA-F_]+')),
        (20, re.compile(r'\w\[0[Xx][0-9a-fA-F]+__[0-9a-fA-F]*\]')),
        (20, re.compile(r'0[Xx][0-9a-fA-F]{1,4}_+[0-9a-fA-F]{1,4}')),
        (15, re.compile(r'\bbuffer\b')),
        (12, re.compile(r'coroutine\.wrap')),
        (20, re.compile(r'"[A-Za-z0-9$#@!%^&*()\[\]{}|<>?_=+\-.,;:\'"\\\/]{200,}"')),
    ],
    "Luraph 10": [
        (60, re.compile(r'--\s*This file was generated using Luraph Obfuscator v10')),
        (55, re.compile(r'"LPH\|[0-9A-Fa-f]{20,}"')),
        (40, re.compile(r'string\.char\s*\(\s*\w+\s*,\s*0\s*\)')),
        (35, re.compile(r':gsub\s*\(\s*"\.\."')),
        (30, re.compile(r'return\s+loadstring\s*\(')),
        (20, re.compile(r'\b[lI]{4,}\b')),
        (25, re.compile(r'l11i1lIil1lIIiiIill:sub\(5\)')),
        (20, re.compile(r'tonumber\s*\(\s*\w+\s*,\s*16\s*\)')),
    ],
    "IronBrew": [
        (10, re.compile(r"local\s+\w+=string\.byte;local\s+\w+=string\.char;local\s+\w+=string\.sub;local\s+\w+=table\.concat;local\s+\w+=table\.insert;local\s+\w+=math\.ldexp")),
        (10, re.compile(r'local\s+function\s+\w+\(\w+\)\s*local\s+\w+,\s*\w+,\s*\w+\s*=\s*"",\s*"",\s*\{\}')),
        (45, re.compile(r"\b\w\('[0-9A-Z]{15,}'\)")),
        (10, re.compile(r"getfenv\s+or\s+function\s*\(\s*\)\s*return\s+_ENV\s+end")),
        (10, re.compile(r"unpack\s+or\s+table\.unpack")),
    ],
    "25ms Obfuscator": [
        (30, re.compile(r'(?:\\\d{2,3}){15,}')),
        (35, re.compile(r'"[A-Za-z0-9+/=]{120,}"')),
        (25, re.compile(r'string\.gsub\s*\(\s*".-",\s*function')),
        (30, re.compile(r'\{(?:\d+,){40,}\d+\}')),
        (20, re.compile(r'math\.ldexp|bit32\.(?:bxor|lshift|rshift)')),
        (15, re.compile(r'(?:\(\s*\d+\s*[\+\-\*/]\s*\d+\s*\)){5,}')),
        (25, re.compile(r'return\s*\(\s*function\s*\(')),
        (20, re.compile(r'^.{400,}$', re.MULTILINE)),
        (15, re.compile(r'(?:[\+\-\*/%^&|]{1}){20,}')),
        (40, re.compile(r'(?:\\\d{2,3}){25,}')),
        (25, re.compile(r'string\.char\s*\(\s*(?:\d+,){10,}\d+\s*\)'))
    ],
    "IronBrew3": [
        (30, re.compile(r"^--ironbrew3:tm")),
        (30, re.compile(r"return\(function\(\w+,\w+,\w+,\w+,\w+,\w+,\w+,\w+,\w+,\w+,\w+,\w+,\w+,\w+,\w+,\w+,\w+,\w+,\w+,\w+")),
        (40, re.compile(r"bit32\s+or\s+bit")),
        (35, re.compile(r"(?:[0-9A-Fa-f]{2}){15,}")),
        (30, re.compile(r"\{(?:\d+,){50,}\d+\},\s*0,\s*255,\s*1\)")),
        (20, re.compile(r"math\.max,math\.atan2,string\.sub,math\.ceil,string\.len")),
    ],
    "LuaObfuscator VM": [
        (50, re.compile(r'local\s+v0\s*=\s*tonumber\s*;\s*local\s+v1\s*=\s*string\.byte')),
        (35, re.compile(r'local\s+function\s+v15\s*\(v16,v17')),
        (50, re.compile(r'return\s+v15\s*\(\s*"LOL!')),
        (30, re.compile(r'[0-9A-F]{2}3Q00[0-9A-F]')),
        (30, re.compile(r'[0-9A-F]{2}2Q00[0-9A-F]')),
        (20, re.compile(r'local\s+function\s+v29\s*\(v57')),
        (15, re.compile(r'v\d+\s*=\s*unpack\s+or\s+table\.unpack')),
        (15, re.compile(r'local\s+v8\s*=\s*math\.ldexp')),
        (15, re.compile(r'getfenv\s+or\s+function\s*\(\s*\)\s*return\s+_ENV')),
    ],
    "WynFuscator": [
        (10, re.compile(r'--\s*Protected by wYnFuscate')),
        (10, re.compile(r'wynfuscate\.com')),
        (30, re.compile(r'local\s+cd\s*=\s*"[A-Za-z0-9^*.?()\[\]!@#$%&_~|<>{}`\'\-]{80,}"')),
        (30, re.compile(r'local\s+cG\s*=\s*65536')),
        (30, re.compile(r'local\s+cj\s*=\s*function\s*\(c8,c9,c4\)')),
        (25, re.compile(r'cg\[cj\(\d+,cT,5\)\]')),
        (20, re.compile(r'local\s+cl\s*=\s*"(?:\\[0-9]{1,3}){20,}"')),
        (15, re.compile(r'c0\s*=\s*4294967296')),
        (20, re.compile(r'\bcA\s*\(\s*\d+\s*\)')),
    ],
    "Hercules": [
        (10, re.compile(r'--\[Protected By Hercules')),
        (15, re.compile(r"'Protected By Hercules V1\.6 \| github\.com/zeusssz/hercules-obfuscator'")),
        (10, re.compile(r'hercules-obfuscator\.xyz')),
        (25, re.compile(r'local\s+[A-Z][a-z][A-Za-z]{6,}\s*,\s*[A-Z][a-z][A-Za-z]{6,}')),
        (30, re.compile(r'[A-Z][a-zA-Z]{6,}\s*=\s*ipairs\s*;')),
        (25, re.compile(r'[A-Z][a-zA-Z]{6,}\s*=\s*pairs\s*;')),
        (20, re.compile(r'if\s+false\s+then\s+local\s+\w+\s*=\s*\d+')),
        (20, re.compile(r'while\s+false\s+do\s+local\s+\w+\s*=\s*\d+\s+break\s+end')),
        (12, re.compile(r'math\.ldexp')),
        (50, re.compile(r"\('.*?\\\d+\\\d+'\)")),
        (15, re.compile(r'return\s+\(function\s*\(\.\.\.\)\s+local\s+[A-Z][a-z][A-Za-z]{5,}')),
    ],
    "MoonVeil": [
        (50, re.compile(r'--\s*This script was generated using the MoonVeil Obfuscator')),
        (40, re.compile(r'moonveil\.cc')),
        (35, re.compile(r'local\s+\w+,\w+,\w+,\w+=getmetatable,bit32\.bxor,pairs,type')),
        (30, re.compile(r'\(function\(\.\.\.\)return\{\[1\]=\{\.\.\.\},\[2\]=\w+\(\'#\',\.\.\.\)\}end\)')),
        (25, re.compile(r'return\s*\{[^}]*\[1\]\s*=\s*\{[^}]*\},\s*\[2\]\s*=\s*\w+\s*\(\s*\'#\'')),
        (30, re.compile(r"Ki=Ig\(Ki,'\[[\^A-Z]")),
        (25, re.compile(r'local\s+function\s+\w+\s*\(\w+,\w+,\w+\)\s*if\s+\w+>\w+\s+then\s+return\s+end\s+return\s+\w+\[\w+\]')),
        (25, re.compile(r'bit32\s*\.\s*lshift\s*,\s*bit32\s*\.\s*rshift\s*,\s*bit32\s*\.\s*band')),
        (20, re.compile(r"'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\+/'.*gsub")),
        (20, re.compile(r'repeat\s+while\s+true\s+do\s+if\s+\w+<=[0-9]+\s+then\s+if\s+\w+<=[0-9]+')),
        (15, re.compile(r'Ng\[[\w-]+\]\s+or\s+\w+\([\w-]+,')),
    ],
    "77fuscator": [
        (60, re.compile(r'\[\[77fuscator\s+[\d.]+')),
        (30, re.compile(r'discord\.gg/[A-Za-z0-9]{8,}')),
        (35, re.compile(r'do\s+local\s+\w\s*=\s*\[\[77fuscator')),
        (30, re.compile(r'o,g,s,l,n,b,j,v,bb,m,r,bf=string\.byte,string\.char,string\.sub,table\.concat,math\.ldexp')),
        (25, re.compile(r'be=function\s*\(\w,\w+\)\s*local\s+\w+\s+local\s+\w+=3')),
        (25, re.compile(r'bd=function\s*\(\w\)\s*local\s+\w+,\w+,\w+,\w+,\w+,\w+,\w+\s+local\s+\w+=0')),
        (20, re.compile(r'bj=function\s*\(\s*\)\s*local\s+\w+,\w+\s+local\s+\w+=0')),
        (20, re.compile(r'getfenv\s+or\s+function\s*\(\s*\)\s*return\s+_ENV\s+end')),
        (20, re.compile(r'bg,bh=nil')),
        (15, re.compile(r'q=2\^32-1')),
        (15, re.compile(r'bh=function\s*\(\w,\w\)\s*if\s+\w<0\s+then\s+return\s+bg\(')),
    ],
    "Lunr": [
        (30, re.compile(r'--\s*This file was protected using Lunr')),
        (15, re.compile(r'discord\.gg/BGQkGUW2Qs')),
        (15, re.compile(r'\{`[A-Za-z0-9+/=]{6,}`\s*[;,]')),
        (10, re.compile(r'\blocal\s+(?:[lI1i]{4,})\s*=')),
        (20, re.compile(r'"(?:All warfare is based on deception|The supreme art of war|If you know the enemy)[^"]*Sun Tzu"')),
        (30, re.compile(r'error\s*\(\s*`Tamper Detected!`\s*\)')),
        (10, re.compile(r'setmetatable\s*\(\s*\{\s*\}\s*,\s*\{')),
        (15, re.compile(r'\(-\d{5,}\+\d{5,}\)')),
        (10, re.compile(r'getfenv\s+and\s+getfenv\(\)\s+or\s+_ENV')),
        (50, re.compile(r'lliilI1i\s*=')),
        (10, re.compile(r'`[A-Za-z0-9+/]{10,}={0,2}`')),
        (15, re.compile(r'pcall\s*\(\s*function\s*\(\s*\)[^)]{0,80}end\s*\)')),
    ],
    "LightRay": [
        (60, re.compile(r'"LPS\?[0-9A-Z]{30,}"')),
        (40, re.compile(r'return\s*\(\s*function\s*\(\w,\w,\w,\w,\w,\w,\w,\w,\w,\w,\w,\w,\w,\w,\w,\w,\w,\w,\w,\w')),
        (30, re.compile(r'function\s*\(\s*vk\s*,\s*vB\s*,\s*DH\s*,\s*ZX')),
        (35, re.compile(r'0[Bb][01_]{8,}')),
        (25, re.compile(r'\bZV\b.*\bwhile\s*\(ZV\)\s*do\b', re.DOTALL)),
        (30, re.compile(r'vB\[0[BbXx][0-9a-fA-F_]{4,}\]')),
        (25, re.compile(r'0_[bBxX][0-9a-fA-F_]{4,}')),
        (20, re.compile(r'\bts\s*\(\s*0[xXbB][0-9a-fA-F_]+\s*,\s*vB\[')),
        (20, re.compile(r'\brY\s*\(\s*ts\s*\(')),
        (15, re.compile(r'\}\s*,\s*false\s*,\s*string\.sub\s*,\s*select\s*,\s*error')),
        (20, re.compile(r'string\.byte\s*,\s*tonumber\s*,\s*math\.ldexp\s*,\s*\.\.\.\s*\)\s*\(\.\.\.\s*\)\s*;')),
    ],
    "Unobfuscated": [
        (15, re.compile(r'--\s*[A-Za-z ]{5,}')),
        (20, re.compile(r'function\s+[a-zA-Z_][a-zA-Z0-9_]{3,}\s*\(')),
        (17, re.compile(r'\bprint\s*\(')),
        (15, re.compile(r'\bwarn\s*\(')),
        (15, re.compile(r'\brequire\s*\(')),
        (15, re.compile(r'\bfor\s+[a-zA-Z_]\w*\s*,\s*[a-zA-Z_]\w*\s+in\s+pairs\s*\(')),
        (15, re.compile(r'\bif\s+[a-zA-Z_]\w*\s*[=~<>]+\s*[a-zA-Z_\d"\']+\s+then\b')),
        (20, re.compile(r'\blocal\s+[a-zA-Z_][a-zA-Z0-9_]{3,}\s*=')),
        (15, re.compile(r'local\s+function\s+[a-zA-Z_]\w+\s*\(')),
        (10, re.compile(r'game\s*:\s*GetService\s*\(')),
        (10, re.compile(r'game\s*:\s*HttpGet\s*\(')),
        (12, re.compile(r'workspace\.')),
        (12, re.compile(r'script\.')),
    ],
}

_DEFINITELY_OBF = [
    re.compile(r'`[A-Za-z0-9+/]{10,}={0,2}`'),
    re.compile(r'error\s*\(\s*`Tamper Detected'),
    re.compile(r'lliilI1i'),
    re.compile(r'Protected_by_MoonSecV2'),
    re.compile(r'Protected By Hercules'),
    re.compile(r'This file was protected using Lunr'),
    re.compile(r'This file was protected using Luraph'),
    re.compile(r'This file was generated using Luraph Obfuscator'),
    re.compile(r'This script was generated using the MoonVeil'),
    re.compile(r'\[\[77fuscator'),
    re.compile(r'--ironbrew3:tm'),
    re.compile(r'return\s+v15\s*\(\s*"LOL!'),
    re.compile(r'[\u3480-\u34c0]{5,}'),
    re.compile(r'\b[lI1i]{5,}\b'),
    re.compile(r'All warfare is based on deception.*Sun Tzu'),
    re.compile(r'"LPS\?[0-9A-Z]{30,}"'),
    re.compile(r'0_[bBxX][0-9a-fA-F_]{6,}'),
    re.compile(r'wearedevs\.net/obfuscator'),
    re.compile(r'return\s*\(\s*function\s*\(\s*\.\.\.\s*\)\s*local\s+\w\s*=\s*\{\s*"(?:\\[0-9]{2,3}){6,}"'),
]

_WEAREDEVS_SIGNALS = [
    re.compile(r'wearedevs\.net/obfuscator'),
    re.compile(r'\[\[\s*v\d+\.\d+\.\d+\s+https?://'),
    re.compile(r'local\s+o\s*=\s*\{\s*"(?:\\[0-9]{2,3}){6,}"'),
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
    avg_line = (sum(len(l) for l in lines) / len(lines)) if lines else 0
    long_lines = sum(1 for l in lines if len(l) > 500) / max(len(lines), 1)
    hex_count = len(re.findall(r'0x[0-9a-fA-F]+', code))
    num_esc = len(re.findall(r'\\[0-9]{2,3}', code))
    ops = len(re.findall(r'[+\-*/%^&|]', code))
    unicode_cnt = len(re.findall(r'[\u3480-\u34c0]{3,}', code))
    backtick_strings = len(re.findall(r'`[^`]{6,}`', code))
    il_names = len(re.findall(r'\b[lI1i]{4,}\b', code))
    bin_literals = len(re.findall(r'0[Bb][01_]{4,}', code))
    underscore_hex = len(re.findall(r'0_[bBxX][0-9a-fA-F_]{4,}', code))
    dq_numesc_strings = len(re.findall(r'"(?:\\[0-9]{2,3}){6,}"', code))
    return {
        "entropy": calc_entropy(code), "avg_line_length": avg_line, "long_line_ratio": long_lines,
        "hex_literal_density": hex_count / max(total_chars / 1000, 1), "numeric_escape_density": num_esc / max(total_chars / 1000, 1),
        "operator_density": ops / max(total_chars / 1000, 1), "unicode_ident_count": unicode_cnt,
        "backtick_string_count": backtick_strings, "il_name_count": il_names, "bin_literal_count": bin_literals,
        "underscore_hex_count": underscore_hex, "dq_numesc_strings": dq_numesc_strings,
    }

def is_wearedevs(code: str) -> bool:
    for pat in _WEAREDEVS_SIGNALS:
        try:
            if pat.search(code): return True
        except: pass
    return False

def stat_bonus(obf_name: str, stats: dict, is_wad: bool = False) -> float:
    bonus = 0.0
    ent = stats.get("entropy", 0); nesc = stats.get("numeric_escape_density", 0); avg_line = stats.get("avg_line_length", 0)
    long_line = stats.get("long_line_ratio", 0); unicode_cnt = stats.get("unicode_ident_count", 0); backtick_cnt = stats.get("backtick_string_count", 0)
    il_cnt = stats.get("il_name_count", 0); bin_cnt = stats.get("bin_literal_count", 0); us_hex = stats.get("underscore_hex_count", 0); dq_nesc = stats.get("dq_numesc_strings", 0)

    if obf_name == "Prometheus":
        if nesc > 5: bonus += 10
        if 4.5 < ent < 6.0: bonus += 5
        if nesc > 15: bonus += 15
        if is_wad: bonus -= 80
        if dq_nesc > 10: bonus -= 40
    elif obf_name == "WeAreDevs":
        if nesc > 10: bonus += 15
        if dq_nesc > 20: bonus += 25
        if 4.0 < ent < 5.5: bonus += 8
        if avg_line > 200: bonus += 10
    elif obf_name == "MoonSec V2":
        if unicode_cnt > 5: bonus += 20
    elif obf_name == "MoonSec V3":
        if avg_line > 300: bonus += 8
        if ent > 5.5: bonus += 5
    elif obf_name == "Luraph 14":
        if long_line > 0.1: bonus += 8
        if stats.get("hex_literal_density", 0) > 10: bonus += 6
    elif obf_name == "Luraph 10":
        if il_cnt > 10: bonus += 10
        if ent > 4.5: bonus += 5
    elif obf_name == "LightRay":
        if bin_cnt > 20: bonus += 15
        if us_hex > 10: bonus += 12
        if avg_line > 1000: bonus += 10
        if ent > 4.8: bonus += 5
    elif obf_name == "LuaObfuscator VM":
        if long_line > 0.5: bonus += 8
    elif obf_name == "WynFuscator":
        if avg_line > 500: bonus += 10
        if ent > 5.0: bonus += 5
    elif obf_name == "Hercules":
        if avg_line > 100: bonus += 5
    elif obf_name == "IronBrew":
        if stats.get("operator_density", 0) > 20: bonus += 5
    elif obf_name == "MoonVeil":
        if avg_line > 200: bonus += 8
        if ent > 5.0: bonus += 5
    elif obf_name == "77fuscator":
        if avg_line > 300: bonus += 8
    elif obf_name == "Lunr":
        if backtick_cnt > 10: bonus += 15
        if il_cnt > 20: bonus += 10
        if ent > 4.5: bonus += 5
    elif obf_name == "25ms Obfuscator":
        if nesc > 8: bonus += 12
        if avg_line > 250: bonus += 10
        if ent > 5.2: bonus += 6
        if is_wad: bonus -= 60
        if dq_nesc > 10: bonus -= 30
    elif obf_name == "Unobfuscated":
        if avg_line < 120: bonus += 10
        if ent < 4.5: bonus += 8
        if backtick_cnt > 5: bonus -= 30
        if il_cnt > 10: bonus -= 25
        if ent > 5.5: bonus -= 20
        if avg_line > 400: bonus -= 15
        if bin_cnt > 10: bonus -= 20
        if us_hex > 5: bonus -= 20
    return bonus

def is_definitely_obfuscated(code: str) -> bool:
    for pat in _DEFINITELY_OBF:
        try:
            if pat.search(code): return True
        except: pass
    return False

def detect(code):
    stats = stat_features(code)
    raw_scores = {}
    definitely_obf = is_definitely_obfuscated(code)
    wad = is_wearedevs(code)

    for obf_name, patterns in SIGNATURES.items():
        score = 0.0
        for weight, pattern in patterns:
            try:
                if pattern.search(code): score += weight
            except: pass
        score += stat_bonus(obf_name, stats, is_wad=wad)
        if obf_name == "Unobfuscated" and definitely_obf: score = 0.0
        raw_scores[obf_name] = max(score, 0.0)

    sorted_scores = sorted(raw_scores.items(), key=lambda x: x[1], reverse=True)
    top_name, top_score = sorted_scores[0]
    second_score = sorted_scores[1][1] if len(sorted_scores) > 1 else 0.0
    total = sum(raw_scores.values())

    if top_score <= 0 or top_score < 20:
        return [("Custom / Unknown", 0.0)]

    gap_ratio = top_score / max(second_score, 1)
    percentages = []
    for name, score in raw_scores.items():
        if score <= 0: confidence = 0.0
        elif name == top_name:
            dominance = score / max(total, 1)
            gap_bonus = min(gap_ratio / 3, 1.0)
            strength = min(score / 120, 1.0)
            confidence = (dominance * 55 + gap_bonus * 25 + strength * 20)
        else:
            relative = score / max(top_score, 1)
            suppress = min(gap_ratio / 2, 1.0)
            confidence = relative * 45 * (1 - suppress)
        confidence = round(min(max(confidence, 0), 99.9), 1)
        percentages.append((name, confidence))

    percentages.sort(key=lambda x: x[1], reverse=True)
    return percentages

def score_1_to_10(pct: float) -> int:
    s = int(round(pct / 10.0))
    return max(1, min(10, s))
# =====================================================================
# FIM DO DETECTOR
# =====================================================================

# --- Servidor Web ---
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
    print(f"Servidor web a correr na porta {port}")

# --- Desofuscador (continuação) ---
async def run_deobf(source: bytes):
    with tempfile.TemporaryDirectory() as tmp:
        in_path = os.path.join(tmp, "input.lua")
        out_path = os.path.join(tmp, "out.lua")
        with open(in_path, "wb") as f:
            f.write(source)
        try:
            proc = await asyncio.create_subprocess_exec(
                NODE, "bin/pdeobf.js", in_path, "-o", out_path,
                cwd=DEOBF_DIR, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=DEOBF_TIMEOUT)
        except asyncio.TimeoutError:
            return None, f"timeout ({DEOBF_TIMEOUT}s)"
        except FileNotFoundError:
            return None, "Node.js não encontrado"
        if proc.returncode != 0 or not os.path.exists(out_path):
            return None, stderr.decode("utf-8", "replace")[-1200:]
        with open(out_path, "rb") as f:
            return f.read(), ""

async def fetch_url(url: str):
    if not re.match(r"^https?://", url):
        return None, "URL inválido"
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(url, timeout=aiohttp.ClientTimeout(total=20)) as r:
                if r.status != 200:
                    return None, f"HTTP {r.status}"
                return await r.read(), ""
    except Exception as e:
        return None, str(e)

# --- Botões e Comando .deobf ---
class PrometheusButton(discord.ui.Button):
    def __init__(self, enabled=True):
        super().__init__(label="Prometheus", style=discord.ButtonStyle.secondary,
                         emoji=discord.PartialEmoji(name="wearedevs", id=WEAREDEVS_EMOJI_ID),
                         disabled=not enabled)

    async def callback(self, interaction: discord.Interaction):
        source = getattr(self.view, "source", None)
        if source is None:
            await interaction.response.send_message("❌ script não encontrado.", ephemeral=True)
            return

        self.view.stop()
        await interaction.response.edit_message(
            content="⏳ **DropX pode demorar um pouco a desofuscar. Por favor, aguarda...**",
            embed=None, view=None)

        result, err = await run_deobf(source)

        if result is None:
            await interaction.followup.send(f"❌ falhou:\n```\n{err}\n```", ephemeral=False)
            return
        if len(result) > 8 * 1024 * 1024:
            await interaction.followup.send("❌ output > 8 MiB.", ephemeral=False)
            return

        final = (HEADER + result.decode("utf-8", "replace")).encode("utf-8")
        await interaction.followup.send(
            content=f"✅ desofuscado — {len(final)} bytes",
            file=discord.File(fp=io.BytesIO(final), filename="deobfuscated.txt"))

class DeobfView(discord.ui.View):
    def __init__(self, source: bytes, enabled=True):
        super().__init__(timeout=600)
        self.source = source
        self.add_item(PrometheusButton(enabled=enabled))

# --- Comando .alojar ---
@bot.command(name="alojar")
@commands.has_permissions(administrator=True)
async def alojar(ctx: commands.Context):
    config["channel_id"] = ctx.channel.id
    save_config(config)
    try:
        await ctx.message.delete()
    except:
        pass
    await ctx.reply(
        f"✅ **Bot alojado com sucesso!**\nA partir de agora, o bot só vai responder a comandos neste canal ({ctx.channel.mention}).",
        delete_after=10)

@alojar.error
async def alojar_error(ctx, error):
    if isinstance(error, commands.MissingPermissions):
        await ctx.reply("❌ Apenas administradores podem usar este comando.", delete_after=5)

# --- Helper para obter código (anexo ou URL) ---
async def get_source(ctx: commands.Context, url: str = None):
    if ctx.message.attachments:
        att = ctx.message.attachments[0]
        if not att.filename.endswith((".txt", ".lua", ".luau")):
            return None, "❌ anexo tem de ser `.txt`/`.lua`/`.luau`."
        if att.size > 5 * 1024 * 1024:
            return None, "❌ ficheiro > 5 MiB."
        return await att.read(), ""
    elif url:
        source, err = await fetch_url(url.strip())
        if source is None:
            return None, f"❌ não consegui obter o URL: {err}"
        if len(source) > 5 * 1024 * 1024:
            return None, "❌ ficheiro > 5 MiB."
        return source, ""
    return None, "❌ uso: `.deobf` + anexo `.txt`/`.lua` **ou** `.deobf <url_raw>`"

# --- Comando .deobf ---
@bot.command(name="deobf")
async def deobf(ctx: commands.Context, *, url: str = None):
    if config["channel_id"] is None:
        await ctx.reply("❌ O bot ainda não foi alojado. Pede a um admin para usar `.alojar` neste canal.", delete_after=5)
        return
    if ctx.channel.id != config["channel_id"]:
        await ctx.reply("❌ Este bot só pode ser usado no canal onde foi alojado.", delete_after=5)
        return

    source, err = await get_source(ctx, url)
    if source is None:
        await ctx.reply(err, delete_after=5)
        return

    try:
        await ctx.message.delete()
    except:
        pass

    code_text = source.decode("utf-8", "ignore")
    results = detect(code_text)
    top_name, top_pct = results[0] if results else ("Custom / Unknown", 0.0)
    is_prometheus = (top_name == "Prometheus")

    if is_prometheus:
        desc = f"**Ofuscador detetado:** {top_name} ({score_1_to_10(top_pct)}/10)\n\nClica no botão abaixo para desofuscar."
    else:
        desc = f"**Ofuscador detetado:** {top_name} ({score_1_to_10(top_pct)}/10)\n\n❌ **Este desofuscador ainda não está disponível neste bot.**"

    embed = discord.Embed(title="DropX Detector & Deobfuscator", description=desc, color=0x2B2D31)
    embed.set_author(name="Prometheus (WeAreDevs)", icon_url=WEAREDEVS_ICON)
    await ctx.reply(embed=embed, view=DeobfView(source, enabled=is_prometheus))

# --- NOVO Comando .detector ---
@bot.command(name="detector")
async def detector(ctx: commands.Context, *, url: str = None):
    if config["channel_id"] is None:
        await ctx.reply("❌ O bot ainda não foi alojado. Pede a um admin para usar `.alojar` neste canal.", delete_after=5)
        return
    if ctx.channel.id != config["channel_id"]:
        await ctx.reply("❌ Este bot só pode ser usado no canal onde foi alojado.", delete_after=5)
        return

    source, err = await get_source(ctx, url)
    if source is None:
        await ctx.reply(err.replace(".deobf", ".detector"), delete_after=5)
        return

    try:
        await ctx.message.delete()
    except:
        pass

    code_text = source.decode("utf-8", "ignore")
    results = detect(code_text)

    if not results or results[0][0] == "Custom / Unknown":
        await ctx.reply("🔍 **Resultado:** `Custom / Unknown` (score 1/10)")
        return

    lines = []
    for name, pct in results[:5]:
        if pct <= 0:
            continue
        bar_len = int(round(pct / 10))
        bar = "█" * bar_len + "░" * (10 - bar_len)
        lines.append(f"**{name}** — {score_1_to_10(pct)}/10 `{bar}` ({pct}%)")

    top_name, top_pct = results[0]
    embed = discord.Embed(
        title="🔍 DropX Detector",
        description=f"**Mais provável:** `{top_name}` (score {score_1_to_10(top_pct)}/10)\n\n" + "\n".join(lines),
        color=0x2B2D31)
    embed.set_footer(text=f"Tamanho analisado: {len(code_text)} caracteres")
    await ctx.reply(embed=embed)

# --- Eventos / Arranque ---
@bot.event
async def on_ready():
    print(f"Bot ligado: {bot.user}")
    try:
        await bot.tree.sync()
    except Exception as e:
        print(f"Erro sync: {e}")

async def main():
    await start_web_server()
    await bot.start(TOKEN)

if __name__ == "__main__":
    asyncio.run(main())
