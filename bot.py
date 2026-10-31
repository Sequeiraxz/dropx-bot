import os
import io
import asyncio
import tempfile
import re
import aiohttp
import discord
import urllib.request
import tarfile
import shutil
import stat
from discord.ext import commands
from aiohttp import web

# ⚠️ METE O TEU TOKEN AQUI
TOKEN = "MTU2NTc3NDk0MjA4NjEwMzEyMg.GwcgxL.9d50odJ3Ujrf0nrIcToLXPFW64yhA1E7hPLJlQ"

DEOBF_DIR = os.environ.get("DEOBF_DIR", "./Prometheus-Deobfuscator-main")
NODE = os.environ.get("NODE", "node")
DEOBF_TIMEOUT = 120

HEADER = "Deobfuscate By DropX :)\n\n"
WEAREDEVS_ICON = "https://www.google.com/s2/favicons?domain=wearedevs.net&sz=128"
WEAREDEVS_EMOJI_ID = 1565837351769481216

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix=".", intents=intents)

# --- Instalação automática do Node.js ---
def setup_node():
    node_dir = "./node-portable"
    node_bin = os.path.join(node_dir, "bin", "node")
    if os.path.exists(node_bin):
        return  # Já está instalado
    
    print("A descarregar Node.js portátil...")
    url = "https://nodejs.org/dist/v20.11.1/node-v20.11.1-linux-x64.tar.xz"
    tar_path = "node.tar.xz"
    
    try:
        urllib.request.urlretrieve(url, tar_path)
        os.makedirs(node_dir, exist_ok=True)
        with tarfile.open(tar_path, "r:xz") as tar:
            members = tar.getmembers()
            for member in members:
                parts = member.name.split("/", 1)
                if len(parts) > 1 and parts[1]:
                    member.name = parts[1]
                    tar.extract(member, node_dir)
        os.remove(tar_path)
        os.chmod(node_bin, os.stat(node_bin).st_mode | stat.S_IEXEC)
        print("Node.js instalado com sucesso!")
    except Exception as e:
        print(f"Erro ao instalar Node.js: {e}")

# --- Servidor Web para a PhanomCloud ---
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

# --- Desofuscador ---
async def run_deobf(source: bytes) -> tuple[bytes | None, str]:
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

async def fetch_url(url: str) -> tuple[bytes | None, str]:
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

# --- Botões e Comando ---
class PrometheusButton(discord.ui.Button):
    def __init__(self):
        super().__init__(label="Prometheus", style=discord.ButtonStyle.secondary, emoji=discord.PartialEmoji(name="wearedevs", id=WEAREDEVS_EMOJI_ID))

    async def callback(self, interaction: discord.Interaction):
        source = getattr(self.view, "source", None)
        if source is None:
            await interaction.response.send_message("❌ script não encontrado.", ephemeral=True)
            return
        await interaction.response.defer()
        result, err = await run_deobf(source)
        if result is None:
            await interaction.followup.send(f"❌ falhou:\n```\n{err}\n```", ephemeral=True)
            return
        if len(result) > 8 * 1024 * 1024:
            await interaction.followup.send("❌ output > 8 MiB.", ephemeral=True)
            return
        final = (HEADER + result.decode("utf-8", "replace")).encode("utf-8")
        await interaction.followup.send(content=f"✅ desofuscado — {len(final)} bytes", file=discord.File(fp=io.BytesIO(final), filename="deobfuscated.txt"))

class DeobfView(discord.ui.View):
    def __init__(self, source: bytes):
        super().__init__(timeout=300)
        self.source = source
        self.add_item(PrometheusButton())

@bot.command(name="deobf")
async def deobf(ctx: commands.Context, *, url: str = None):
    if ctx.message.attachments:
        att = ctx.message.attachments[0]
        if not att.filename.endswith((".txt", ".lua", ".luau")):
            await ctx.reply("❌ anexo tem de ser `.txt`/`.lua`/`.luau`.")
            return
        if att.size > 5 * 1024 * 1024:
            await ctx.reply("❌ ficheiro > 5 MiB.")
            return
        source = await att.read()
    elif url:
        source, err = await fetch_url(url.strip())
        if source is None:
            await ctx.reply(f"❌ não consegui obter o URL: {err}")
            return
        if len(source) > 5 * 1024 * 1024:
            await ctx.reply("❌ ficheiro > 5 MiB.")
            return
    else:
        await ctx.reply("❌ uso: `.deobf` + anexo `.txt`/`.lua` **ou** `.deobf <url_raw>`")
        return

    embed = discord.Embed(title="DropX Deobfuscator", description="**Ofuscador detetado:** Prometheus (WeAreDevs)\n\nClica no botão abaixo para desofuscar.", color=0x2B2D31)
    embed.set_author(name="Prometheus (WeAreDevs)", icon_url=WEAREDEVS_ICON)
    await ctx.reply(embed=embed, view=DeobfView(source))

@bot.event
async def on_ready():
    print(f"Bot ligado: {bot.user}")
    try:
        await bot.tree.sync()
    except Exception as e:
        print(f"Erro sync: {e}")

# --- Arranque ---
async def main():
    setup_node() # <--- Instala o Node automaticamente antes de ligar o bot
    await start_web_server()
    await bot.start(TOKEN)

if __name__ == "__main__":
    asyncio.run(main())
