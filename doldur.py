import asyncio, base64, json, os, subprocess, sys, tempfile, threading, time, zipfile
from urllib.parse import urlparse, parse_qs, unquote
import requests
from flask import Flask
from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command, StateFilter
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import Message

# ================== AYARLAR ==================
BOT_TOKEN = os.environ["8900993410:AAHlqTyQwtTGR0yNl9__3p3BddKcEKIJFi8"]
ADMIN_ID = int(os.environ["7523674506"])
RENDER_URL = os.environ.get("RENDER_URL", "")   # https://xxxx.onrender.com (sonunda / olmadan)
PORT = int(os.environ.get("PORT", "10000"))

XRAY_DIR = "/opt/render/project/xray_dir"
SOCKS_PORT = 10808
THREADS = 64
CHUNK = 1024 * 1024
FLUSH = 8 * 1024 * 1024
# ===============================================

DL_URLS = [
    "https://speed.cloudflare.com/__down?bytes=1000000000",
    "http://speedtest.tele2.net/10GB.zip",
    "https://proof.ovh.net/files/10Gb.dat",
    "http://ipv4.download.thinkbroadband.com/1GB.zip",
    "http://speedtest.ftp.otenet.gr/files/test10Gb.db",
    "http://speedtest.london.linode.com/100MB-london.bin",
    "http://speedtest.frankfurt.linode.com/100MB-frankfurt.bin",
    "http://speedtest.fremont.linode.com/100MB-fremont.bin",
]
PROXIES = {"http": f"socks5h://127.0.0.1:{SOCKS_PORT}",
           "https": f"socks5h://127.0.0.1:{SOCKS_PORT}"}

bot = Bot(BOT_TOKEN)
dp = Dispatcher(storage=MemoryStorage())

job = {"running": False}


class Fill(StatesGroup):
    waiting_gb = State()


# ---------- Xray kurulumu ----------

def ensure_xray():
    exe = os.path.join(XRAY_DIR, "xray")
    if os.path.exists(exe):
        return exe
    os.makedirs(XRAY_DIR, exist_ok=True)
    url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
    zpath = os.path.join(XRAY_DIR, "x.zip")
    import urllib.request
    urllib.request.urlretrieve(url, zpath)
    zipfile.ZipFile(zpath).extractall(XRAY_DIR)
    os.chmod(exe, 0o755)
    return exe


# ---------- Link parse ----------

def b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4)).decode(errors="ignore")


def fetch_links(src):
    if src.startswith("http"):
        r = requests.get(src, headers={"User-Agent": "v2rayN/6.0"}, timeout=20)
        r.raise_for_status()
        txt = r.text.strip()
        if "://" not in txt[:20]:
            txt = b64d(txt)
    else:
        txt = src
    return [l.strip() for l in txt.splitlines()
            if l.strip().split("://")[0] in ("vless", "vmess", "trojan", "ss")]


def stream_settings(net, sec, p):
    st = {"network": net, "security": sec}
    if net == "ws":
        st["wsSettings"] = {"path": p.get("path", "/"), "headers": {"Host": p.get("host", "")}}
    elif net == "grpc":
        st["grpcSettings"] = {"serviceName": p.get("serviceName", p.get("path", ""))}
    elif net == "httpupgrade":
        st["httpupgradeSettings"] = {"path": p.get("path", "/"), "host": p.get("host", "")}
    elif net == "xhttp":
        st["xhttpSettings"] = {"path": p.get("path", "/"), "host": p.get("host", ""),
                               "mode": p.get("mode", "auto")}
    if sec == "tls":
        t = {"serverName": p.get("sni") or p.get("host", ""),
             "fingerprint": p.get("fp", "chrome")}
        if p.get("alpn"):
            t["alpn"] = p["alpn"].split(",")
        st["tlsSettings"] = t
    elif sec == "reality":
        st["realitySettings"] = {"serverName": p.get("sni", ""), "fingerprint": p.get("fp", "chrome"),
                                 "publicKey": p.get("pbk", ""), "shortId": p.get("sid", ""),
                                 "spiderX": p.get("spx", "")}
    return st


def build_outbound(link):
    proto = link.split("://")[0]
    if proto == "vmess":
        j = json.loads(b64d(link[8:]))
        p = {"path": j.get("path", "/"), "host": j.get("host", ""), "sni": j.get("sni", ""),
             "fp": j.get("fp", "chrome"), "alpn": j.get("alpn", "")}
        sec = "tls" if j.get("tls") == "tls" else "none"
        return {"protocol": "vmess", "settings": {"vnext": [{
            "address": j["add"], "port": int(j["port"]),
            "users": [{"id": j["id"], "alterId": int(j.get("aid", 0)),
                       "security": j.get("scy", "auto")}]}]},
            "streamSettings": stream_settings(j.get("net", "tcp"), sec, p)}
    if proto == "ss":
        body = link[5:].split("#")[0]
        if "@" not in body:
            body = b64d(body)
        userinfo, hostport = body.rsplit("@", 1)
        if ":" not in userinfo:
            userinfo = b64d(userinfo)
        method, pw = userinfo.split(":", 1)
        host, port = hostport.split("?")[0].rsplit(":", 1)
        return {"protocol": "shadowsocks", "settings": {"servers": [{
            "address": host, "port": int(port), "method": method, "password": unquote(pw)}]}}
    u = urlparse(link)
    p = {k: v[0] for k, v in parse_qs(u.query).items()}
    net, sec = p.get("type", "tcp"), p.get("security", "none")
    st = stream_settings(net, sec, p)
    if proto == "vless":
        return {"protocol": "vless", "settings": {"vnext": [{
            "address": u.hostname, "port": u.port,
            "users": [{"id": unquote(u.username), "encryption": "none",
                       "flow": p.get("flow", "")}]}]}, "streamSettings": st}
    if proto == "trojan":
        if sec == "none":
            st["security"] = "tls"
            st["tlsSettings"] = {"serverName": p.get("sni", u.hostname)}
        return {"protocol": "trojan", "settings": {"servers": [{
            "address": u.hostname, "port": u.port, "password": unquote(u.username)}]},
            "streamSettings": st}
    raise ValueError("Desteklenmeyen protokol")


# ---------- Doldurma ----------

def worker(i, state):
    n = i
    local = 0
    s = requests.Session()
    while not state["stop"].is_set():
        url = DL_URLS[n % len(DL_URLS)]
        n += 1
        try:
            with s.get(url, stream=True, proxies=PROXIES, timeout=15) as r:
                r.raise_for_status()
                for chunk in r.iter_content(CHUNK):
                    if state["stop"].is_set():
                        return
                    local += len(chunk)
                    if local >= FLUSH:
                        with state["lock"]:
                            state["total"] += local
                            state["errs"] = 0
                        local = 0
        except Exception:
            with state["lock"]:
                state["errs"] += 1
            time.sleep(0.5)


def run_fill_blocking(link, target_gb, state):
    try:
        xray_exe = ensure_xray()
    except Exception as e:
        state["error"] = f"Xray kurulamadi: {e}"
        state["done"] = True
        return

    links = fetch_links(link)
    if not links:
        state["error"] = "Link bulunamadi veya desteklenmeyen format."
        state["done"] = True
        return

    cfg = {"log": {"loglevel": "warning"},
           "inbounds": [{"listen": "127.0.0.1", "port": SOCKS_PORT, "protocol": "socks",
                         "settings": {"udp": False}}],
           "outbounds": [build_outbound(links[0])]}
    path = os.path.join(tempfile.gettempdir(), f"vpn_fill_{os.getpid()}.json")
    with open(path, "w") as f:
        json.dump(cfg, f)

    xr = subprocess.Popen([xray_exe, "run", "-c", path],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(2)
    if xr.poll() is not None:
        state["error"] = f"Xray acilmadi:\n{xr.stdout.read()[:400]}"
        state["done"] = True
        return

    try:
        requests.get("http://cp.cloudflare.com/generate_204", proxies=PROXIES, timeout=15)
    except Exception as e:
        xr.terminate()
        state["error"] = f"Config'e baglanilamadi ({type(e).__name__}). Baska bir link dene."
        state["done"] = True
        return

    for i in range(THREADS):
        threading.Thread(target=worker, args=(i, state), daemon=True).start()

    target = int(target_gb * 1024 ** 3)
    while not state["stop"].is_set():
        if state["total"] >= target:
            break
        if state["errs"] > THREADS * 2:
            state["error"] = "Surekli hata: kota dolmus veya baglanti koptu."
            break
        time.sleep(2)

    state["stop"].set()
    xr.terminate()
    state["done"] = True


# ---------- Telegram akisi ----------

def looks_like_link(text: str) -> bool:
    return "://" in text and text.split("://")[0] in (
        "http", "https", "vless", "vmess", "trojan", "ss"
    )


@dp.message(Command("start"))
async def cmd_start(msg: Message):
    if msg.from_user.id != ADMIN_ID:
        return
    await msg.answer(
        "Marzban/panel abonelik linkini veya tek bir VPN linkini (vless/vmess/trojan/ss) gonder, "
        "kac GB doldurulacagini sorarim.\n\n/stop ile durdurabilirsin."
    )


@dp.message(StateFilter(None), F.text.func(looks_like_link))
async def got_link(msg: Message, state: FSMContext):
    if msg.from_user.id != ADMIN_ID:
        return
    if job["running"]:
        await msg.answer("Zaten calisan bir islem var. Once /stop gonder.")
        return
    await state.update_data(link=msg.text.strip())
    await state.set_state(Fill.waiting_gb)
    await msg.answer("Kac GB doldurulsun? (sayi yaz, orn: 5)")


@dp.message(Fill.waiting_gb)
async def got_gb(msg: Message, state: FSMContext):
    if msg.from_user.id != ADMIN_ID:
        return
    try:
        gb = float(msg.text.strip().replace(",", "."))
        if gb <= 0:
            raise ValueError
    except ValueError:
        await msg.answer("Gecerli bir sayi yaz, orn: 5")
        return

    data = await state.get_data()
    link = data["link"]
    await state.clear()

    run_state = {"total": 0, "errs": 0, "lock": threading.Lock(),
                 "stop": threading.Event(), "error": None, "done": False}
    job["state"] = run_state
    job["running"] = True

    threading.Thread(target=run_fill_blocking, args=(link, gb, run_state), daemon=True).start()
    status_msg = await msg.answer(f"Basladi, hedef {gb} GB. Durdurmak icin /stop")

    last, last_t = 0, time.time()
    while not run_state["done"]:
        await asyncio.sleep(5)
        now = time.time()
        cur = run_state["total"]
        speed = (cur - last) / (now - last_t) / 1024 ** 2
        last, last_t = cur, now
        try:
            await status_msg.edit_text(
                f"{cur/1024**3:.2f} / {gb} GB | {speed:.1f} MB/s"
            )
        except Exception:
            pass

    if run_state.get("error"):
        await msg.answer(f"Durdu: {run_state['error']}\n"
                         f"Doldurulan: {run_state['total']/1024**3:.2f} GB")
    else:
        await msg.answer(f"Tamamlandi: {run_state['total']/1024**3:.2f} GB")
    job["running"] = False


@dp.message(Command("stop"))
async def cmd_stop(msg: Message, state: FSMContext):
    if msg.from_user.id != ADMIN_ID:
        return
    await state.clear()
    if job["running"]:
        job["state"]["stop"].set()
        await msg.answer("Durduruluyor...")
    else:
        await msg.answer("Calisan islem yok.")


@dp.message(StateFilter(None))
async def fallback(msg: Message):
    if msg.from_user.id != ADMIN_ID:
        return
    await msg.answer("Once bir Marzban/VPN linki gonder.")


# ---------- Flask: Render icin web sunucusu + uyku engelleme ----------

flask_app = Flask(__name__)


@flask_app.route("/")
def index():
    return "ok"


def run_flask():
    flask_app.run(host="0.0.0.0", port=PORT)


def self_ping_loop():
    if not RENDER_URL:
        return
    while True:
        try:
            requests.get(RENDER_URL, timeout=10)
        except Exception:
            pass
        time.sleep(600)  # 10 dakikada bir


async def main():
    threading.Thread(target=run_flask, daemon=True).start()
    threading.Thread(target=self_ping_loop, daemon=True).start()
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())