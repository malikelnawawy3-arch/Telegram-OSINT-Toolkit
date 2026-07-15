#!/usr/bin/env python3
"""
Telegram OSINT Toolkit - Highly Advanced Edition
================================================
Professional-grade local Telegram intelligence tool for OSINT, 
cybersecurity research, threat intelligence, and authorized investigations.

Features:
- Bulk & single keyword search with date filters
- Full chat export (JSON / CSV / HTML) + media + link extraction
- Member enumeration with export
- User/channel profiling
- Live real-time monitoring with keyword alerts
- Proxy / Tor support (socks5 / http)
- Robust FloodWait handling + auto-retry
- SQLite persistent storage with rich metadata
- Join public channels
- Database statistics

Author: Anurag Roy (@AnuragRoy485)
License: MIT
"""

import asyncio
import json
import csv
import sqlite3
import argparse
import os
import sys
import re
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any, Union
import logging
from urllib.parse import urlparse

try:
    from telethon import TelegramClient, events
    from telethon.errors import FloodWaitError, SessionPasswordNeededError, ChannelPrivateError
    from telethon.tl.functions.channels import JoinChannelRequest, GetFullChannelRequest
except ImportError:
    print("ERROR: Telethon not installed. Run: pip install telethon")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.panel import Panel
except ImportError:
    print("ERROR: Rich not installed. Run: pip install rich")
    sys.exit(1)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # optional dependency

console = Console()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("TelegramOSINT")


def parse_proxy(proxy_str: Optional[str]) -> Optional[Dict]:
    """Parse proxy string into Telethon-compatible dict.
    Supports: socks5://user:pass@host:port | socks5://host:port | http://...
    """
    if not proxy_str:
        return None

    proxy_str = proxy_str.strip()
    try:
        if "://" not in proxy_str:
            proxy_str = "socks5://" + proxy_str

        parsed = urlparse(proxy_str)
        scheme = parsed.scheme.lower()
        if scheme not in ("socks5", "socks4", "http", "https"):
            console.print(f"[yellow]Unknown scheme '{scheme}', defaulting to socks5[/]")
            scheme = "socks5"

        host = parsed.hostname
        port = parsed.port or (1080 if "socks" in scheme else 8080)

        proxy_dict = {
            "proxy_type": scheme,
            "addr": host,
            "port": int(port),
            "rdns": True,
        }
        if parsed.username:
            proxy_dict["username"] = parsed.username
        if parsed.password:
            proxy_dict["password"] = parsed.password

        console.print(f"[cyan]Using proxy → {scheme}://{host}:{port}[/]")
        return proxy_dict
    except Exception as e:
        console.print(f"[red]Failed to parse proxy '{proxy_str}': {e}[/]")
        return None


class TelegramOSINT:
    def __init__(
        self,
        api_id: int,
        api_hash: str,
        session_name: str = "osint_session",
        proxy: Optional[str] = None,
        flood_sleep_threshold: int = 60,
    ):
        self.proxy = parse_proxy(proxy)
        self.client = TelegramClient(
            session_name,
            api_id,
            api_hash,
            proxy=self.proxy,
            flood_sleep_threshold=flood_sleep_threshold,
        )
        self.db_path = Path("telegram_osint.db")
        self.init_db()
        self.session_name = session_name

    def init_db(self):
        """Initialize enhanced SQLite schema."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER,
                chat_id INTEGER,
                chat_title TEXT,
                sender_id INTEGER,
                sender_username TEXT,
                date TEXT,
                text TEXT,
                media_path TEXT,
                views INTEGER,
                forwards INTEGER,
                replies INTEGER,
                query TEXT,
                exported_at TEXT,
                PRIMARY KEY (id, chat_id)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS entities (
                id INTEGER PRIMARY KEY,
                username TEXT,
                title TEXT,
                type TEXT,
                members_count INTEGER,
                description TEXT,
                last_scraped TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_date ON messages(date)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_query ON messages(query)")
        conn.commit()
        conn.close()

    async def start(self):
        """Connect and show login info."""
        try:
            await self.client.start()
            me = await self.client.get_me()
            console.print(Panel(
                f"[green]✅ Connected successfully![/]\n"
                f"Logged in as: [bold]{me.first_name}[/] (@{me.username or 'N/A'})\n"
                f"User ID: {me.id}",
                title="Telegram OSINT Toolkit",
                border_style="green"
            ))
        except SessionPasswordNeededError:
            console.print("[red]2FA password required. Enter it when Telethon prompts.[/]")
            sys.exit(1)
        except Exception as e:
            console.print(f"[red]Login failed: {e}[/]")
            sys.exit(1)

    async def get_entity(self, identifier: Union[str, int]):
        """Resolve username / link / ID with good error messages."""
        try:
            return await self.client.get_entity(identifier)
        except ChannelPrivateError:
            console.print(f"[red]Private entity: {identifier}. Need invite or membership.[/]")
            return None
        except Exception as e:
            console.print(f"[red]Could not resolve '{identifier}': {e}[/]")
            return None

    async def safe_iter_messages(self, entity, **kwargs):
        """Generator that auto-handles FloodWait and retries."""
        retries = 5
        for attempt in range(retries):
            try:
                async for msg in self.client.iter_messages(entity, **kwargs):
                    yield msg
                return
            except FloodWaitError as e:
                wait = e.seconds + 5
                console.print(f"[yellow]⚠️  FloodWait: sleeping {wait}s (try {attempt+1}/{retries})[/]")
                await asyncio.sleep(wait)
            except Exception as e:
                console.print(f"[red]Iteration error: {e}[/]")
                await asyncio.sleep(3)
                if attempt == retries - 1:
                    break

    def save_message(self, chat_id: int, chat_title: str, msg, query: str = None, media_path: str = None):
        """Persist rich message metadata."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            INSERT OR REPLACE INTO messages 
            (id, chat_id, chat_title, sender_id, sender_username, date, text, 
             media_path, views, forwards, replies, query, exported_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            msg.id,
            chat_id,
            chat_title,
            msg.sender_id,
            getattr(msg.sender, "username", None) if msg.sender else None,
            msg.date.isoformat() if msg.date else None,
            msg.text or msg.message or "",
            media_path,
            getattr(msg, "views", None),
            getattr(msg, "forwards", None),
            getattr(msg.replies, "replies", None) if getattr(msg, "replies", None) else None,
            query,
            datetime.utcnow().isoformat()
        ))
        conn.commit()
        conn.close()

    async def search_messages(
        self,
        chat: str,
        query: str,
        limit: int = 100,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> List[Dict]:
        """Server-side search + progress + DB save."""
        entity = await self.get_entity(chat)
        if not entity:
            return []

        chat_title = getattr(entity, "title", None) or getattr(entity, "username", str(entity.id))
        results = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task(f"[cyan]Searching {chat_title} for '{query}'...", total=limit or None)

            async for msg in self.safe_iter_messages(entity, search=query, limit=limit):
                if since and msg.date and msg.date.replace(tzinfo=None) < since:
                    continue
                if until and msg.date and msg.date.replace(tzinfo=None) > until:
                    continue

                msg_data = {
                    "id": msg.id,
                    "date": msg.date.isoformat() if msg.date else None,
                    "sender_id": msg.sender_id,
                    "sender": getattr(msg.sender, "username", None) if msg.sender else None,
                    "text": msg.text or "",
                    "chat": chat,
                    "views": getattr(msg, "views", None),
                    "forwards": getattr(msg, "forwards", None),
                }
                results.append(msg_data)
                self.save_message(entity.id, chat_title, msg, query=query)
                progress.update(task, advance=1)
                await asyncio.sleep(0.15)

        console.print(f"[green]Found {len(results)} messages matching '{query}'[/]")
        return results

    async def bulk_search(
        self,
        chats: List[str],
        query: str,
        limit: int = 50,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        output: str = "bulk_results.json",
    ):
        """Bulk search with aggregation + JSON + Markdown report."""
        all_results = {}
        total_hits = 0

        for i, chat in enumerate(chats, 1):
            console.print(f"\n[bold cyan][{i}/{len(chats)}] → {chat}[/]")
            results = await self.search_messages(chat, query, limit, since, until)
            if results:
                all_results[chat] = results
                total_hits += len(results)
            await asyncio.sleep(1.5)

        with open(output, "w", encoding="utf-8") as f:
            json.dump({
                "query": query,
                "timestamp": datetime.utcnow().isoformat(),
                "total_chats": len(chats),
                "chats_with_hits": len(all_results),
                "total_messages": total_hits,
                "results": all_results
            }, f, indent=2, ensure_ascii=False)

        md_path = output.replace(".json", ".md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(f"# Bulk Search Report\n\n")
            f.write(f"**Query:** `{query}`  \n")
            f.write(f"**Date:** {datetime.utcnow().isoformat()}  \n")
            f.write(f"**Total Hits:** {total_hits}\n\n")
            for chat, msgs in all_results.items():
                f.write(f"## {chat} ({len(msgs)} hits)\n\n")
                for m in msgs[:25]:
                    f.write(f"- `{m['date']}` @{m['sender']}: {m['text'][:180]}...\n")
                f.write("\n")

        console.print(Panel(
            f"[green]✅ Bulk search complete![/]\n"
            f"Chats processed: {len(chats)}\n"
            f"Chats with hits: {len(all_results)}\n"
            f"Total messages: {total_hits}\n"
            f"JSON → {output}\n"
            f"Markdown → {md_path}",
            title="Bulk Search Summary",
            border_style="green"
        ))
        return all_results

    async def export_chat(
        self,
        chat: str,
        limit: int = 500,
        export_format: str = "json",
        download_media: bool = False,
        extract_links: bool = False,
    ):
        """Full history export with media + links + HTML support."""
        entity = await self.get_entity(chat)
        if not entity:
            return

        chat_title = getattr(entity, "title", None) or getattr(entity, "username", str(entity.id))
        messages = []
        media_dir = Path(f"media_{entity.id}")
        if download_media:
            media_dir.mkdir(exist_ok=True)

        links = set()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task(f"[cyan]Exporting {chat_title}...", total=limit or None)

            async for msg in self.safe_iter_messages(entity, limit=limit or None):
                media_path = None
                if download_media and msg.media:
                    try:
                        path = await msg.download_media(file=media_dir / f"{msg.id}")
                        media_path = str(path) if path else None
                    except Exception as e:
                        logger.warning(f"Media failed for {msg.id}: {e}")

                text = msg.text or msg.message or ""
                if extract_links and text:
                    found = re.findall(r'https?://[^\s<>"\']+|t\.me/[^\s<>"\']+', text)
                    links.update(found)

                msg_data = {
                    "id": msg.id,
                    "date": msg.date.isoformat() if msg.date else None,
                    "sender_id": msg.sender_id,
                    "sender_username": getattr(msg.sender, "username", None) if msg.sender else None,
                    "text": text,
                    "views": getattr(msg, "views", None),
                    "forwards": getattr(msg, "forwards", None),
                    "replies": getattr(msg.replies, "replies", None) if getattr(msg, "replies", None) else None,
                    "media_path": media_path,
                    "forwarded_from": str(msg.fwd_from) if msg.fwd_from else None,
                }
                messages.append(msg_data)
                self.save_message(entity.id, chat_title, msg, media_path=media_path)
                progress.update(task, advance=1)
                await asyncio.sleep(0.2)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_title = re.sub(r'[^\w\-]', '_', chat_title)[:40]
        base = f"{entity.id}_{safe_title}_{ts}"

        if export_format == "json":
            path = f"{base}.json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump({
                    "chat": chat_title,
                    "chat_id": entity.id,
                    "exported_at": datetime.utcnow().isoformat(),
                    "message_count": len(messages),
                    "messages": messages
                }, f, indent=2, ensure_ascii=False)
        elif export_format == "csv":
            path = f"{base}.csv"
            if messages:
                with open(path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=list(messages[0].keys()))
                    writer.writeheader()
                    writer.writerows(messages)
        elif export_format == "html":
            path = f"{base}.html"
            self._export_html(path, chat_title, messages)
        else:
            path = f"{base}.json"

        if extract_links and links:
            links_path = f"{base}_links.txt"
            with open(links_path, "w", encoding="utf-8") as f:
                for link in sorted(links):
                    f.write(link + "\n")
            console.print(f"[cyan]Extracted {len(links)} unique links → {links_path}[/]")

        console.print(Panel(
            f"[green]✅ Export complete![/]\n"
            f"Messages: {len(messages)}\n"
            f"File: {path}\n"
            f"Media: {media_dir if download_media else 'skipped'}",
            title=f"Export: {chat_title}",
            border_style="green"
        ))

    def _export_html(self, path: str, title: str, messages: List[Dict]):
        """Beautiful dark-mode HTML report."""
        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{title} – OSINT Export</title>
<style>
body {{ font-family: system-ui, -apple-system, sans-serif; max-width: 960px; margin: 40px auto; padding: 20px; background: #0d1117; color: #c9d1d9; }}
.msg {{ border-left: 4px solid #00ff9d; padding: 14px 18px; margin: 14px 0; background: #161b22; border-radius: 0 10px 10px 0; }}
.meta {{ color: #8b949e; font-size: 0.82em; margin-bottom: 8px; }}
.text {{ white-space: pre-wrap; line-height: 1.55; }}
h1 {{ color: #00ff9d; border-bottom: 1px solid #30363d; padding-bottom: 12px; }}
a {{ color: #58a6ff; }}
</style></head><body>
<h1>{title}</h1>
<p>Exported: {datetime.utcnow().isoformat()} UTC | Total messages: {len(messages)}</p>
"""
        for m in messages:
            html += f"""
<div class="msg">
  <div class="meta">#{m['id']} · {m.get('date','')} · @{m.get('sender_username') or m.get('sender_id')} · views: {m.get('views') or '–'}</div>
  <div class="text">{(m.get('text') or '[media / no text]').replace('<','&lt;')}</div>
</div>"""
        html += "</body></html>"
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    async def get_members(self, chat: str, limit: int = 200):
        """Enumerate members + auto JSON export."""
        entity = await self.get_entity(chat)
        if not entity:
            return

        console.print(f"[cyan]Fetching up to {limit} members of {getattr(entity, 'title', chat)}...[/]")
        participants = []
        try:
            async for user in self.client.iter_participants(entity, limit=limit):
                participants.append(user)
                await asyncio.sleep(0.04)
        except FloodWaitError as e:
            console.print(f"[yellow]FloodWait on members: sleeping {e.seconds}s[/]")
            await asyncio.sleep(e.seconds + 3)

        table = Table(title=f"Members — {getattr(entity, 'title', chat)} ({len(participants)})")
        table.add_column("ID", style="cyan")
        table.add_column("Username")
        table.add_column("Name")
        table.add_column("Type")

        for p in participants[:40]:
            typ = "bot" if p.bot else ("premium" if getattr(p, "premium", False) else "user")
            table.add_row(
                str(p.id),
                f"@{p.username}" if p.username else "—",
                f"{p.first_name or ''} {p.last_name or ''}".strip() or "—",
                typ
            )
        console.print(table)

        if participants:
            out = f"members_{entity.id}_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
            data = [{
                "id": p.id,
                "username": p.username,
                "first_name": p.first_name,
                "last_name": p.last_name,
                "bot": p.bot,
                "premium": getattr(p, "premium", False),
            } for p in participants]
            with open(out, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            console.print(f"[green]Saved {len(participants)} members → {out}[/]")

        return participants

    async def profile_user(self, user: str):
        """Rich profile view."""
        entity = await self.get_entity(user)
        if not entity:
            return

        about = getattr(entity, "about", None)
        console.print(Panel(
            f"[bold]ID:[/] {entity.id}\n"
            f"[bold]Username:[/] @{entity.username or 'N/A'}\n"
            f"[bold]Name:[/] {getattr(entity, 'first_name', '')} {getattr(entity, 'last_name', '') or ''}\n"
            f"[bold]About:[/] {about or 'N/A'}\n"
            f"[bold]Type:[/] {'Channel/Broadcast' if getattr(entity, 'broadcast', False) else 'User / Group'}\n"
            f"[bold]Verified:[/] {getattr(entity, 'verified', False)}\n"
            f"[bold]Restricted:[/] {getattr(entity, 'restricted', False)}\n"
            f"[bold]Scam/Fake:[/] {getattr(entity, 'scam', False)} / {getattr(entity, 'fake', False)}",
            title=f"Profile → {user}",
            border_style="blue"
        ))

    async def join_channel(self, channel: str):
        """Join a public channel."""
        entity = await self.get_entity(channel)
        if not entity:
            return
        try:
            await self.client(JoinChannelRequest(entity))
            console.print(f"[green]✅ Joined {channel}[/]")
        except Exception as e:
            console.print(f"[red]Join failed: {e}[/]")

    async def monitor(self, chats: List[str], keywords: Optional[List[str]] = None, duration: int = 0):
        """Real-time keyword monitoring."""
        console.print(Panel(
            f"[bold magenta]LIVE MONITOR[/]\n"
            f"Chats: {', '.join(chats)}\n"
            f"Keywords: {keywords or 'ALL messages'}\n"
            f"Duration: {'∞ (Ctrl+C to stop)' if duration == 0 else f'{duration} seconds'}",
            title="MONITOR MODE",
            border_style="magenta"
        ))

        @self.client.on(events.NewMessage(chats=chats if chats else None))
        async def handler(event):
            text = event.message.text or ""
            if keywords and not any(kw.lower() in text.lower() for kw in keywords):
                return
            sender = await event.get_sender()
            uname = getattr(sender, "username", None) or str(sender.id)
            console.print(
                f"[bold magenta][{event.date.strftime('%H:%M:%S')}][/] "
                f"[cyan]{event.chat_id}[/] | @{uname}: {text[:220]}"
            )
            chat_title = getattr(event.chat, "title", str(event.chat_id))
            self.save_message(event.chat_id, chat_title, event.message, query="monitor")

        if duration > 0:
            await asyncio.sleep(duration)
            console.print("[yellow]Monitor duration finished.[/]")
        else:
            await self.client.run_until_disconnected()

    async def load_chats_list(self, file_path: str) -> List[str]:
        """Load channels from .txt or .json."""
        path = Path(file_path)
        if not path.exists():
            console.print(f"[red]File not found: {file_path}[/]")
            return []
        if path.suffix.lower() == ".json":
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else [data]
        with open(path, encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    async def db_stats(self):
        """Quick database overview."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM messages")
        total = c.fetchone()[0]
        c.execute("SELECT COUNT(DISTINCT chat_id) FROM messages")
        chats = c.fetchone()[0]
        c.execute("SELECT COUNT(DISTINCT query) FROM messages WHERE query IS NOT NULL")
        queries = c.fetchone()[0]
        conn.close()

        console.print(Panel(
            f"Total messages stored : [bold]{total}[/]\n"
            f"Unique chats          : [bold]{chats}[/]\n"
            f"Unique queries        : [bold]{queries}[/]\n"
            f"Database path         : {self.db_path.absolute()}",
            title="Database Statistics",
            border_style="blue"
        ))


async def main():
    parser = argparse.ArgumentParser(
        description="🚀 Telegram OSINT Toolkit — Advanced Intelligence Gathering Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python telegram_osint.py search @durov "telegram" --limit 50
  python telegram_osint.py bulk-search channels.txt "APT36 OR malware" --limit 100 --since 2025-01-01
  python telegram_osint.py export @channel --limit 2000 --format html --media --links
  python telegram_osint.py members @group --limit 500
  python telegram_osint.py monitor @channel1 @channel2 --keywords ransomware,APT --duration 3600
  python telegram_osint.py profile @username
  python telegram_osint.py join @publicchannel
  python telegram_osint.py stats
  python telegram_osint.py --proxy socks5://127.0.0.1:9050 bulk-search channels.txt "keyword"
        """
    )
    parser.add_argument("--api-id", type=int, help="Telegram API ID")
    parser.add_argument("--api-hash", help="Telegram API Hash")
    parser.add_argument("--session", default="osint_session", help="Session file name")
    parser.add_argument("--proxy", help="Proxy (socks5://user:pass@host:port or socks5://host:port)")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # bulk-search
    bs = subparsers.add_parser("bulk-search", help="Bulk keyword search across many chats")
    bs.add_argument("chats_file", help="channels.txt or channels.json")
    bs.add_argument("query", help="Search query")
    bs.add_argument("--limit", type=int, default=50)
    bs.add_argument("--since", help="YYYY-MM-DD")
    bs.add_argument("--until", help="YYYY-MM-DD")
    bs.add_argument("--output", default="bulk_results.json")

    # search
    s = subparsers.add_parser("search", help="Search single chat")
    s.add_argument("chat")
    s.add_argument("query")
    s.add_argument("--limit", type=int, default=100)
    s.add_argument("--since")
    s.add_argument("--until")

    # export
    e = subparsers.add_parser("export", help="Export chat history")
    e.add_argument("chat")
    e.add_argument("--limit", type=int, default=500)
    e.add_argument("--format", choices=["json", "csv", "html"], default="json")
    e.add_argument("--media", action="store_true", help="Download media files")
    e.add_argument("--links", action="store_true", help="Extract all URLs")

    # members
    m = subparsers.add_parser("members", help="Enumerate members")
    m.add_argument("chat")
    m.add_argument("--limit", type=int, default=200)

    # profile
    p = subparsers.add_parser("profile", help="User / channel profile")
    p.add_argument("user")

    # join
    j = subparsers.add_parser("join", help="Join public channel")
    j.add_argument("channel")

    # monitor
    mon = subparsers.add_parser("monitor", help="Live keyword monitoring")
    mon.add_argument("chats", nargs="+", help="One or more chats")
    mon.add_argument("--keywords", help="Comma-separated keywords (optional)")
    mon.add_argument("--duration", type=int, default=0, help="Seconds (0 = forever)")

    # stats
    subparsers.add_parser("stats", help="Show local DB statistics")

    args = parser.parse_args()

    api_id = args.api_id or int(os.getenv("TG_API_ID", "0"))
    api_hash = args.api_hash or os.getenv("TG_API_HASH")

    if not api_id or not api_hash:
        console.print("[red]❌ Missing API credentials!\n"
                      "Use --api-id / --api-hash or set TG_API_ID & TG_API_HASH in environment / .env[/]")
        return

    tool = TelegramOSINT(
        api_id=api_id,
        api_hash=api_hash,
        session_name=args.session,
        proxy=args.proxy,
    )
    await tool.start()

    def parse_date(d: Optional[str]) -> Optional[datetime]:
        if not d:
            return None
        try:
            return datetime.fromisoformat(d)
        except Exception:
            console.print(f"[red]Invalid date: {d}. Use YYYY-MM-DD[/]")
            return None

    if args.command == "bulk-search":
        chats = await tool.load_chats_list(args.chats_file)
        if chats:
            await tool.bulk_search(
                chats, args.query, args.limit,
                parse_date(args.since), parse_date(args.until), args.output
            )

    elif args.command == "search":
        results = await tool.search_messages(
            args.chat, args.query, args.limit,
            parse_date(args.since), parse_date(args.until)
        )
        for r in results:
            console.print(
                f"[dim]{r['date']}[/] | @{r['sender'] or r['sender_id']} | "
                f"views:{r.get('views')} | {r['text'][:180]}"
            )

    elif args.command == "export":
        await tool.export_chat(
            args.chat, args.limit, args.format,
            download_media=args.media, extract_links=args.links
        )

    elif args.command == "members":
        await tool.get_members(args.chat, args.limit)

    elif args.command == "profile":
        await tool.profile_user(args.user)

    elif args.command == "join":
        await tool.join_channel(args.channel)

    elif args.command == "monitor":
        kws = [k.strip() for k in args.keywords.split(",")] if args.keywords else None
        await tool.monitor(args.chats, kws, args.duration)

    elif args.command == "stats":
        await tool.db_stats()

    await tool.client.disconnect()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user. Goodbye![/]")
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/]")
        logger.exception("Unhandled exception")
```
