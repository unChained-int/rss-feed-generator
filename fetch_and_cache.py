#!/usr/bin/env python3
# fetch_and_cache.py
# Aggregates RSS feeds and scrapes additional sources for top Security + Policy news

import feedparser, time, os, math, requests
from feedgen.feed import FeedGenerator
from datetime import datetime, timezone, timedelta
from dateutil import parser as dateparser
import logging
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(__file__)
CACHE_FILE = os.path.join(BASE_DIR, "cached_feed.xml")
TMP_FILE = os.path.join(BASE_DIR, "cached_feed.tmp")
LOG_FILE = os.path.join(BASE_DIR, "feed_log.txt")

BEST_N = 50
SLEEP_BETWEEN = 1.5
USER_AGENT = "Mozilla/5.0 (SecurityFeedAggregator/1.0; +https://github.com/unChained-int/rss-feed-generator)"

GENERAL_FEEDS = [
    "https://krebsonsecurity.com/feed",
    "https://nakedsecurity.sophos.com/feed", 
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.darkreading.com/rss_simple.asp",
    "http://feeds.feedburner.com/Securityweek",
    "https://www.bleepingcomputer.com/feed/",
    "https://threatpost.com/feed/",
    "https://www.infosecurity-magazine.com/rss/news/",
    "https://www.scmagazine.com/news/feed",
    "https://cyware.com/allnews/feed",
    "https://www.csoonline.com/news/index.rss",
    "https://www.cybersecuritydive.com/feeds/news/",
    "https://feeds.feedburner.com/eset/blog",
    "https://blog.malwarebytes.com/feed/",
    # Webscraping-Quellen werden gesondert behandelt
]

POLICY_FEEDS = [
    "https://www.cisa.gov/sites/default/files/rss.xml",
    "https://www.bsi.bund.de/SharedDocs/RSS/DE/0_RSSFeed.xml",
    "https://www.enisa.europa.eu/news/enisa-news/feed", 
    "https://ccdcoe.org/news/feed/",
    "https://www.nist.gov/news-events/cybersecurity/rss.xml",
    "https://www.sans.org/reading-room/rss",
    "https://www.europol.europa.eu/rss",
    "https://ec.europa.eu/newsroom/dae/rss.cfm",
]

POLICY_KEYWORDS = [
    "nis2", "cyber resilience", "cyber resilience act", "regulation", "directive",
    "policy", "strategy", "critical infrastructure", "sanction", "export control",
    "gdpr", "dora", "digital operational resilience", "cybersecurity act",
    "essential services", "important entities", "incident reporting",
    "supply chain", "third party risk", "cyber threat intelligence",
    "national cybersecurity strategy", "cyber diplomacy", "attribution"
]

SOURCE_PRIORITY = {
    "cisa.gov": 6.0,
    "bsi.bund.de": 5.5,
    "enisa.europa.eu": 5.0,
    "ccdcoe.org": 4.5,
    "nist.gov": 4.0,
    "europol.europa.eu": 4.0,
    "ec.europa.eu": 3.5,
    "krebsonsecurity.com": 3.0,
    "darkreading.com": 2.5,
    "bleepingcomputer.com": 2.5,
    "thehackernews.com": 2.0,
    "securityweek.com": 2.0,
    "threatpost.com": 2.0,
    "infosecurity-magazine.com": 2.0,
    "scmagazine.com": 2.0,
    "nakedsecurity.sophos.com": 1.8,
    "sans.org": 3.0,
    "heise.de": 2.8
}

# Logging Setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def log_message(message):
    """Log message to file and console"""
    logger.info(message)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat()} - {message}\n")
    except Exception as e:
        logger.error(f"Failed to write to log file: {e}")

def domain(url):
    try:
        return urlparse(url).netloc.lower()
    except:
        return ""

def parse_date(entry):
    date_fields = ["published", "updated", "created", "pubDate", "dc:date"]
    for field in date_fields:
        if field in entry:
            try:
                parsed_date = dateparser.parse(entry.get(field))
                if parsed_date:
                    if parsed_date.tzinfo is None:
                        parsed_date = parsed_date.replace(tzinfo=timezone.utc)
                    return parsed_date
            except Exception as e:
                logger.debug(f"Failed to parse date from {field}: {e}")
                continue
    if hasattr(entry, "published_parsed") and entry.published_parsed:
        try:
            import time
            timestamp = time.mktime(entry.published_parsed)
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)
        except:
            pass
    import random
    hours_ago = random.randint(1, 48)
    return datetime.now(timezone.utc) - timedelta(hours=hours_ago)

def is_policy(entry, feed_url):
    d = domain(feed_url)
    policy_domains = [
        "cisa.gov", "bsi.bund.de", "ccdcoe.org", "enisa.europa.eu", 
        "europa.eu", "nist.gov", "europol.europa.eu", "ec.europa.eu",
        "sans.org"
    ]
    if any(pd in d for pd in policy_domains):
        return True
    text = f"{entry.get('title', '')} {entry.get('summary', '')} {entry.get('description', '')}".lower()
    return any(keyword in text for keyword in POLICY_KEYWORDS)

def score_entry(entry, feed_url):
    base_score = SOURCE_PRIORITY.get(domain(feed_url), 1.0)
    dt = parse_date(entry)
    if dt:
        age_hours = (datetime.now(timezone.utc) - dt).total_seconds() / 3600.0
        freshness_score = math.exp(-age_hours / 96.0) * 4.0
        base_score += freshness_score
    summary_length = len((entry.get("summary", "") or entry.get("description", "")).split())
    length_score = min(summary_length, 200) / 100.0
    base_score += length_score
    if is_policy(entry, feed_url):
        base_score += 2.0
    title = entry.get("title", "").lower()
    if any(word in title for word in ["breaking", "alert", "urgent", "critical", "zero-day", "breach"]):
        base_score += 1.0
    return base_score

def scrape_heise_security(max_items=10):
    """
    Scrapes the latest news from https://www.heise.de/security/, returns RSS-like entries.
    """
    from bs4 import BeautifulSoup
    url = "https://www.heise.de/security/"
    headers = {"User-Agent": USER_AGENT}
    try:
        log_message("Scraping Heise Security news...")
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.content, "html.parser")
        articles = soup.select("main section[data-ct-area='Teaser'] article")[:max_items]
        entries = []
        for a in articles:
            title_elem = a.find("a", class_="a-strong")
            title = title_elem.get_text(strip=True) if title_elem else "No title"
            link = f"https://www.heise.de{title_elem['href']}" if title_elem and title_elem.has_attr("href") else url
            desc_elem = a.find("p")
            summary = desc_elem.get_text(strip=True) if desc_elem else ""
            pub_elem = a.find("time")
            pub_date = pub_elem["datetime"] if pub_elem and pub_elem.has_attr("datetime") else None
            entry = {
                "title": title,
                "link": link,
                "summary": summary,
                "published": pub_date
            }
            entries.append(("https://www.heise.de/security/", entry))
        log_message(f"Scraped {len(entries)} Heise Security articles.")
        return entries
    except Exception as e:
        log_message(f"Failed to scrape Heise Security: {e}")
        return []

def collect_all():
    """Collect all entries from all feeds and scrapers"""
    entries = []
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/rss+xml, application/xml, text/xml, */*",
        "Accept-Encoding": "gzip, deflate",
    }
    all_feeds = POLICY_FEEDS + GENERAL_FEEDS
    log_message(f"Starting collection from {len(all_feeds)} feeds")
    # RSS/Atom Feeds
    for i, url in enumerate(all_feeds, 1):
        log_message(f"Processing feed {i}/{len(all_feeds)}: {url}")
        try:
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            feed = feedparser.parse(response.content)
            if feed.bozo:
                log_message(f"Warning: Feed {url} has parsing issues: {feed.bozo_exception}")
            if not feed.entries:
                log_message(f"Warning: No entries found in feed {url}")
                continue
            log_message(f"Successfully parsed {len(feed.entries)} entries from {url}")
            for entry in feed.entries:
                if entry.get("title") or entry.get("link"):
                    entries.append((url, entry))
        except requests.exceptions.Timeout:
            log_message(f"Timeout error for {url}")
        except requests.exceptions.RequestException as e:
            log_message(f"Request error for {url}: {e}")
        except Exception as e:
            log_message(f"Unexpected error parsing {url}: {e}")
        time.sleep(SLEEP_BETWEEN)
    # Webscraping sources
    entries.extend(scrape_heise_security())
    log_message(f"Total entries collected: {len(entries)}")
    return entries

def build_and_write(entries):
    if not entries:
        log_message("No entries to process!")
        return
    scored = [(score_entry(entry, url), url, entry) for url, entry in entries]
    scored.sort(key=lambda x: x[0], reverse=True)
    selected = scored[:BEST_N]
    log_message(f"Selected top {len(selected)} entries from {len(scored)} total")
    fg = FeedGenerator()
    fg.title("Security + Policy News Aggregator")
    fg.link(href="https://github.com/unChained-int/rss-feed-generator", rel="alternate")
    fg.link(href="https://github.com/unChained-int/rss-feed-generator/releases/latest/download/cached_feed.xml", rel="self")
    fg.description("Curated Security and Cybersecurity Policy news from trusted sources")
    fg.author({"name": "Security Feed Aggregator", "email": "noreply@users.noreply.github.com"})
    fg.language("en")
    fg.lastBuildDate(datetime.now(timezone.utc))
    fg.generator("Python Security Feed Aggregator")
    for score, feed_url, entry in selected:
        try:
            fe = fg.add_entry()
            title = entry.get("title", "(No title)")
            fe.title(title)
            link = entry.get("link", entry.get("id", ""))
            if link:
                fe.link(href=link)
                fe.guid(link)
            else:
                import hashlib
                unique_id = hashlib.md5(f"{feed_url}{title}{entry.get('summary', '')}".encode()).hexdigest()
                fe.guid(f"urn:uuid:{unique_id}")
            description = entry.get("summary", "") or entry.get("description", "") or "No description available"
            fe.description(description)
            pub_date = parse_date(entry)
            fe.pubDate(pub_date)
            if is_policy(entry, feed_url):
                fe.category(term="policy", label="Cybersecurity Policy")
            fe.category(term="security", label="Cybersecurity")
            source_domain = domain(feed_url)
            fe.author({"name": source_domain})
            fe.comments(f"Score: {score:.2f}")
        except Exception as e:
            log_message(f"Error adding entry '{entry.get('title', 'Unknown')}': {e}")
            continue
    try:
        xml_content = fg.rss_str(pretty=True)
        with open(TMP_FILE, "wb") as f:
            f.write(xml_content)
        os.replace(TMP_FILE, CACHE_FILE)
        log_message(f"Successfully wrote RSS feed to {CACHE_FILE}")
        log_message(f"Feed contains {len(selected)} entries")
    except Exception as e:
        log_message(f"Error writing feed file: {e}")
        raise

def cleanup_old_logs():
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                lines = f.readlines()
            if len(lines) > 100:
                with open(LOG_FILE, "w", encoding="utf-8") as f:
                    f.writelines(lines[-100:])
    except Exception as e:
        logger.error(f"Error cleaning up logs: {e}")

if __name__ == "__main__":
    try:
        log_message("=== Starting RSS Feed Aggregation ===")
        cleanup_old_logs()
        all_entries = collect_all()
        if all_entries:
            build_and_write(all_entries)
            log_message("=== RSS Feed Aggregation Completed Successfully ===")
        else:
            log_message("=== No entries collected, RSS aggregation failed ===")
    except Exception as e:
        log_message(f"=== RSS Feed Aggregation Failed: {e} ===")
        raise
