"""
Shared IOC extraction + triage logic, used by process_mail.py.
"""

import csv
import io
import ipaddress
import os
import re
import email.utils
import hashlib
import unicodedata
from datetime import date, timezone
from email.header import decode_header
from html.parser import HTMLParser
from urllib.parse import urlparse

# Optional image-analysis dependencies. Everything degrades gracefully:
# without Pillow/imagehash there's no perceptual hashing, without
# pytesseract (plus the Tesseract binary) there's no OCR -- but byte-level
# image hashing and everything else still works.
try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
try:
    import imagehash
    HAS_IMAGEHASH = HAS_PIL
except ImportError:
    HAS_IMAGEHASH = False
try:
    import pytesseract
    HAS_TESSERACT = HAS_PIL
except ImportError:
    HAS_TESSERACT = False

BASE = os.path.dirname(os.path.abspath(__file__))

URL_RE = re.compile(r'https?://[^\s"\'<>\)\]]+', re.IGNORECASE)

# Phone extraction is two-stage: a loose candidate matcher (digits with
# reasonable separators, 9-13 digits total -- covers international formats
# like "+256 743324632" as well as ragged spacing like "+ 1 (656) 556 - 2194"),
# then a confidence filter (see extract_phones below) to reject bare digit
# runs that are actually tracking/reference/order numbers, not phone numbers.
PHONE_CANDIDATE_RE = re.compile(r'(?:\+?\d[\d\s\-\.\(\)]{7,18}\d)')
PHONE_KEYWORD_RE = re.compile(r'(call|phone|tel\b|dial|contact|hotline|support)', re.I)


def extract_phones(text):
    """Return deduped, plausible phone numbers from text. A bare digit run
    (no spacing) only counts if a phone-related keyword appears just before
    it -- otherwise it's more likely an order/tracking/reference number."""
    results = []
    for m in PHONE_CANDIDATE_RE.finditer(text):
        raw = m.group(0)
        digits = re.sub(r'\D', '', raw)
        if not (9 <= len(digits) <= 13):
            continue
        separators = len(re.findall(r'[\s\-.()]', raw))
        context = text[max(0, m.start() - 25):m.start()]
        has_keyword = bool(PHONE_KEYWORD_RE.search(context))
        if separators >= 2 or has_keyword:
            results.append(re.sub(r'\s+', ' ', raw.strip()))
    return list(dict.fromkeys(results))

BTC_RE = re.compile(r'\b(bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b')
ETH_RE = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

# Your own addresses -- these show up constantly in body text (salutations,
# "Dear you@example.com...", etc.) and aren't attacker IOCs. Kept in a
# gitignored file (data/self_addresses.txt, one address per line, '#'
# comments allowed) rather than hardcoded here, since this is a personal
# source file that gets committed to git -- see data/self_addresses_example.txt
# for the format.
SELF_ADDRESSES_PATH = os.path.join(BASE, "data", "self_addresses.txt")


def _load_self_addresses():
    if not os.path.exists(SELF_ADDRESSES_PATH):
        return set()
    with open(SELF_ADDRESSES_PATH, encoding="utf-8") as f:
        return {
            line.strip().lower() for line in f
            if line.strip() and not line.strip().startswith("#")
        }


SELF_ADDRESSES = _load_self_addresses()

# Real third-party service domains whose support/no-reply addresses show up
# inside spam bodies -- usually because a chunk of a genuine account-signup
# confirmation email (Fastly, Podio, Calendly, etc.) got pasted wholesale
# into the spam as camouflage/deliverability padding. These are never the
# scammer's own contact point, so they're excluded outright rather than run
# through the functional/filler heuristic. Extend as you spot more.
KNOWN_SERVICE_DOMAINS = {
    "fastly.com", "podio.com", "calendly.com", "google.com", "microsoft.com",
    "apple.com", "amazon.com", "paypal.com", "shopify.com", "shopifyemail.com",
    "parsec.app", "ibm.com", "zoom.us", "stripe.com", "mailchimp.com",
    "sendgrid.net", "twitter.com", "x.com", "facebook.com", "linkedin.com",
}

# Domains we consider legitimate bulk mail / not phishing, even if unwanted.
# Extend this list over time as you see more of your own "annoying but not
# a scam" senders (Substack authors, gov agencies, etc.)
KNOWN_LEGIT_DOMAINS = {
    "substack.com", "calendly.com", "usajobs.gov", "google.com",
    "accounts.google.com", "mail.google.com", "linkedin.com",
    "fastly.com", "podio.com",
}

# --- Flexible keyword matching ------------------------------------------
# Keyword phrases used to be matched as exact substrings, which missed
# variants like "verify your Amazon account" (extra word) or punctuation
# differences. Instead, each phrase is compiled to a regex that tokenizes
# on non-alphanumerics and allows a small gap of extra words between
# tokens: "verify your account" also matches "verify your Amazon account".
def _phrase_regex(phrase, max_gap_words=2):
    tokens = re.findall(r'[a-z0-9]+', phrase.lower())
    if not tokens:
        return None
    gap = r'(?:\W+\w+){0,%d}?\W+' % max_gap_words
    return r'\b' + gap.join(re.escape(t) for t in tokens) + r'\b'


def _compile_phrases(phrases, max_gap_words=2):
    parts = [p for p in (_phrase_regex(kw, max_gap_words) for kw in phrases) if p]
    return re.compile("|".join(parts), re.IGNORECASE)


URGENT_KEYWORDS = [
    # English
    "act now", "urgent", "verify your account", "suspended", "final notice",
    "wire transfer", "gift card", "bitcoin", "crypto wallet", "inheritance",
    "next of kin", "congratulations you have won", "claim your prize",
    "social security number", "confirm your identity", "unusual activity",
    "account has been locked", "account locked", "response required",
    "overdue", "irreversible", "last warning", "action needed",
    "critical alert", "will be erased", "will be wiped", "will be deleted",
    "charged your bank", "call now",
    # Fake prize / sweepstakes claims
    "you have won", "you've won", "you are our", "claim your free",
    "claim your exclusive", "confirmed: you have won", "welcome free spins",
    "free spins", "no deposit needed", "congratulations, ", "3rd winner",
    "reward is ready", "ready to claim",
    # Fake account/storage/security warnings (broader than the original set)
    "storage is full", "deletion will start", "secure your data",
    "cloud is full", "account has been blocked", "will be removed",
    "payment failed", "attempt 3 of 3", "2nd attempt", "account will be closed",
    "your account will be closed",
    # Unauthorized pharma/medical marketing (near-universally scam/unlicensed
    # when sent unsolicited from disposable domains)
    "glp-1", "lose weight effortlessly", "lose up to", "doctor reveals",
    # Portuguese (common Brazilian phishing: fake DETRAN/Correios notices)
    "suspensão", "suspensao", "bloqueio", "regularize", "regularizar",
    "pendência", "pendencia", "protocolo", "notificação oficial",
    "notificacao oficial", "infração", "infracao", "multa", "alfândega",
    "alfandega", "devolução", "devolucao", "ação necessária", "acao necessaria",
    # Spanish (common equivalents)
    "suspensión", "suspension", "urgente", "acción requerida",
    "accion requerida", "última oportunidad", "ultima oportunidad",
]

URGENT_RE = _compile_phrases(URGENT_KEYWORDS)

# Brands/institutions commonly impersonated in the sample data. This is a
# subcategory on top of triage's likely_scam/review/bulk_marketing -- e.g.
# "likely_scam, impersonating Aflac and AARP". Keyword-based like the lists
# above, so expect to keep tuning it (and watch for over-broad keywords like
# a bare company name colliding with unrelated mentions).
IMPERSONATED_BRANDS = {
    "Aflac": ["aflac"],
    "AARP": ["aarp"],
    "Medicare": ["medicare"],
    "Social Security Administration": ["social security administration", "ssa.gov"],
    "IRS": ["internal revenue service", " irs ", "irs.gov"],
    "USPS": ["usps", "united states postal service", "u.s. postal service"],
    "FedEx": ["fedex"],
    "UPS": ["ups.com", "united parcel service"],
    "Amazon": ["amazon.com", "your amazon", "amazon order", "amazon account"],
    "Netflix": ["netflix"],
    "PayPal": ["paypal"],
    "Apple": ["apple id", "icloud storage", "your apple account"],
    "Microsoft": ["microsoft account", "office 365", "windows defender"],
    "Norton": ["norton antivirus", "norton security", "norton renewal"],
    "McAfee": ["mcafee"],
    "Geek Squad": ["geek squad"],
    "DocuSign": ["docusign"],
    "Coinbase": ["coinbase"],
    "Bank of America": ["bank of america"],
    "Wells Fargo": ["wells fargo"],
    "Chase": ["chase bank", "jpmorgan chase"],
}

# Official root domains per brand, used by the display-name-mismatch signal:
# a From name of "PayPal" sent from anything but paypal.com is one of the
# most reliable phishing markers there is, and needs no keyword in the body.
BRAND_LEGIT_DOMAINS = {
    "Aflac": {"aflac.com"},
    "AARP": {"aarp.org"},
    "Medicare": {"medicare.gov", "cms.gov"},
    "Social Security Administration": {"ssa.gov"},
    "IRS": {"irs.gov"},
    "USPS": {"usps.com", "usps.gov"},
    "FedEx": {"fedex.com"},
    "UPS": {"ups.com"},
    "Amazon": {"amazon.com"},
    "Netflix": {"netflix.com"},
    "PayPal": {"paypal.com"},
    "Apple": {"apple.com", "icloud.com"},
    "Microsoft": {"microsoft.com", "outlook.com", "live.com"},
    "Norton": {"norton.com", "nortonlifelock.com", "gendigital.com"},
    "McAfee": {"mcafee.com"},
    "Geek Squad": {"bestbuy.com", "geeksquad.com"},
    "DocuSign": {"docusign.com", "docusign.net"},
    "Coinbase": {"coinbase.com"},
    "Bank of America": {"bankofamerica.com", "bofa.com"},
    "Wells Fargo": {"wellsfargo.com"},
    "Chase": {"chase.com", "jpmorganchase.com", "jpmchase.com"},
}

# Brand names that are common English words / too short to match against a
# display name bare (e.g. "UPS" would hit "SIGN UPS"). For display-name
# matching these use the full keyword regexes instead of the brand name.
_BRAND_NAME_RES = {
    brand: _compile_phrases([brand] if len(brand) > 3 else keywords, max_gap_words=0)
    for brand, keywords in IMPERSONATED_BRANDS.items()
}
_BRAND_KEYWORD_RES = {
    brand: _compile_phrases(keywords) for brand, keywords in IMPERSONATED_BRANDS.items()
}


def detect_brands(subject, body, from_name=""):
    """Return the sorted list of brands/institutions this email appears to
    be impersonating, based on keyword hits in the display name, subject,
    and body."""
    text = f" {from_name}\n{subject}\n{body} "
    return sorted(
        brand for brand, kw_re in _BRAND_KEYWORD_RES.items()
        if kw_re.search(text)
    )


def brands_in_display_name(from_name):
    """Brands whose name appears in the From display name itself."""
    if not from_name:
        return []
    return sorted(b for b, name_re in _BRAND_NAME_RES.items() if name_re.search(from_name))


# --- Deobfuscating hidden contact info ---------------------------------
# Spam bodies sometimes hide a real contact address from naive scanners:
# invisible zero-width characters spliced into words, Cyrillic/Greek
# letters that look identical to Latin ones, or spelling out "(at)"/"(dot)"
# instead of using @ and . directly. Undoing these before running
# EMAIL_RE/PHONE_CANDIDATE_RE surfaces contacts that would otherwise be
# missed entirely.
# zero-width space, non-joiner, joiner, BOM, soft hyphen
_ZERO_WIDTH_CHARS = "".join(chr(c) for c in (0x200B, 0x200C, 0x200D, 0xFEFF, 0x00AD))
ZERO_WIDTH_RE = re.compile("[" + _ZERO_WIDTH_CHARS + "]")

# A handful of Cyrillic/Greek letters commonly used to visually impersonate
# Latin ones -- not an exhaustive confusables table, just what shows up in
# practice.
HOMOGLYPH_MAP = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X",
})

OBFUSCATED_EMAIL_RE = re.compile(
    r'([a-zA-Z0-9._%+-]+)\s*[\(\[]?\s*at\s*[\)\]]?\s*'
    r'([a-zA-Z0-9.-]+)\s*[\(\[]?\s*dot\s*[\)\]]?\s*([a-zA-Z]{2,})',
    re.IGNORECASE,
)


def deobfuscate(text):
    """Undo the cheap obfuscation tricks described above so downstream
    extraction sees plain @ addresses. NFKC normalization additionally
    folds fullwidth/stylized Unicode letters (ｕｒｇｅｎｔ, 𝐮𝐫𝐠𝐞𝐧𝐭, etc.)
    back to plain ASCII -- a much wider net than the homoglyph map alone."""
    text = unicodedata.normalize("NFKC", text)
    text = ZERO_WIDTH_RE.sub('', text)
    text = text.translate(HOMOGLYPH_MAP)
    text = OBFUSCATED_EMAIL_RE.sub(lambda m: f"{m.group(1)}@{m.group(2)}.{m.group(3)}", text)
    return text


# --- Body template fingerprinting (for cross-campaign clustering) ------
# Scammers reuse the same template body across many messages with
# different senders/contact info per blast. To detect that similarity
# later (see build_master_report.py's template-cluster tab) without
# storing the actual body text anywhere, each message gets a small SimHash
# fingerprint computed over the body with the parts that vary (URLs,
# emails, phones, wallet addresses) stripped out first. Two fingerprints
# with a small Hamming distance likely came from the same template.
def _shingles(text, k=4):
    words = re.findall(r'[a-z0-9]+', text.lower())
    if len(words) < k:
        return {' '.join(words)} if words else set()
    return {' '.join(words[i:i + k]) for i in range(len(words) - k + 1)}


def _simhash(shingles, bits=64):
    if not shingles:
        return 0
    v = [0] * bits
    for sh in shingles:
        h = int(hashlib.md5(sh.encode("utf-8")).hexdigest(), 16)
        for i in range(bits):
            v[i] += 1 if (h >> i) & 1 else -1
    fingerprint = 0
    for i in range(bits):
        if v[i] > 0:
            fingerprint |= (1 << i)
    return fingerprint


def body_template_fingerprint(body):
    """64-bit SimHash (as a 16-char hex string) of the body with URLs,
    emails, phone-candidates, and wallet addresses stripped out."""
    stripped = body
    for pattern in (URL_RE, EMAIL_RE, PHONE_CANDIDATE_RE, BTC_RE, ETH_RE):
        stripped = pattern.sub(" ", stripped)
    return format(_simhash(_shingles(stripped)), "016x")


def decode_mime_header(value):
    if not value:
        return ""
    try:
        parts = decode_header(value)
        decoded = ""
        for text, enc in parts:
            if isinstance(text, bytes):
                decoded += text.decode(enc or "utf-8", errors="replace")
            else:
                decoded += text
        return decoded.replace("\n", " ").replace("\r", "").strip()
    except Exception:
        return str(value)


# --- HTML body parsing ---------------------------------------------------
# HTML used to be flattened with a bare tag-stripping regex, which (a) never
# decoded entities, so "Verif&#121; your account" dodged every keyword,
# (b) threw away <a href=...> URLs entirely -- HTML-only spam contributed no
# URLs unless one appeared in visible text, (c) kept display:none word-salad
# blocks that poison keyword matching and the SimHash, and (d) lost the
# anchor-text-vs-href mismatch evidence (<a href="evil.top">paypal.com</a>),
# a top-tier phishing signal. This parser fixes all four. html.parser
# decodes entities for free (convert_charrefs=True by default).
_HIDDEN_STYLE_RE = re.compile(
    r'display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em|rem|;|\s|$)|'
    r'opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)', re.I)
_DOMAINISH_RE = re.compile(r'\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b', re.I)
_VOID_TAGS = {"br", "img", "hr", "input", "meta", "link", "area", "base", "col",
              "embed", "source", "track", "wbr"}


class _HTMLBodyParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.chunks = []           # visible text
        self.img_srcs = []         # every <img src=...>
        self.hrefs = []            # every <a href=...>
        self.link_mismatches = []  # "shown-domain => real-href-domain"
        self._skip_stack = []      # open script/style/hidden elements
        self._anchor_href = None
        self._anchor_text = []

    def handle_starttag(self, tag, attrs):
        if tag in _VOID_TAGS:
            if tag == "img":
                src = dict(attrs).get("src") or ""
                if src:
                    self.img_srcs.append(src.strip())
            elif tag == "br":
                self.chunks.append("\n")
            return
        style = dict(attrs).get("style") or ""
        if tag in ("script", "style") or _HIDDEN_STYLE_RE.search(style):
            self._skip_stack.append(tag)
            return
        if tag == "a":
            href = (dict(attrs).get("href") or "").strip()
            if href and not href.lower().startswith(("mailto:", "javascript:", "tel:")):
                self.hrefs.append(href)
            self._anchor_href = href
            self._anchor_text = []
        elif tag in ("p", "div", "tr", "li", "table", "h1", "h2", "h3", "h4"):
            self.chunks.append("\n")

    def handle_endtag(self, tag):
        if self._skip_stack and self._skip_stack[-1] == tag:
            self._skip_stack.pop()
            return
        if tag == "a" and self._anchor_href is not None:
            self._check_anchor_mismatch()
            self._anchor_href = None
            self._anchor_text = []

    def _check_anchor_mismatch(self):
        """Flag anchors whose *visible* text looks like a URL/domain that
        doesn't match where the href actually points."""
        text = " ".join(self._anchor_text).strip()
        href_domain = domain_of(self._anchor_href)
        if not text or not href_domain:
            return
        m = _DOMAINISH_RE.search(text)
        if not m:
            return
        shown = m.group(1).lower()
        shown_root = ".".join(shown.split(".")[-2:])
        href_root = ".".join(href_domain.split(":")[0].split(".")[-2:])
        if shown_root != href_root:
            self.link_mismatches.append(f"{shown} => {href_domain}")

    def handle_data(self, data):
        if self._skip_stack:
            return
        if self._anchor_href is not None:
            self._anchor_text.append(data)
        self.chunks.append(data)


def html_to_evidence(html_text):
    """Parse an HTML body into (visible_text, hrefs, img_srcs, mismatches)."""
    parser = _HTMLBodyParser()
    try:
        parser.feed(html_text)
        parser.close()
    except Exception:
        # malformed HTML: fall back to the old tag-stripping behavior
        import html as html_mod
        return html_mod.unescape(re.sub(r"<[^>]+>", " ", html_text)), [], [], []
    return ("".join(parser.chunks), parser.hrefs, parser.img_srcs,
            parser.link_mismatches)


def get_body_text(msg):
    """Return (text, hrefs, img_srcs, link_mismatches) for a message: plain
    text plus the flattened visible text of any HTML parts, and the link/
    image evidence recovered from the HTML."""
    text_parts, html_parts = [], []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "")
            if "attachment" in disp:
                continue
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                payload = None
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            try:
                decoded = payload.decode(charset, errors="replace")
            except Exception:
                decoded = payload.decode("utf-8", errors="replace")
            if ctype == "text/plain":
                text_parts.append(decoded)
            elif ctype == "text/html":
                html_parts.append(decoded)
    else:
        try:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or "utf-8"
            decoded = payload.decode(charset, errors="replace") if payload else ""
        except Exception:
            decoded = str(msg.get_payload())
        if msg.get_content_type() == "text/html":
            html_parts.append(decoded)
        else:
            text_parts.append(decoded)

    combined = "\n".join(text_parts)
    hrefs, img_srcs, mismatches = [], [], []
    for html_text in html_parts:
        text, h, srcs, mm = html_to_evidence(html_text)
        combined += "\n" + text
        hrefs += h
        img_srcs += srcs
        mismatches += mm
    return combined, hrefs, img_srcs, mismatches


def extract_ips(received_headers):
    """Public IPs from the Received chain, in header order (first = the hop
    closest to you, last = closest to the true origin). Candidates are
    validated with ipaddress -- the bare regex also matches version strings
    like '15.21.270.5' -- and private/reserved relay hops are dropped.

    IPs are only extracted when bracket/paren-delimited ("from x ([1.2.3.4])",
    "(1.2.3.4)"), which is how every real connecting-client IP appears in a
    Received header. This deliberately excludes bare dotted-quad tokens
    elsewhere in the header text -- most importantly Microsoft Exchange's
    "with Microsoft SMTP Server (...) id 15.21.245.11" build/version stamp,
    which is not an IP at all but happens to fall in a real, globally-routable
    /8 (historically HP's) and so would otherwise pass validation and get
    mistaken for a shared-infrastructure signal across unrelated messages."""
    ip_re = re.compile(r'[\[\(](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\]\)]')
    ips = []
    for h in received_headers:
        for m in ip_re.finditer(h):
            ip = m.group(1)
            if ip in ips:
                continue
            try:
                if ipaddress.ip_address(ip).is_global:
                    ips.append(ip)
            except ValueError:
                continue
    return ips


def domain_of(url):
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def parse_auth_results(auth_header):
    """Capture the full result token, not just pass/fail -- softfail, none,
    neutral, permerror, temperror all carry signal (or its absence)."""
    if not auth_header:
        return "", "", ""

    def result_of(mech):
        m = re.search(mech + r'=(\w+)', auth_header, re.I)
        return m.group(1).lower() if m else ""

    return result_of("dkim"), result_of("spf"), result_of("dmarc")


def msg_id_hash(msg):
    """Dedup id. Messages with no Message-ID (not rare in spam) fall back to
    hashing Date+From+Subject -- previously they all hashed to the same id,
    so every Message-ID-less email after the first was silently dropped as
    a 'duplicate'."""
    mid = (msg.get("Message-ID", "") or "").strip()
    if not mid:
        mid = "\x00".join(str(msg.get(h, "") or "") for h in ("Date", "From", "Subject"))
    return hashlib.sha1(mid.encode("utf-8", errors="replace")).hexdigest()[:10]


# Freemail providers: a Reply-To at one of these while From claims some
# other domain is a classic advance-fee/BEC pattern (the From is spoofed
# or a burner; the freemail inbox is the part the scammer actually reads).
FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "msn.com", "yahoo.com", "ymail.com", "aol.com", "proton.me",
    "protonmail.com", "icloud.com", "me.com", "mail.com", "gmx.com",
    "gmx.net", "yandex.com", "yandex.ru", "zoho.com", "mail.ru",
}

# Common URL shorteners/redirectors -- these hide the real destination, so
# their presence in spam is worth flagging (and the shortened link is what
# you'd report to the shortener's abuse desk).
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy",
    "rebrand.ly", "ow.ly", "buff.ly", "shorturl.at", "t.ly", "s.id",
    "tiny.cc", "lnkd.in", "qrco.de",
}

# WHOIS enrichment (data/domain_enrichment.csv, built by lookup_domains.py)
# doubles as a triage signal: a sender domain registered days/weeks ago is
# near-conclusive on its own. Loaded once at import, keyed by domain.
ENRICHMENT_PATH = os.path.join(BASE, "data", "domain_enrichment.csv")
_DATE_IN_STRING_RE = re.compile(r'(\d{4})-(\d{2})-(\d{2})')


def _load_domain_ages():
    ages = {}
    if not os.path.exists(ENRICHMENT_PATH):
        return ages
    try:
        with open(ENRICHMENT_PATH, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                m = _DATE_IN_STRING_RE.search(r.get("registered_date") or "")
                if m:
                    try:
                        reg = date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
                        ages[(r.get("domain") or "").lower()] = (date.today() - reg).days
                    except ValueError:
                        pass
    except Exception:
        pass
    return ages


DOMAIN_AGE_DAYS = _load_domain_ages()


def url_flags(urls):
    """Suspicious-URL markers: punycode (IDN homoglyph) domains and known
    URL shorteners."""
    flags = []
    for u in urls:
        dom = domain_of(u)
        root = ".".join(dom.split(".")[-2:]) if dom else ""
        if "xn--" in dom:
            flags.append(f"punycode:{dom}")
        if root in SHORTENER_DOMAINS or dom in SHORTENER_DOMAINS:
            flags.append(f"shortener:{dom}")
    return sorted(set(flags))


def triage(signals):
    """Weighted rule-based triage -- still no LLM/API calls. Takes a dict of
    extracted signals, returns (category, score, reasons). Each reason is a
    human-readable 'why', kept in the CSV so scores can be audited/tuned.

    Rough calibration: one strong signal (urgent keywords, brand display-name
    mismatch, brand-new domain) is enough for likely_scam on its own;
    weaker signals (auth failures, freemail reply-to, shorteners) need to
    stack up. A List-Unsubscribe header no longer vetoes anything -- scams
    add fake ones -- it only classifies otherwise-signal-free mail as
    bulk_marketing."""
    score = 0
    reasons = []

    from_domain = signals.get("from_domain", "")
    root_domain = ".".join(from_domain.split(".")[-2:]) if from_domain else ""
    if root_domain in KNOWN_LEGIT_DOMAINS or from_domain in KNOWN_LEGIT_DOMAINS:
        return "bulk_marketing", 0, ["known legit domain"]

    m = URGENT_RE.search(signals.get("text", ""))
    if m:
        score += 3
        reasons.append(f"urgent keyword: {m.group(0)[:40]!r}")

    # Brand in the From display name but sent from a non-official domain
    for brand in signals.get("display_name_brands", []):
        legit = BRAND_LEGIT_DOMAINS.get(brand, set())
        if root_domain and root_domain not in legit and from_domain not in legit:
            score += 3
            reasons.append(f"display name claims {brand}, sent from {from_domain}")
            break

    reply_domain = signals.get("reply_to_domain", "")
    reply_root = ".".join(reply_domain.split(".")[-2:]) if reply_domain else ""
    if reply_root and root_domain and reply_root != root_domain:
        if reply_root in FREEMAIL_DOMAINS:
            score += 2
            reasons.append(f"reply-to diverted to freemail ({reply_domain})")
        else:
            score += 1
            reasons.append(f"reply-to domain ({reply_domain}) != from domain")

    dkim, spf, dmarc = signals.get("dkim", ""), signals.get("spf", ""), signals.get("dmarc", "")
    if dmarc == "fail":
        score += 2
        reasons.append("dmarc=fail")
    if spf in ("fail", "softfail"):
        score += 1
        reasons.append(f"spf={spf}")
    if dkim == "fail":
        score += 1
        reasons.append("dkim=fail")

    age = DOMAIN_AGE_DAYS.get(from_domain) or DOMAIN_AGE_DAYS.get(root_domain)
    if age is not None:
        if age < 90:
            score += 3
            reasons.append(f"sender domain registered {age} days ago")
        elif age < 365:
            score += 1
            reasons.append(f"sender domain registered {age} days ago")

    if from_domain.endswith(".edu") or ".edu." in from_domain or ".ac." in from_domain:
        score += 2
        reasons.append("unsolicited mail from academic domain (often compromised)")

    n_mismatch = len(signals.get("link_mismatches", []))
    if n_mismatch:
        score += 2
        reasons.append(f"{n_mismatch} link(s) whose visible text hides the real destination")

    if signals.get("has_wallet"):
        score += 1
        reasons.append("crypto wallet address in body")

    flags = signals.get("url_flags", [])
    if any(f.startswith("punycode:") for f in flags):
        score += 2
        reasons.append("punycode (IDN look-alike) domain in URL")
    elif flags:
        score += 1
        reasons.append("URL shortener hides destination")

    if score >= 3:
        return "likely_scam", score, reasons
    if score == 0 and signals.get("has_list_unsubscribe"):
        return "bulk_marketing", score, reasons
    return "review", score, reasons


# --- Functional vs. filler classification -----------------------------
# Spam bodies often stuff a block of unrelated-looking emails/phone numbers/
# names into the text purely to confuse spam-filter word-frequency scoring
# ("word salad" / Bayesian poisoning) -- these aren't real contact points,
# just noise. A genuine reused contact point (worth reporting) usually has
# either (a) explicit call-to-action language near it ("contact us at...",
# "book a call", "reply to"), or (b) stands alone rather than sitting in a
# dense cluster of other PII-looking tokens.
CONTACT_CONTEXT_RE = re.compile(
    r'(contact|reply to|email us|write to|book|schedule|questions|support|'
    r'reach us|for more info|inquiries|call now|call us)', re.I
)
DENSITY_WINDOW = 150   # chars on each side to look for other PII tokens
DENSITY_THRESHOLD = 3  # 3+ other PII tokens nearby => looks like a stuffed block


def _all_pii_spans(body):
    """All (start, end) spans of anything that looks like an email or a
    phone-candidate, used only to measure local PII density."""
    spans = [(m.start(), m.end()) for m in EMAIL_RE.finditer(body)]
    spans += [(m.start(), m.end()) for m in PHONE_CANDIDATE_RE.finditer(body)]
    return spans


def classify_contacts(body, candidate_emails):
    """Split candidate contact emails into (functional, filler) sets based
    on nearby call-to-action language vs. dense PII clustering."""
    pii_spans = _all_pii_spans(body)
    functional, filler = [], []
    for addr in candidate_emails:
        # find this address's occurrence(s) in the body
        occurrences = [m for m in re.finditer(re.escape(addr), body, re.I)]
        if not occurrences:
            filler.append(addr)  # shouldn't happen, but default conservative
            continue
        is_functional = False
        for m in occurrences:
            start, end = m.start(), m.end()
            # context window EXCLUDES the match itself -- otherwise an
            # address like "support@fastly.com" trivially "matches" the
            # keyword "support" against its own username.
            before = body[max(0, start - 80):start]
            after = body[end:min(len(body), end + 80)]
            has_context = bool(CONTACT_CONTEXT_RE.search(before) or CONTACT_CONTEXT_RE.search(after))
            nearby_pii = sum(
                1 for s, e in pii_spans
                if s != start and abs(s - start) <= DENSITY_WINDOW
            )
            if has_context and nearby_pii < DENSITY_THRESHOLD:
                is_functional = True
                break
        (functional if is_functional else filler).append(addr)
    return sorted(functional), sorted(filler)


def classify_phones(body, candidate_phones):
    """Same idea for phone numbers: keyword-confirmed + not in a dense PII
    cluster = functional; matched purely by formatting, or sitting in a
    stuffed block = filler."""
    pii_spans = _all_pii_spans(body)
    functional, filler = [], []
    for phone in candidate_phones:
        occurrences = [m for m in re.finditer(re.escape(phone), body)]
        if not occurrences:
            filler.append(phone)
            continue
        is_functional = False
        for m in occurrences:
            start, end = m.start(), m.end()
            window = body[max(0, start - 30):start]
            has_keyword = bool(PHONE_KEYWORD_RE.search(window))
            nearby_pii = sum(
                1 for s, e in pii_spans
                if s != start and abs(s - start) <= DENSITY_WINDOW
            )
            if has_keyword and nearby_pii < DENSITY_THRESHOLD:
                is_functional = True
                break
        (functional if is_functional else filler).append(phone)
    return sorted(functional), sorted(filler)


# --- Image analysis ------------------------------------------------------
# Three tiers, all local, each optional beyond the first:
# 1. sha256 of the raw bytes -- image reuse across campaigns is an operator
#    fingerprint all by itself, no image decoding needed.
# 2. Perceptual hash (Pillow + imagehash) -- survives recompression/resizing,
#    so near-identical images cluster like SimHash does for text.
# 3. OCR (pytesseract + the Tesseract binary) -- recovers text from
#    image-only spam, which then flows through the existing deobfuscate/
#    keyword/extraction pipeline like any other body text.
IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff")
OCR_MIN_DIMENSION = 60      # skip tracking pixels / tiny decorations
OCR_MAX_BYTES = 5_000_000   # don't decode absurdly large payloads


def extract_images(msg):
    """Return (image_records, ocr_text) for every inline/attached image.
    Each record: {sha256 (truncated), phash, filename, content_type, size}."""
    records = []
    ocr_chunks = []
    for part in msg.walk():
        fname = part.get_filename() or ""
        is_image = (part.get_content_maintype() == "image"
                    or fname.lower().endswith(IMAGE_EXTS))
        if not is_image:
            continue
        try:
            payload = part.get_payload(decode=True)
        except Exception:
            payload = None
        if not payload:
            continue
        rec = {
            "sha256": hashlib.sha256(payload).hexdigest()[:16],
            "phash": "",
            "filename": decode_mime_header(fname),
            "content_type": part.get_content_type(),
            "size": len(payload),
        }
        if HAS_PIL and len(payload) <= OCR_MAX_BYTES:
            try:
                img = Image.open(io.BytesIO(payload))
                img.load()
                if HAS_IMAGEHASH:
                    try:
                        rec["phash"] = str(imagehash.phash(img))
                    except Exception:
                        pass
                if HAS_TESSERACT and min(img.size) >= OCR_MIN_DIMENSION:
                    try:
                        text = pytesseract.image_to_string(img)
                        if text.strip():
                            ocr_chunks.append(text)
                    except Exception:
                        pass  # e.g. tesseract binary not installed
            except Exception:
                pass  # not decodable as an image; keep the byte hash anyway
        records.append(rec)
    return records, "\n".join(ocr_chunks)


def normalize_date(date_hdr):
    """Header date -> ISO 'YYYY-MM-DD' (UTC), or '' if unparseable. Gives
    the report a real time axis for trend analysis."""
    if not date_hdr:
        return ""
    try:
        dt = email.utils.parsedate_to_datetime(date_hdr)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc)
        return dt.date().isoformat()
    except Exception:
        return ""


def extract_row(msg, source="imap"):
    """Extract one IOC row (dict) from an email.message.Message."""
    subject = decode_mime_header(msg.get("Subject"))
    from_hdr = decode_mime_header(msg.get("From"))
    from_name, from_addr = email.utils.parseaddr(from_hdr)
    from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""

    reply_to_hdr = msg.get("Reply-To")
    reply_to_name, reply_to_addr = email.utils.parseaddr(reply_to_hdr or "")
    reply_to_domain = reply_to_addr.split("@")[-1].lower() if "@" in reply_to_addr else ""

    return_path = (msg.get("Return-Path", "") or "").strip("<>")
    date_hdr = msg.get("Date", "")
    date_iso = normalize_date(date_hdr)

    auth_results = msg.get("Authentication-Results", "")
    dkim, spf, dmarc = parse_auth_results(auth_results)

    received_headers = msg.get_all("Received") or []
    ips = extract_ips(received_headers)

    has_list_unsubscribe = bool(msg.get("List-Unsubscribe"))

    raw_body, hrefs, img_srcs, link_mismatches = get_body_text(msg)
    images, ocr_text = extract_images(msg)
    # OCR text joins the body for extraction/keywords -- image-only spam
    # finally contributes URLs, contacts, and keyword hits.
    if ocr_text:
        raw_body += "\n" + ocr_text
    body = deobfuscate(raw_body)

    # <a href> targets recovered from the HTML count as URLs too -- the old
    # tag-stripping approach deleted them along with the markup.
    urls = list(dict.fromkeys(hrefs + URL_RE.findall(body)))
    url_domains = sorted(set(domain_of(u) for u in urls if domain_of(u)))
    remote_image_domains = sorted(set(
        d for d in (domain_of(s) for s in img_srcs if s.lower().startswith("http"))
        if d
    ))

    phones = extract_phones(body)
    btc = list(dict.fromkeys(BTC_RE.findall(body)))
    eth = list(dict.fromkeys(ETH_RE.findall(body)))

    body_emails = set(EMAIL_RE.findall(body))
    header_from_set = {from_addr.lower()} if from_addr else set()
    def is_known_service(addr):
        dom = addr.split("@")[-1].lower() if "@" in addr else ""
        return any(dom == d or dom.endswith("." + d) for d in KNOWN_SERVICE_DOMAINS)

    contact_emails = sorted(
        e for e in body_emails
        if e.lower() not in header_from_set
        and e.lower() not in SELF_ADDRESSES
        and not is_known_service(e)
    )
    functional_contacts, filler_contacts = classify_contacts(body, contact_emails)
    functional_phones, filler_phones = classify_phones(body, phones)

    flags = url_flags(urls)
    display_name_brands = brands_in_display_name(from_name)
    category, scam_score, scam_reasons = triage({
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "text": f"{subject}\n{body}",
        "display_name_brands": display_name_brands,
        "dkim": dkim, "spf": spf, "dmarc": dmarc,
        "link_mismatches": link_mismatches,
        "has_wallet": bool(btc or eth),
        "url_flags": flags,
        "has_list_unsubscribe": has_list_unsubscribe,
    })
    impersonated_brands = detect_brands(subject, body, from_name)
    template_fingerprint = body_template_fingerprint(body)

    return {
        "id": msg_id_hash(msg),
        "source": source,
        "category": category,
        "scam_score": scam_score,
        "scam_signals": "; ".join(scam_reasons),
        "date": date_hdr,
        "date_iso": date_iso,
        "subject": subject,
        "from_name": from_name,
        "from_addr": from_addr,
        "from_domain": from_domain,
        "return_path": return_path,
        "reply_to_addr": reply_to_addr,
        "list_unsubscribe": has_list_unsubscribe,
        "dkim": dkim,
        "spf": spf,
        "dmarc": dmarc,
        "originating_ips": "; ".join(ips),
        "url_count": len(urls),
        "url_domains": "; ".join(url_domains),
        "phone_numbers": "; ".join(phones),
        "phones_functional": "; ".join(functional_phones),
        "phones_filler": "; ".join(filler_phones),
        "btc_addresses": "; ".join(btc),
        "eth_addresses": "; ".join(eth),
        "contact_emails_in_body": "; ".join(contact_emails),
        "contacts_functional": "; ".join(functional_contacts),
        "contacts_filler": "; ".join(filler_contacts),
        "first_url": urls[0] if urls else "",
        "impersonated_brands": "; ".join(impersonated_brands),
        "body_template_fingerprint": template_fingerprint,
        "link_mismatches": "; ".join(link_mismatches),
        "url_flags": "; ".join(flags),
        "remote_image_domains": "; ".join(remote_image_domains),
        "image_count": len(images),
        "image_hashes": "; ".join(r["sha256"] for r in images),
        "image_phashes": "; ".join(r["phash"] for r in images if r["phash"]),
        "image_filenames": "; ".join(r["filename"] for r in images if r["filename"]),
        "image_ocr_chars": len(ocr_text),
    }, urls
