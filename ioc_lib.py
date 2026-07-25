"""
Shared IOC extraction + triage logic, used by process_mail.py.
"""

import os
import re
import email.utils
import hashlib
from email.header import decode_header
from urllib.parse import urlparse

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


def detect_brands(subject, body):
    """Return the sorted list of brands/institutions this email appears to
    be impersonating, based on keyword hits in the subject+body."""
    text = f" {subject}\n{body} ".lower()
    return sorted(
        brand for brand, keywords in IMPERSONATED_BRANDS.items()
        if any(k in text for k in keywords)
    )


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
    extraction sees plain @ addresses."""
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


def get_body_text(msg):
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
    if html_parts:
        combined += "\n" + re.sub(r"<[^>]+>", " ", "\n".join(html_parts))
    return combined


def extract_ips(received_headers):
    ip_re = re.compile(r'\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?')
    ips = []
    for h in received_headers:
        for m in ip_re.finditer(h):
            ip = m.group(1)
            if ip not in ips:
                ips.append(ip)
    return ips


def domain_of(url):
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def parse_auth_results(auth_header):
    if not auth_header:
        return "", "", ""
    dkim = "pass" if re.search(r'dkim=pass', auth_header) else ("fail" if re.search(r'dkim=fail', auth_header) else "")
    spf = "pass" if re.search(r'spf=pass', auth_header) else ("fail" if re.search(r'spf=fail', auth_header) else "")
    dmarc = "pass" if re.search(r'dmarc=pass', auth_header) else ("fail" if re.search(r'dmarc=fail', auth_header) else "")
    return dkim, spf, dmarc


def msg_id_hash(msg):
    mid = msg.get("Message-ID", "") or ""
    return hashlib.sha1(str(mid).encode("utf-8", errors="replace")).hexdigest()[:10]


def triage(from_domain, has_list_unsubscribe, subject, body):
    """Very cheap rule-based triage -- no LLM/API calls, so it costs nothing to run."""
    text = f"{subject}\n{body}".lower()
    root_domain = ".".join(from_domain.split(".")[-2:]) if from_domain else ""

    if root_domain in KNOWN_LEGIT_DOMAINS or from_domain in KNOWN_LEGIT_DOMAINS:
        return "bulk_marketing"
    if has_list_unsubscribe and not any(k in text for k in URGENT_KEYWORDS):
        return "bulk_marketing"
    if any(k in text for k in URGENT_KEYWORDS):
        return "likely_scam"
    if from_domain.endswith(".edu") or ".edu." in from_domain or ".ac." in from_domain:
        return "likely_scam"  # academic domains sending unsolicited mail are usually compromised
    return "review"


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


def extract_row(msg, source="imap"):
    """Extract one IOC row (dict) from an email.message.Message."""
    subject = decode_mime_header(msg.get("Subject"))
    from_hdr = decode_mime_header(msg.get("From"))
    from_name, from_addr = email.utils.parseaddr(from_hdr)
    from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""

    reply_to_hdr = msg.get("Reply-To")
    reply_to_name, reply_to_addr = email.utils.parseaddr(reply_to_hdr or "")

    return_path = (msg.get("Return-Path", "") or "").strip("<>")
    date_hdr = msg.get("Date", "")

    auth_results = msg.get("Authentication-Results", "")
    dkim, spf, dmarc = parse_auth_results(auth_results)

    received_headers = msg.get_all("Received") or []
    ips = extract_ips(received_headers)

    has_list_unsubscribe = bool(msg.get("List-Unsubscribe"))

    body = deobfuscate(get_body_text(msg))

    urls = list(dict.fromkeys(URL_RE.findall(body)))
    url_domains = sorted(set(domain_of(u) for u in urls if domain_of(u)))

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

    category = triage(from_domain, has_list_unsubscribe, subject, body)
    impersonated_brands = detect_brands(subject, body)
    template_fingerprint = body_template_fingerprint(body)

    return {
        "id": msg_id_hash(msg),
        "source": source,
        "category": category,
        "date": date_hdr,
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
    }, urls
