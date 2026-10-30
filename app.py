import os
import re
import secrets
from datetime import timedelta
from urllib.parse import urlparse, parse_qs, unquote
from flask import Flask, jsonify, request, send_from_directory

from auth import auth_bp

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def load_secret_key():
    """Signs the login cookie. Set SCAMSHIELD_SECRET, or one is created once and saved."""
    from_env = os.environ.get("SCAMSHIELD_SECRET")
    if from_env:
        return from_env
    path = os.path.join(BASE_DIR, "secret.key")
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(path, "w") as f:
        f.write(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


app = Flask(__name__)
app.json.ensure_ascii = False   # lets Hindi and Punjabi show properly
app.config.update(
    SECRET_KEY=load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SCAMSHIELD_HTTPS") == "1",   # set to 1 when served over https
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)
app.register_blueprint(auth_bp)


# =====================================================
# PART 1: TEXTS IN ENGLISH (en), HINDI (hi), PUNJABI (pa)
# =====================================================
TEXT = {
    # ----- message reasons -----
    "otp_pin": {
        "en": "It asks you to share an OTP or PIN. Banks never ask for this.",
        "hi": "यह आपसे OTP या PIN मांगता है। बैंक कभी ऐसा नहीं करते।",
        "pa": "ਇਹ ਤੁਹਾਡੇ ਤੋਂ OTP ਜਾਂ PIN ਮੰਗਦਾ ਹੈ। ਬੈਂਕ ਕਦੇ ਇਹ ਨਹੀਂ ਮੰਗਦੇ।",
    },
    "urgency": {
        "en": "It pressures you to act immediately.",
        "hi": "यह आप पर तुरंत कदम उठाने का दबाव डालता है।",
        "pa": "ਇਹ ਤੁਹਾਡੇ 'ਤੇ ਤੁਰੰਤ ਕਾਰਵਾਈ ਕਰਨ ਦਾ ਦਬਾਅ ਪਾਉਂਦਾ ਹੈ।",
    },
    "account_threat": {
        "en": "It threatens to block or close your account or KYC.",
        "hi": "यह आपका अकाउंट या KYC बंद करने की धमकी देता है।",
        "pa": "ਇਹ ਤੁਹਾਡਾ ਖਾਤਾ ਜਾਂ KYC ਬੰਦ ਕਰਨ ਦੀ ਧਮਕੀ ਦਿੰਦਾ ਹੈ।",
    },
    "prize": {
        "en": "It promises a prize, reward or free money.",
        "hi": "यह इनाम, रिवॉर्ड या मुफ़्त पैसे का वादा करता है।",
        "pa": "ਇਹ ਇਨਾਮ, ਰਿਵਾਰਡ ਜਾਂ ਮੁਫ਼ਤ ਪੈਸੇ ਦਾ ਵਾਅਦਾ ਕਰਦਾ ਹੈ।",
    },
    "link_present": {
        "en": "It contains a link. Do not tap links you did not expect.",
        "hi": "इसमें एक लिंक है। जो लिंक आपने नहीं मांगा उसे न खोलें।",
        "pa": "ਇਸ ਵਿੱਚ ਇੱਕ ਲਿੰਕ ਹੈ। ਜੋ ਲਿੰਕ ਤੁਸੀਂ ਨਹੀਂ ਮੰਗਿਆ ਉਸਨੂੰ ਨਾ ਖੋਲ੍ਹੋ।",
    },
    # ----- link reasons -----
    "url_shortener": {
        "en": "The link is shortened, so its real destination is hidden.",
        "hi": "लिंक छोटा किया हुआ है, इसलिए असली वेबसाइट छिपी है।",
        "pa": "ਲਿੰਕ ਛੋਟਾ ਕੀਤਾ ਹੋਇਆ ਹੈ, ਇਸ ਲਈ ਅਸਲ ਵੈੱਬਸਾਈਟ ਲੁਕੀ ਹੋਈ ਹੈ।",
    },
    "url_ip_host": {
        "en": "The link uses numbers (an IP address) instead of a website name.",
        "hi": "लिंक में वेबसाइट के नाम की जगह सीधे नंबर (IP पता) हैं।",
        "pa": "ਲਿੰਕ ਵਿੱਚ ਵੈੱਬਸਾਈਟ ਦੇ ਨਾਂ ਦੀ ਥਾਂ ਸਿੱਧੇ ਨੰਬਰ (IP ਪਤਾ) ਹਨ।",
    },
    "url_lookalike": {
        "en": "The website imitates {brand} but is not its real website.",
        "hi": "यह वेबसाइट {brand} की नकल करती है, पर यह उसकी असली वेबसाइट नहीं है।",
        "pa": "ਇਹ ਵੈੱਬਸਾਈਟ {brand} ਦੀ ਨਕਲ ਕਰਦੀ ਹੈ, ਪਰ ਇਹ ਉਸਦੀ ਅਸਲ ਵੈੱਬਸਾਈਟ ਨਹੀਂ ਹੈ।",
    },
    "url_bad_ending": {
        "en": "The website ending is often used for scam sites.",
        "hi": "वेबसाइट का यह अंत अक्सर ठगी वाली साइटों में इस्तेमाल होता है।",
        "pa": "ਵੈੱਬਸਾਈਟ ਦਾ ਇਹ ਅੰਤ ਅਕਸਰ ਠੱਗੀ ਵਾਲੀਆਂ ਸਾਈਟਾਂ ਵਿੱਚ ਵਰਤਿਆ ਜਾਂਦਾ ਹੈ।",
    },
    "url_no_https": {
        "en": "The link is not encrypted (http instead of https).",
        "hi": "लिंक सुरक्षित नहीं है (https की जगह http)।",
        "pa": "ਲਿੰਕ ਸੁਰੱਖਿਅਤ ਨਹੀਂ ਹੈ (https ਦੀ ਥਾਂ http)।",
    },
    "url_keywords": {
        "en": "The link has words like kyc, verify or reward, common in phishing.",
        "hi": "लिंक में kyc, verify या reward जैसे शब्द हैं, जो फ़िशिंग में आम हैं।",
        "pa": "ਲਿੰਕ ਵਿੱਚ kyc, verify ਜਾਂ reward ਵਰਗੇ ਸ਼ਬਦ ਹਨ, ਜੋ ਫ਼ਿਸ਼ਿੰਗ ਵਿੱਚ ਆਮ ਹਨ।",
    },
    # ----- QR reasons -----
    "qr_collect": {
        "en": "This QR is a collect request: scanning it will take money OUT of your account.",
        "hi": "यह QR कलेक्ट रिक्वेस्ट है: इसे स्कैन करने से आपके खाते से पैसे कटेंगे।",
        "pa": "ਇਹ QR ਕਲੈਕਟ ਰਿਕੁਐਸਟ ਹੈ: ਸਕੈਨ ਕਰਨ ਨਾਲ ਤੁਹਾਡੇ ਖਾਤੇ ਵਿੱਚੋਂ ਪੈਸੇ ਕੱਟਣਗੇ।",
    },
    "qr_intent_mismatch": {
        "en": "You want to RECEIVE money, but this QR makes you PAY. Receiving never needs a scan or a PIN.",
        "hi": "आप पैसे पाना चाहते हैं, पर यह QR आपसे पैसे भरवाएगा। पैसे पाने के लिए स्कैन या PIN नहीं लगता।",
        "pa": "ਤੁਸੀਂ ਪੈਸੇ ਲੈਣਾ ਚਾਹੁੰਦੇ ਹੋ, ਪਰ ਇਹ QR ਤੁਹਾਡੇ ਤੋਂ ਪੈਸੇ ਭਰਵਾਏਗਾ। ਪੈਸੇ ਲੈਣ ਲਈ ਸਕੈਨ ਜਾਂ PIN ਨਹੀਂ ਲੱਗਦਾ।",
    },
    "qr_pays_money": {
        "en": "This is a payment QR: you will PAY {payee}. Continue only if you meant to pay.",
        "hi": "यह पेमेंट QR है: आप {payee} को पैसे देंगे। तभी आगे बढ़ें जब आप पैसे देना चाहते हों।",
        "pa": "ਇਹ ਪੇਮੈਂਟ QR ਹੈ: ਤੁਸੀਂ {payee} ਨੂੰ ਪੈਸੇ ਦਿਓਗੇ। ਤਾਂ ਹੀ ਅੱਗੇ ਵਧੋ ਜੇ ਤੁਸੀਂ ਪੈਸੇ ਦੇਣਾ ਚਾਹੁੰਦੇ ਹੋ।",
    },
    "qr_amount": {
        "en": "The amount (Rs {amount}) is already filled in. Check it is correct.",
        "hi": "रकम (Rs {amount}) पहले से भरी है। जांचें कि यह सही है।",
        "pa": "ਰਕਮ (Rs {amount}) ਪਹਿਲਾਂ ਤੋਂ ਭਰੀ ਹੈ। ਜਾਂਚੋ ਕਿ ਇਹ ਸਹੀ ਹੈ।",
    },
    "qr_bad_note": {
        "en": "The note mentions refund, cashback or prize, a common trick.",
        "hi": "नोट में रिफ़ंड, कैशबैक या इनाम लिखा है, यह आम चाल है।",
        "pa": "ਨੋਟ ਵਿੱਚ ਰਿਫ਼ੰਡ, ਕੈਸ਼ਬੈਕ ਜਾਂ ਇਨਾਮ ਲਿਖਿਆ ਹੈ, ਇਹ ਆਮ ਚਾਲ ਹੈ।",
    },
    "qr_unknown_handle": {
        "en": "The UPI handle @{handle} is not a well-known bank or app.",
        "hi": "UPI हैंडल @{handle} किसी जाने-पहचाने बैंक या ऐप का नहीं है।",
        "pa": "UPI ਹੈਂਡਲ @{handle} ਕਿਸੇ ਜਾਣੇ-ਪਛਾਣੇ ਬੈਂਕ ਜਾਂ ਐਪ ਦਾ ਨਹੀਂ ਹੈ।",
    },
    "qr_not_upi": {
        "en": "This QR is not a UPI payment QR.",
        "hi": "यह QR UPI पेमेंट QR नहीं है।",
        "pa": "ਇਹ QR UPI ਪੇਮੈਂਟ QR ਨਹੀਂ ਹੈ।",
    },
}

VERDICT_TEXT = {
    "Safe": {
        "headline": {"en": "Looks safe", "hi": "सुरक्षित लगता है", "pa": "ਸੁਰੱਖਿਅਤ ਲੱਗਦਾ ਹੈ"},
        "advice": {
            "en": "No scam signs found. Still, never share your OTP or UPI PIN.",
            "hi": "ठगी के कोई संकेत नहीं मिले। फिर भी OTP या UPI PIN कभी साझा न करें।",
            "pa": "ਠੱਗੀ ਦੇ ਕੋਈ ਸੰਕੇਤ ਨਹੀਂ ਮਿਲੇ। ਫਿਰ ਵੀ OTP ਜਾਂ UPI PIN ਕਦੇ ਸਾਂਝਾ ਨਾ ਕਰੋ।",
        },
    },
    "Suspicious": {
        "headline": {"en": "Be careful", "hi": "सावधान रहें", "pa": "ਸਾਵਧਾਨ ਰਹੋ"},
        "advice": {
            "en": "Do not click or pay until you verify through the official app or website.",
            "hi": "आधिकारिक ऐप या वेबसाइट से जांचे बिना क्लिक या भुगतान न करें।",
            "pa": "ਅਧਿਕਾਰਤ ਐਪ ਜਾਂ ਵੈੱਬਸਾਈਟ ਤੋਂ ਜਾਂਚੇ ਬਿਨਾਂ ਕਲਿੱਕ ਜਾਂ ਭੁਗਤਾਨ ਨਾ ਕਰੋ।",
        },
    },
    "Scam": {
        "headline": {"en": "Likely a scam", "hi": "ठगी होने की संभावना", "pa": "ਠੱਗੀ ਹੋਣ ਦੀ ਸੰਭਾਵਨਾ"},
        "advice": {
            "en": "Do not click, pay or reply. Report it on cybercrime.gov.in or call 1930.",
            "hi": "क्लिक, भुगतान या जवाब न दें। cybercrime.gov.in पर रिपोर्ट करें या 1930 पर कॉल करें।",
            "pa": "ਕਲਿੱਕ, ਭੁਗਤਾਨ ਜਾਂ ਜਵਾਬ ਨਾ ਦਿਓ। cybercrime.gov.in 'ਤੇ ਰਿਪੋਰਟ ਕਰੋ ਜਾਂ 1930 'ਤੇ ਕਾਲ ਕਰੋ।",
        },
    },
}


def say(code, **params):
    """Return the reason in all three languages, filling in {brand}, {payee} etc."""
    result = {"code": code}
    for lang in ("en", "hi", "pa"):
        result[lang] = TEXT[code][lang].format(**params)
    return result


# =====================================================
# PART 2: RULES AND DATA
# =====================================================
# (reason code, points, pattern to look for)
RULES = [
    ("otp_pin", 45, r"(share|send|tell).{0,30}(otp|pin)"),
    ("urgency", 15, r"urgent|immediately|within \d+ hours"),
    ("account_threat", 25, r"(block|suspend|close).{0,40}(account|kyc)"),
    ("prize", 25, r"lottery|you have won|prize|cashback"),
    ("link_present", 15, r"https?://|www\."),
]

SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy", "is.gd", "goo.gl"]

REAL_SITES = {
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi"],
    "hdfcbank": ["hdfcbank.com"],
    "icicibank": ["icicibank.com"],
    "amazon": ["amazon.in", "amazon.com"],
    "npci": ["npci.org.in"],
    "kotak": ["kotak.com"],
}

BAD_ENDINGS = (".xyz", ".top", ".club", ".online", ".site", ".icu", ".vip")
PHISH_WORDS = ["kyc", "verify", "reward", "cashback", "refund", "claim"]

KNOWN_HANDLES = ["ybl", "ibl", "axl", "okaxis", "okhdfcbank", "okicici",
                 "oksbi", "paytm", "upi", "sbi", "hdfcbank", "icici", "apl"]
QR_SCAM_WORDS = r"refund|cashback|prize|reward|lottery|claim"


# =====================================================
# PART 3: HELPER FUNCTIONS
# =====================================================
def anonymise(text):
    """Hide phone numbers, UPI IDs and long numbers before a report draft is shown."""
    text = re.sub(r"(?<!\d)(\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)", "XXXXXXXXXX", text)
    text = re.sub(r"\b[\w.\-]{1,64}@[a-zA-Z]{2,20}\b", "***@upi", text)
    text = re.sub(r"(?<!\d)\d{6,18}(?!\d)", "XXXXXX", text)
    return text


def finish(score, reasons, **extra):
    """Turn a score and reasons into the final answer, with verdict texts in 3 languages."""
    score = min(score, 100)
    if score >= 60:
        verdict = "Scam"
    elif score >= 25:
        verdict = "Suspicious"
    else:
        verdict = "Safe"
    result = {
        "verdict": verdict,
        "score": score,
        "headline": VERDICT_TEXT[verdict]["headline"],
        "advice": VERDICT_TEXT[verdict]["advice"],
        "reasons": reasons,
    }
    result.update(extra)
    if verdict != "Safe":
        result["report"] = {"portal": "https://cybercrime.gov.in", "helpline": "1930", "draft": ""}
    return result


def get_domain(url):
    """http://www.Paytm-KYC.xyz/login  ->  paytm-kyc.xyz"""
    url = url.strip().lower()
    url = re.sub(r"^https?://", "", url)
    domain = re.split(r"[/?#]", url)[0]
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def check_url(url):
    domain = get_domain(url)
    score = 0
    reasons = []

    if domain in SHORTENERS:
        score += 30
        reasons.append(say("url_shortener"))

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain):
        score += 60
        reasons.append(say("url_ip_host"))

    tokens = re.split(r"[.\-]", domain)
    for brand, real_list in REAL_SITES.items():
        looks_like = brand in tokens or (len(brand) >= 5 and brand in domain)
        is_real = any(domain == r or domain.endswith("." + r) for r in real_list)
        if looks_like and not is_real:
            score += 60
            reasons.append(say("url_lookalike", brand=brand.title()))
            break

    if domain.endswith(BAD_ENDINGS):
        score += 20
        reasons.append(say("url_bad_ending"))

    if url.strip().lower().startswith("http://"):
        score += 10
        reasons.append(say("url_no_https"))

    if any(word in url.lower() for word in PHISH_WORDS):
        score += 15
        reasons.append(say("url_keywords"))

    result = finish(score, reasons, domain=domain)
    if "report" in result:
        result["report"]["draft"] = anonymise(url.strip())[:1000]
    return result


def check_message(text):
    score = 0
    reasons = []
    for code, points, pattern in RULES:
        if re.search(pattern, text, re.IGNORECASE):
            score += points
            reasons.append(say(code))

    # Also check every link inside the message
    for url in re.findall(r"(?:https?://|www\.)\S+", text, re.IGNORECASE):
        result = check_url(url.rstrip(".,!?)"))
        if result["score"] >= 25:
            score += result["score"]
            reasons.extend(result["reasons"])

    result = finish(score, reasons)
    if "report" in result:
        result["report"]["draft"] = anonymise(text)[:1000]
    return result


def check_qr(content, intent="unknown"):
    """intent = what the user BELIEVES they are doing: receive / pay / unknown"""
    content = content.strip()
    score = 0
    reasons = []

    # Not a UPI QR? It might be a website link.
    if not content.lower().startswith("upi:"):
        if content.lower().startswith(("http://", "https://", "www.")):
            result = check_url(content)
            result["qr_type"] = "link"
            return result
        return finish(0, [say("qr_not_upi")], qr_type="text")

    # Pull the pieces out of the UPI text
    parts = urlparse(content)
    action = parts.netloc.lower()
    info = {k.lower(): unquote(v[0]) for k, v in parse_qs(parts.query).items()}
    payee_id = info.get("pa", "")
    payee_name = info.get("pn", "") or payee_id or "this payee"
    amount = info.get("am", "")
    note = info.get("tn", "") + " " + info.get("pn", "")

    if action == "collect":
        score += 70
        reasons.append(say("qr_collect"))

    if intent == "receive" and action in ("pay", "collect"):
        score += 80
        reasons.append(say("qr_intent_mismatch"))
    elif action == "pay":
        score += 10
        reasons.append(say("qr_pays_money", payee=payee_name))

    if amount:
        score += 15
        reasons.append(say("qr_amount", amount=amount))

    if re.search(QR_SCAM_WORDS, note, re.IGNORECASE):
        score += 40
        reasons.append(say("qr_bad_note"))

    if "@" in payee_id:
        handle = payee_id.split("@")[1].lower()
        if handle not in KNOWN_HANDLES:
            score += 20
            reasons.append(say("qr_unknown_handle", handle=handle))

    result = finish(score, reasons, qr_type="upi", action=action, payee=payee_id,
                    amount=amount or None, is_payment_request=True)
    if "report" in result:
        result["report"]["draft"] = anonymise(content)[:1000]
    return result


# =====================================================
# PART 4: WEB ADDRESSES
# =====================================================
def get_value(name, default=""):
    """Read a value sent by the page (JSON body) or typed in the address bar (?name=...)."""
    data = request.get_json(silent=True)
    if isinstance(data, dict) and data.get(name) is not None:
        return str(data.get(name))
    return request.args.get(name, default)


@app.get("/")
def home():
    if os.path.exists(os.path.join(BASE_DIR, "index.html")):
        return send_from_directory(BASE_DIR, "index.html")
    return "Scam Shield is running. Put index.html next to app.py to see the app."


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "languages": ["en", "hi", "pa"]})


@app.route("/api/check", methods=["GET", "POST"])
def check():
    return jsonify(check_message(get_value("text")))


@app.route("/api/check-url", methods=["GET", "POST"])
def check_url_route():
    return jsonify(check_url(get_value("url")))


@app.route("/api/check-qr", methods=["GET", "POST"])
def check_qr_route():
    return jsonify(check_qr(get_value("content"), get_value("intent", "unknown")))


if __name__ == "__main__":
    app.run(debug=True)