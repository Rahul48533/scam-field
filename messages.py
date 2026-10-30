VERDICTS = {
    "en": {"Scam": "Scam", "Suspicious": "Suspicious", "Safe": "Safe"},
    "hi": {"Scam": "धोखाधड़ी", "Suspicious": "संदिग्ध", "Safe": "सुरक्षित"},
    "pa": {"Scam": "ਠੱਗੀ", "Suspicious": "ਸ਼ੱਕੀ", "Safe": "ਸੁਰੱਖਿਅਤ"},
}

TEXT = {
    "en": {
        "otp_pin": "Asks you to share an OTP or PIN",
        "urgent": "Pressures you to act fast",
        "block_account": "Threatens to block your account",
        "prize": "Promises a prize or free money",
        "has_link": "Contains a link",
        "shortened": "Shortened link hides the real website",
        "raw_ip": "Uses a raw IP address instead of a website name",
        "lookalike": "Pretends to be {brand} but is not its real website",
        "bad_ending": "Domain ending is often used for scam sites",
        "no_https": "Link is not encrypted (http, not https)",
        "phish_words": "Contains words like kyc, verify or reward",
        "not_upi": "This QR is not a UPI payment QR",
        "collect": "This is a collect request: it will take money out of your account",
        "receive_but_pay": "You want to RECEIVE money, but this QR makes you PAY. Receiving never needs a scan or a PIN",
        "pay_qr": "This is a payment QR: you will PAY {payee}. Continue only if you meant to pay",
        "amount": "Amount is pre-filled (Rs {amount}). Check it is correct",
        "bait_note": "The note mentions refund, cashback or prize, a common trick",
        "unknown_handle": "The UPI handle @{handle} is not a well-known bank or app",
        "in_database": "Reported as a scam {count} time(s) in our fraud database",
    },
    "hi": {
        "otp_pin": "आपसे OTP या PIN साझा करने को कहा जा रहा है",
        "urgent": "जल्दबाज़ी करने का दबाव बनाया जा रहा है",
        "block_account": "आपका खाता बंद करने की धमकी दी जा रही है",
        "prize": "इनाम या मुफ़्त पैसे का लालच दिया जा रहा है",
        "has_link": "इसमें एक लिंक है",
        "shortened": "छोटा किया हुआ लिंक असली वेबसाइट छिपा देता है",
        "raw_ip": "वेबसाइट के नाम की जगह IP एड्रेस इस्तेमाल हुआ है",
        "lookalike": "यह {brand} होने का दिखावा कर रहा है, पर यह उसकी असली वेबसाइट नहीं है",
        "bad_ending": "ऐसे डोमेन अक्सर ठगी वाली साइटों पर इस्तेमाल होते हैं",
        "no_https": "लिंक सुरक्षित (एन्क्रिप्टेड) नहीं है (http है, https नहीं)",
        "phish_words": "इसमें kyc, verify या reward जैसे शब्द हैं",
        "not_upi": "यह UPI पेमेंट QR नहीं है",
        "collect": "यह एक कलेक्ट रिक्वेस्ट है: इससे आपके खाते से पैसे कट जाएँगे",
        "receive_but_pay": "आप पैसे पाना चाहते हैं, लेकिन यह QR आपसे पैसे भरवाएगा। पैसे पाने के लिए कभी स्कैन या PIN की ज़रूरत नहीं होती",
        "pay_qr": "यह पेमेंट QR है: आप {payee} को पैसे भेजेंगे। तभी आगे बढ़ें जब आपका यही इरादा हो",
        "amount": "राशि पहले से भरी हुई है (₹{amount})। जाँच लें कि यह सही है",
        "bait_note": "नोट में रिफंड, कैशबैक या इनाम का ज़िक्र है, जो ठगी का आम तरीका है",
               "unknown_handle": "UPI हैंडल @{handle} कोई जाना-माना बैंक या ऐप नहीं है",
        "in_database": "हमारे धोखाधड़ी डेटाबेस में इसकी {count} बार ठगी के रूप में शिकायत हो चुकी है",
    },
    "pa": {
        "otp_pin": "ਤੁਹਾਨੂੰ OTP ਜਾਂ PIN ਸਾਂਝਾ ਕਰਨ ਲਈ ਕਿਹਾ ਜਾ ਰਿਹਾ ਹੈ",
        "urgent": "ਤੁਹਾਡੇ 'ਤੇ ਜਲਦਬਾਜ਼ੀ ਕਰਨ ਦਾ ਦਬਾਅ ਪਾਇਆ ਜਾ ਰਿਹਾ ਹੈ",
        "block_account": "ਤੁਹਾਡਾ ਖਾਤਾ ਬੰਦ ਕਰਨ ਦੀ ਧਮਕੀ ਦਿੱਤੀ ਜਾ ਰਹੀ ਹੈ",
        "prize": "ਇਨਾਮ ਜਾਂ ਮੁਫ਼ਤ ਪੈਸੇ ਦਾ ਲਾਲਚ ਦਿੱਤਾ ਜਾ ਰਿਹਾ ਹੈ",
        "has_link": "ਇਸ ਵਿੱਚ ਇੱਕ ਲਿੰਕ ਹੈ",
        "shortened": "ਛੋਟਾ ਕੀਤਾ ਲਿੰਕ ਅਸਲੀ ਵੈੱਬਸਾਈਟ ਲੁਕਾ ਦਿੰਦਾ ਹੈ",
        "raw_ip": "ਵੈੱਬਸਾਈਟ ਦੇ ਨਾਮ ਦੀ ਥਾਂ IP ਐਡਰੈੱਸ ਵਰਤਿਆ ਗਿਆ ਹੈ",
        "lookalike": "ਇਹ {brand} ਹੋਣ ਦਾ ਦਿਖਾਵਾ ਕਰ ਰਿਹਾ ਹੈ, ਪਰ ਇਹ ਉਸਦੀ ਅਸਲੀ ਵੈੱਬਸਾਈਟ ਨਹੀਂ ਹੈ",
        "bad_ending": "ਅਜਿਹੇ ਡੋਮੇਨ ਅਕਸਰ ਠੱਗੀ ਵਾਲੀਆਂ ਸਾਈਟਾਂ ਵਿੱਚ ਵਰਤੇ ਜਾਂਦੇ ਹਨ",
        "no_https": "ਲਿੰਕ ਸੁਰੱਖਿਅਤ (ਇਨਕ੍ਰਿਪਟਿਡ) ਨਹੀਂ ਹੈ (http ਹੈ, https ਨਹੀਂ)",
        "phish_words": "ਇਸ ਵਿੱਚ kyc, verify ਜਾਂ reward ਵਰਗੇ ਸ਼ਬਦ ਹਨ",
        "not_upi": "ਇਹ UPI ਪੇਮੈਂਟ QR ਨਹੀਂ ਹੈ",
        "collect": "ਇਹ ਇੱਕ ਕੁਲੈਕਟ ਰਿਕੁਐਸਟ ਹੈ: ਇਸ ਨਾਲ ਤੁਹਾਡੇ ਖਾਤੇ ਵਿੱਚੋਂ ਪੈਸੇ ਕੱਟੇ ਜਾਣਗੇ",
        "receive_but_pay": "ਤੁਸੀਂ ਪੈਸੇ ਲੈਣਾ ਚਾਹੁੰਦੇ ਹੋ, ਪਰ ਇਹ QR ਤੁਹਾਡੇ ਤੋਂ ਪੈਸੇ ਭਰਵਾਏਗਾ। ਪੈਸੇ ਲੈਣ ਲਈ ਕਦੇ ਸਕੈਨ ਜਾਂ PIN ਦੀ ਲੋੜ ਨਹੀਂ ਹੁੰਦੀ",
        "pay_qr": "ਇਹ ਪੇਮੈਂਟ QR ਹੈ: ਤੁਸੀਂ {payee} ਨੂੰ ਪੈਸੇ ਭੇਜੋਗੇ। ਤਾਂ ਹੀ ਅੱਗੇ ਵਧੋ ਜੇ ਤੁਹਾਡਾ ਇਹੀ ਇਰਾਦਾ ਹੈ",
        "amount": "ਰਕਮ ਪਹਿਲਾਂ ਤੋਂ ਭਰੀ ਹੋਈ ਹੈ (₹{amount})। ਜਾਂਚ ਲਓ ਕਿ ਇਹ ਸਹੀ ਹੈ",
        "bait_note": "ਨੋਟ ਵਿੱਚ ਰਿਫੰਡ, ਕੈਸ਼ਬੈਕ ਜਾਂ ਇਨਾਮ ਦਾ ਜ਼ਿਕਰ ਹੈ, ਜੋ ਠੱਗੀ ਦਾ ਆਮ ਤਰੀਕਾ ਹੈ",
        "unknown_handle": "UPI ਹੈਂਡਲ @{handle} ਕੋਈ ਜਾਣਿਆ-ਪਛਾਣਿਆ ਬੈਂਕ ਜਾਂ ਐਪ ਨਹੀਂ ਹੈ",
    },
}


def reason(code, **params):
    """Build a reason entry: reason("amount", amount="4999")"""
    return {"code": code, "params": params}


def localize(result, lang="en"):
    lang = lang if lang in TEXT else "en"
    out = dict(result)
    out["verdict_code"] = result["verdict"]          # keep English for colours/logic
    out["verdict"] = VERDICTS[lang][result["verdict"]]
    out["reasons"] = [TEXT[lang][r["code"]].format(**r["params"])
                      for r in result["reasons"]]
    out["lang"] = lang
    return out