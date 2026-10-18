"""Plain-language explanations for reason codes (design.md §7, testing.md U-ENG-13). en + bn."""
from __future__ import annotations

REASON_TEXT: dict[str, dict[str, str]] = {
    "REGISTRY_MATCH": {"en": "The payee matches a signed registry record.",
                       "bn": "প্রাপক একটি স্বাক্ষরিত রেজিস্ট্রি রেকর্ডের সাথে মিলেছে।"},
    "WITHIN_CAP": {"en": "The amount is within your limits.", "bn": "পরিমাণ আপনার সীমার মধ্যে আছে।"},
    "CATEGORY_ALLOWED": {"en": "This kind of payment is allowed.", "bn": "এই ধরনের পেমেন্ট অনুমোদিত।"},
    "KNOWN_PAYEE": {"en": "This payee is already known.", "bn": "এই প্রাপক আগে থেকেই পরিচিত।"},
    "APPROVED": {"en": "An approver approved this exact payment.", "bn": "একজন অনুমোদনকারী এই পেমেন্ট অনুমোদন করেছেন।"},
    "MANDATE_INVALID": {"en": "Your mandate could not be verified, so nothing was sent.",
                        "bn": "আপনার ম্যান্ডেট যাচাই করা যায়নি, তাই কিছু পাঠানো হয়নি।"},
    "MANDATE_SUPERSEDED": {"en": "This mandate version is no longer active.", "bn": "এই ম্যান্ডেট সংস্করণ আর চালু নেই।"},
    "CATEGORY_NOT_ALLOWED": {"en": "This kind of payment is not in your rules.", "bn": "এই ধরনের পেমেন্ট আপনার নিয়মে নেই।"},
    "REGISTRY_MISMATCH": {"en": "This account is not the one your university uses.",
                          "bn": "এই অ্যাকাউন্টটি আপনার বিশ্ববিদ্যালয়ের ব্যবহৃত অ্যাকাউন্ট নয়।"},
    "REGISTRY_SIGNATURE_INVALID": {"en": "The registry record could not be trusted.", "bn": "রেজিস্ট্রি রেকর্ডটি বিশ্বাসযোগ্য নয়।"},
    "REGISTRY_ENTRY_EXPIRED": {"en": "The registry record is out of date.", "bn": "রেজিস্ট্রি রেকর্ডটির মেয়াদ শেষ।"},
    "REGISTRY_ENTRY_REVOKED": {"en": "The registry record was revoked.", "bn": "রেজিস্ট্রি রেকর্ডটি বাতিল করা হয়েছে।"},
    "ANOMALY_BLOCKED": {"en": "The document contains hidden or instruction-like text, so it was blocked.",
                        "bn": "ডকুমেন্টে লুকানো বা নির্দেশসদৃশ লেখা আছে, তাই আটকানো হয়েছে।"},
    "LOW_CONFIDENCE": {"en": "We could not read the document confidently enough.", "bn": "ডকুমেন্টটি যথেষ্ট নিশ্চিতভাবে পড়া যায়নি।"},
    "READER_OUTPUT_MISSING": {"en": "The document could not be read.", "bn": "ডকুমেন্টটি পড়া যায়নি।"},
    "NEW_PAYEE": {"en": "This is a new payee, so it needs approval.", "bn": "এটি নতুন প্রাপক, তাই অনুমোদন দরকার।"},
    "COOLING_OFF": {"en": "New payee. We'll wait before sending.", "bn": "নতুন প্রাপক। পাঠানোর আগে অপেক্ষা করা হবে।"},
    "OVER_CAP": {"en": "This is over your per-payment or rolling limit.", "bn": "এটি আপনার সীমার বেশি।"},
    "OVER_SOFT_CAP": {"en": "This is over your limit and needs approval.", "bn": "এটি আপনার সীমার বেশি, অনুমোদন দরকার।"},
    "ESCALATE_ABOVE": {"en": "This amount needs approval.", "bn": "এই পরিমাণের জন্য অনুমোদন দরকার।"},
    "INSUFFICIENT_FUNDS": {"en": "There is not enough balance in that account.", "bn": "ওই অ্যাকাউন্টে যথেষ্ট ব্যালেন্স নেই।"},
    "UNKNOWN_ACCOUNT": {"en": "That account is not recognised.", "bn": "অ্যাকাউন্টটি চেনা যায়নি।"},
    "RAIL_NOT_ALLOWED": {"en": "That payment method is not in your rules.", "bn": "পেমেন্ট পদ্ধতিটি আপনার নিয়মে নেই।"},
    "PROPOSAL_READER_MISMATCH": {"en": "The proposed payment does not match the document.", "bn": "প্রস্তাবিত পেমেন্ট ডকুমেন্টের সাথে মেলে না।"},
    "APPROVAL_REJECTED": {"en": "An approver rejected this payment.", "bn": "একজন অনুমোদনকারী এটি বাতিল করেছেন।"},
    "ACTION_NOT_SUPPORTED": {"en": "That action is not supported.", "bn": "এই কাজটি সমর্থিত নয়।"},
    "CAP_CURRENCY_UNSUPPORTED": {"en": "The currencies do not match your rule.", "bn": "মুদ্রা আপনার নিয়মের সাথে মেলে না।"},
    "DUPLICATE_PAYMENT": {"en": "This invoice was already paid, so it was not sent again.",
                          "bn": "এই ইনভয়েসটি আগেই পরিশোধ করা হয়েছে, তাই আবার পাঠানো হয়নি।"},
}

# User-facing verdict text (design.md §3). Shape + text + colour always travel together.
VERDICT_TEXT = {
    "ALLOW": {"en": "Allowed", "bn": "অনুমোদিত"},
    "HOLD": {"en": "On hold", "bn": "অপেক্ষমাণ"},
    "ESCALATE": {"en": "Needs approval", "bn": "অনুমোদন দরকার"},
    "DENY": {"en": "Blocked", "bn": "আটকানো হয়েছে"},
}


def explain(code: str, lang: str = "en") -> str:
    entry = REASON_TEXT.get(code)
    if entry is None:
        return code  # never invent text for an unknown code
    return entry.get(lang) or entry["en"]
