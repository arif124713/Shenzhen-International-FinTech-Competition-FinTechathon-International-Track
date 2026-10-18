# design.md — Mandate: Visual Identity and UI Specification

> Audience: AI coders and the human designer. Follow this file exactly when building UI; if a decision is missing, choose the option that best serves the **primary job** below and add it here.

---

## 1. Design brief (grounded in the subject)

- **Subject:** a web app where an AI agent handles cross-border student money tasks under a user-signed mandate.
- **Audiences:** Rafi (student, bilingual, mobile-first, anxious about mistakes) and Ammu (guardian in Bangladesh, Bangla reader, approves on a phone). Judges also review it on a laptop.
- **Primary job:** make a person **trust a delegation** — see what the agent may do, why a payment was allowed, held or blocked, and what it cost. Trust here comes from legibility, not from decoration.
- **Tone:** calm, exact, plain-spoken. Closer to a well-kept ledger and a signed cheque than to a "futuristic AI" dashboard.

### 1.1 The one memorable thing

**The Decision Trace.** Every proposal gets a horizontal track of checkpoints (Document → Registry → Policy → Rail → Result). Each checkpoint resolves in sequence with its own verdict mark and a one-line reason. It is the only element allowed a signature animation. Everything else stays quiet.

### 1.2 Secondary identity device: the Mandate card

The user's rules appear as a **card with a notched, perforated edge** (like a cheque counterfoil) so a mandate is visibly a *signed document*, not a settings page. Used on the Dashboard, Mandate page, Guardian page and Attestation. No other component gets the notch.

### 1.3 Design plan review (what was rejected and why)

| First instinct | Why it was rejected | Replacement |
|---|---|---|
| Warm cream background with serif display and terracotta accent | Generic "AI-generated" default | Cool mist-grey ground, sans-serif system, teal/ochre/brick semantics |
| Dark near-black UI with neon accent | Cliché "fintech/AI" look; harder to read for older guardians | Light UI, high contrast ink |
| Same rounded card + soft shadow everywhere | Flattens hierarchy | Borders for most surfaces; shadow only for floating layers; distinct radii per role |
| Monospace for all small labels, ALL-CAPS eyebrows above headings | Template chrome | Sentence-case labels; mono used **only** for hashes/IDs/account numbers |
| Red/green allow/deny only | Colour-blind unsafe; also reads as flag clichés | Verdicts use **shape + text + colour** together |
| Numbered 01/02/03 markers | Content is not a sequence (except the trace) | Numbers only inside the trace and the stepped upload flow |

---

## 2. Design tokens

Define in `apps/web/src/styles/tokens.css` as CSS variables; Tailwind config reads them. Never hard-code hex values in components.

### 2.1 Colour (role-based)

| Token | Hex | Role |
|---|---|---|
| `--ground` | `#EDF0F2` | App background (cool mist) |
| `--surface` | `#FFFFFF` | Cards, inputs, panels |
| `--surface-sunk` | `#E3E8EC` | Table stripes, inset areas, disabled fields |
| `--ink` | `#14212B` | Primary text (deep slate-teal ink) |
| `--ink-muted` | `#4A5B68` | Secondary text (contrast ≥ 4.5:1 on surface) |
| `--line` | `#C5CFD6` | Borders, dividers |
| `--seal` | `#0B6E6E` | Primary actions, verified/allowed, focus ring base |
| `--seal-tint` | `#DCEFEF` | Allowed background wash |
| `--hold` | `#8A5A00` | Hold / needs-approval text and icons (text-safe) |
| `--hold-fill` | `#B7791F` | Hold graphic fills/borders only (not for small text) |
| `--hold-tint` | `#F6EBD3` | Hold background wash |
| `--deny` | `#B3261E` | Blocked / destructive text and icons |
| `--deny-tint` | `#F8E1DF` | Blocked background wash |
| `--untrusted` | `#5B4B8A` | Marks text that came from an untrusted document |
| `--untrusted-tint` | `#ECE8F5` | Background for quoted untrusted text |
| `--sim` | `#3F4B55` | "Simulated" banner |

Contrast notes (verify with a checker during build): ink on ground and surface ≥ 12:1; seal on surface ≈ 6:1; hold (text) on surface ≈ 5.9:1; deny on surface ≈ 6.5:1. `--hold-fill` is ≈ 3.6:1 on white, so use it for borders/icons ≥ 3:1 only, never for body text.

### 2.2 Typography

| Role | Family | Fallback | Notes |
|---|---|---|---|
| UI + headings (Latin) | **Schibsted Grotesk** | `system-ui, sans-serif` | Weights 400, 500, 700. Characterful but sober. |
| Bangla (UI + body) | **Hind Siliguri** | `"Noto Sans Bengali", sans-serif` | Weights 400, 500, 600. Set `font-feature-settings: normal`. Bangla needs +0.1 line-height. |
| Hashes, IDs, account numbers | **IBM Plex Mono** | `ui-monospace, monospace` | Only for `hash`, `trace_id`, account/bank identifiers. |

Font stack in CSS: `font-family: "Schibsted Grotesk", "Hind Siliguri", system-ui, sans-serif;` so Bangla glyphs fall through automatically. Use `lang` attributes (`lang="bn"`) on Bangla blocks. Tabular numerals (`font-variant-numeric: tabular-nums`) for all money.

Scale (rem; 16px base; ratio ≈ 1.2): `12 / 14 / 16 / 19 / 23 / 28 / 34`. Line-height: body 1.5 (Bangla 1.65), headings 1.2. Max line length: 68ch (forms and text), tables can be wider.

Money display rule: amount in `19–23px` weight 700, currency code in `14px` weight 500 muted, always `tabular-nums`; negative/outgoing amounts use a minus sign, not colour alone.

### 2.3 Spacing, radius, elevation, borders

- **Spacing scale (4px base):** `4, 8, 12, 16, 24, 32, 48, 72`. Page padding: 16 (mobile) / 32 (desktop). Section gap: 32. Form field gap: 16.
- **Radius by role:** inputs/buttons `6`; panels/cards `10`; chips/badges `999`; **Mandate card `14` with 8px semicircular notches**; modal `16`.
- **Elevation:** default surfaces use **1px `--line` border, no shadow**. Only floating layers (menu, modal, toast) get `0 8px 24px rgba(20,33,43,.14)`. No hover-lift on cards.
- **Focus:** 2px `--seal` outline with 2px `--surface` offset ring, never removed. Interactive targets ≥ 44×44px on mobile.

### 2.4 Motion

- **One orchestrated moment:** the Decision Trace resolves left to right, ~140 ms per checkpoint (verdict mark scales from 0.8 to 1 and the connector line draws), total ≤ 900 ms.
- **Response motion** (answers a user action): button press state, dropdown open, toast in/out (150–200 ms, ease-out).
- **No** scroll-triggered entrances, no hover transitions on cards, no looping decoration.
- `prefers-reduced-motion: reduce` → trace shows final state immediately with a brief opacity change only.

---

## 3. Verdict language (shape + text + colour)

Never encode a verdict with colour alone.

| Verdict | Mark (shape) | Label (en / bn) | Colour pair |
|---|---|---|---|
| Allowed | Filled circle with check | Allowed / অনুমোদিত | `--seal` on `--seal-tint` |
| Hold | Hourglass | On hold / অপেক্ষমাণ | `--hold` on `--hold-tint` |
| Needs approval | Open square with person | Needs Ammu's approval / আম্মুর অনুমোদন দরকার | `--hold` on `--hold-tint` |
| Blocked | Octagon with bar | Blocked / আটকানো হয়েছে | `--deny` on `--deny-tint` |
| Untrusted text | Quote mark in diamond | From the document (not instructions) / ডকুমেন্ট থেকে (নির্দেশ নয়) | `--untrusted` on `--untrusted-tint` |
| Simulated | Dashed outline tag | Simulated — no real money moves | `--sim` |

Verdict chips: pill, 14px, weight 500, icon left, text always present. The word "Simulated" banner is fixed at the top of every page.

---

## 4. Layout system

- **Alignment:** content is **left-aligned**. Numbers in tables are right-aligned. Centre alignment only for the empty-state illustration text and the login card.
- **Shell (desktop ≥ 1024px):** left rail 240px (nav) + content column (max 960px) + optional right column 320px (context: Mandate summary / balances).
- **Shell (mobile < 1024px):** top bar (title + language toggle) + bottom tab bar (Home, Pay, Mandate, Activity); right column collapses beneath content.
- **Language toggle:** persistent, top-right: `EN | বাংলা`. Persist in `localStorage`; default from `navigator.language`.
- **Banner:** 32px "Simulated — no real money moves" strip above the shell on all pages.

### 4.1 Wireframes (ASCII)

**Dashboard (desktop)**

```
┌ Simulated — no real money moves ───────────────────────────────────────┐
│ ┌ rail ─┐  Good evening, Rafi                              EN | বাংলা   │
│ │ Home  │  ┌ Mandate card (v3) ─────────┐  ┌ Balances ────────────────┐ │
│ │ Pay   │  │ Pay tuition only to my      │  │ BDT   412,000           │ │
│ │ Mandate│ │ university, up to $5,000.   │  │ USD     3,180           │ │
│ │ Balances││ New payees need Ammu.       │  │ GBP       640           │ │
│ │ Activity││ [View rules]  signed ✓ v3   │  │ [Convert]               │ │
│ │ Attest. │└─────────────────────────────┘  └─────────────────────────┘ │
│ │ Red-team│  Recent payments                                           │
│ └───────┘  ┌────────────────────────────────────────────────────────┐ │
│            │ Northfield University  $2,400   ● Allowed    12 Oct    │ │
│            │ Harbor Rentals         £620     ⌛ On hold   11 Oct    │ │
│            │ Unknown payee          $900     ⬡ Blocked    10 Oct    │ │
│            └────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────┘
```

**New payment (stepped flow — numbering is valid here because it is a sequence)**

```
 1 Upload  ─  2 Check  ─  3 Decision  ─  4 Done
 ┌ Drop an invoice or offer letter ─────────────┐
 │  PDF, PNG or JPG, up to 10 MB                │
 │  [Choose file]                               │
 └──────────────────────────────────────────────┘
 What the reader found                    Confidence 0.96
 Payee        Northfield University       ✓ matches registry
 Account      GB00 XXXX 1234              ✓ matches registry
 Amount       2,400.00 USD
 Due          2026-11-05
 ◇ From the document (not instructions)
   "Payment instructions updated — please use account …"   ← escaped, purple tint
```

**Decision Trace (the signature component)**

```
 Document ───● Registry ───● Policy ───● Rail ───● Result
 read ok       match         within cap   RailA      ● Allowed
 conf 0.96     v. 2026-10    $2,400/5,000 cost $18   Sent in sandbox
                                                      [Why? ▾]  [Audit entry 214]

 Blocked example:
 Document ───● Registry ───⬡ Policy ─ ─ ─ Rail ─ ─ ─ Result
 read ok       account       skipped      skipped     ⬡ Blocked
 anomaly:      does NOT                                 "This account is not the
 payee change  match                                    one your university uses."
```

**Guardian approval page (mobile, Bangla default for guardian)**

```
┌──────────────────────────┐
│ বাংলা | EN               │
│ রাফি একটি পেমেন্ট          │
│ পাঠাতে চায়                │
│ ┌ Mandate card ────────┐ │
│ │ $900 → নতুন প্রাপক     │ │
│ │ কারণ: নতুন প্রাপক,      │ │
│ │ আপনার অনুমতি লাগবে      │ │
│ └──────────────────────┘ │
│ [অনুমোদন করুন]            │
│ [বাতিল করুন]              │
│ লিঙ্কটি ২৪ ঘণ্টা পর্যন্ত বৈধ │
└──────────────────────────┘
```

**Red-team report**

```
 Results from 100 attacks (synthetic, sandbox)
 ┌ System ──────────┬ Attack success ┬ False blocks ┬ Tasks done ┐
 │ B0 naive agent   │ …% (measured)  │ …%           │ …/30       │
 │ B1 prompted agent│ …%             │ …%           │ …/30       │
 │ Mandate          │ …%             │ …%           │ …/30       │
 └──────────────────┴────────────────┴──────────────┴────────────┘
 By attack family ▾    Failures we found ▾    How to reproduce ▾
```
(Values are always injected from the report JSON — never typed by hand.)

---

## 5. Pages and routes

| Route | Page | Key components |
|---|---|---|
| `/login` | Demo login (Rafi / Ammu) | Role cards |
| `/` | Dashboard | Mandate card, balances, recent activity, alerts |
| `/mandate` | Mandate editor | NL textarea (en/bn), compile result, back-translation, test cases, confirm, version history |
| `/pay` | New payment | Stepper, uploader, extraction panel, untrusted-text quote, Decision Trace |
| `/payments/:id` | Payment detail | Trace, rail comparison table, audit link |
| `/balances` | Balances and conversions | Account list, conversion rule form, fee audit |
| `/activity` | Audit log | Table with chain-verify button, export |
| `/attest` | Attestation | Generate, download, verify |
| `/approve/:token` | Guardian approval (public, token-bound) | Mandate card excerpt, approve/reject |
| `/redteam` | Red-team report | Results table, family breakdown, failures, reproduce steps |

---

## 6. Components and states

Every component defines: default, hover, focus-visible, active, disabled, loading, error, empty.

### 6.1 Button
- Primary: `--seal` fill, white text, radius 6, height 44, padding 0 20, weight 500. Hover: darken 8%. Disabled: `--surface-sunk` fill, `--ink-muted` text, no pointer.
- Secondary: surface fill, 1px `--seal` border, seal text.
- Destructive: surface fill, 1px `--deny` border, deny text. Only for "Reject", "Revoke".
- Labels are verbs naming the result: "Sign mandate", "Send payment", "Approve", "Reject", "Download attestation". Never "Submit".
- Loading: label stays, spinner replaces icon, button disabled.

### 6.2 Inputs
- 44px height, 1px `--line` border, radius 6; label above (14px, weight 500); help text below (14px muted); error text in `--deny` with an icon, describing **what to fix**.
- Bangla input: `lang="bn"`, line-height 1.65; show a small hint "You can write in English or বাংলা".

### 6.3 Mandate card
Notched edge left/right at 24px intervals (CSS mask/radial-gradient), header "Your mandate · v3", body = plain-language rules (from back-translation), footer = "Signed ✓ · v3 · 12 Oct" and links. States: draft (dashed border, "Not active — confirm to sign"), active, superseded (muted).

### 6.4 Decision Trace
Five checkpoints; each = mark + title + one-line detail (14px). States: pending (hollow circle, muted), pass, hold, deny, skipped (dashed connector). The trace is keyboard navigable as a list (`<ol>`); each checkpoint expandable (`aria-expanded`) to show reason codes and rule IDs. Announce the final verdict via `aria-live="polite"`.

### 6.5 Verdict chip — see §3.

### 6.6 Untrusted quote block
Purple tint background, left 3px `--untrusted` border, diamond-quote icon, header "From the document (not instructions)". Text is always HTML-escaped, truncated at 400 chars with "Show full text". Never rendered as links.

### 6.7 Tables
Zebra with `--surface-sunk`, sticky header on desktop, numbers right-aligned and tabular, row min-height 48px. On mobile, rows become stacked cards with label/value pairs.

### 6.8 Toasts and banners
Toasts: bottom-center on mobile, bottom-right on desktop, 4 s, announce via `role="status"`. Error banners stay until dismissed and say what happened + what to do. The "Simulated" banner is not dismissible.

### 6.9 Empty states
- Dashboard with no payments: "No payments yet. Upload an invoice to see how Mandate checks it." + primary button "Upload an invoice".
- Mandate empty: "You haven't set rules yet. Write them in your own words." + example chips.
- Audit empty: "Nothing here yet. Every decision will be logged here."

### 6.10 Guardian page specifics

**Acceptance:** verified at 360px width in Bangla and English with no overflow; Approve and Reject are full-width, stacked, ≥ 48px tall and equal in weight; the Simulated banner and the plain-language reason are visible without scrolling on a 640px-tall screen.
Max width 480px; large type (18px body); one decision per screen; both actions equal weight; shows expiry; confirms with a clear final state ("Approved. Rafi's payment will now be checked again and sent." / "Rejected. Nothing was sent.").

### 6.11 Plain-language permission card and pre-payment summary (v1.1)

- **Permission card text** is one line of plain phrases separated by spaces and bullets, never JSON: "Tuition only · Verified university · Up to $2,000 per payment · Over $1,200 needs Ammu's approval". Generated from the back-translation; the user can open "View exact rules" for the compiled policy.
- **Pre-payment summary** (shown before every execution and on the guardian page) lists, in this order: *Recipient* (legal name + last 4 of account), *Amount and currency*, *Fee*, *Recipient receives*, *Why this decision*, and for approvals *Expires*. Nothing is hidden behind a disclosure for these six items.
- **Reject is as easy as approve:** equal size, adjacent, no pre-selected default, no guilt copy.
- **On-hold state:** "On hold for 24 hours because this is a new payee." If the due date falls inside the hold, add: "Your due date is 5 Nov. Need it sooner?" with the button **Ask Ammu to release the hold**. The button sends a guardian approval request for that exact payment; it does not shorten the hold by itself.
- **Correcting an ambiguous mandate:** show the refusal, quote the unclear phrase, and offer two or three concrete rewrites as buttons ("Up to $1,000 per payment" / "Up to $2,000 per payment" / "Write my own").

### 6.12 Registry trust badge (v1.1)

Every registry-verified payee shows a badge: "Matches signed registry record · version 2026-10-18". An expandable panel lists provenance (how and when the entry was enrolled, source, second check, validity, revocation status) and always includes this sentence: **"A signature shows the record hasn't been changed. It doesn't prove the institution is genuine."** Never label a payee "verified institution" without this panel.

---

## 7. Copy guidelines

- Sentence case everywhere. Plain verbs. No filler. No mascots, no "AI magic" language.
- Explain outcomes in the user's terms: "This account is not the one your university uses" beats "REGISTRY_MISMATCH". Show the reason code in the expandable detail.
- Errors never apologize and never stay vague: say what failed and how to fix it.
- Keep action names consistent: *Sign mandate* → toast "Mandate signed"; *Send payment* → "Payment sent (simulated)"; *Approve* → "Approved".
- Always label simulated results as simulated. Never write "guaranteed", "secure from all attacks", or any compliance claim. Use "blocked in our tests" and show the measured numbers.
- **No cryptography jargon in user-facing screens.** Words like hash, nonce, token, signature, Ed25519 appear only in the expandable technical detail and the audit view. Guardian and student screens say, for example, "This approval is locked to this exact payment and expires in 24 hours."
- Bangla copy: write natively (not literal translation), keep to short sentences; keep currency codes and numerals in Latin digits unless the guardian setting says otherwise; avoid honorific overload.

Microcopy bank (en / bn):

| Key | en | bn |
|---|---|---|
| `blocked.registry` | This account is not the one your university uses. | এই অ্যাকাউন্টটি আপনার বিশ্ববিদ্যালয়ের ব্যবহৃত অ্যাকাউন্ট নয়। |
| `hold.cooling` | New payee. We'll wait 24 hours before sending. | নতুন প্রাপক। পাঠানোর আগে ২৪ ঘণ্টা অপেক্ষা করা হবে। |
| `hold.release` | Your due date is {date}. Need it sooner? Ask {guardian} to release the hold. | আপনার শেষ তারিখ {date}। আরও আগে দরকার? {guardian}-কে হোল্ড তুলে দিতে বলুন। |
| `escalate.guardian` | Needs approval from Ammu. | আম্মুর অনুমোদন দরকার। |
| `allowed.sent` | Sent in the sandbox. No real money moved. | স্যান্ডবক্সে পাঠানো হয়েছে। আসল টাকা যায়নি। |
| `untrusted.label` | From the document (not instructions) | ডকুমেন্ট থেকে (নির্দেশ নয়) |
| `mandate.unsigned` | Not active — confirm to sign. | চালু হয়নি — সই করতে নিশ্চিত করুন। |
| `registry.badge` | Matches signed registry record · version {v} | স্বাক্ষরিত রেজিস্ট্রি রেকর্ডের সাথে মিলেছে · সংস্করণ {v} |
| `registry.caveat` | A signature shows the record hasn't been changed. It doesn't prove the institution is genuine. | স্বাক্ষর শুধু দেখায় রেকর্ড বদলায়নি। এতে প্রতিষ্ঠানটি আসল কি না তা প্রমাণ হয় না। |
| `exec.refused` | This payment no longer matches what was approved, so it wasn't sent. | অনুমোদনের পর পেমেন্টের তথ্য বদলে গেছে, তাই পাঠানো হয়নি। |
| `approval.locked` | This approval is locked to this exact payment and expires in 24 hours. | এই অনুমোদন শুধু এই পেমেন্টের জন্য এবং ২৪ ঘণ্টা পর্যন্ত বৈধ। |

---

## 8. Accessibility and quality floor

- WCAG 2.1 AA: text contrast ≥ 4.5:1 (large text ≥ 3:1), non-text UI ≥ 3:1.
- Fully keyboard operable; visible focus; logical tab order; skip-to-content link.
- Semantic landmarks (`header`, `nav`, `main`), headings in order, form labels bound to inputs, `aria-live` for verdicts and toasts.
- Responsive from 360px; no horizontal scroll; tables stack on mobile.
- `prefers-reduced-motion` and `prefers-color-scheme` considered (light theme only for v1; document this).
- Language switch updates `lang` attribute and fonts.
- Run axe and a manual keyboard pass before submission (log findings in `bugs.md`).

## 9. Do and don't

**Do:** let the Decision Trace carry the personality; use borders instead of shadows; show reasons in plain language; label untrusted text every time; show real numbers from the report JSON; keep Bangla and English equally polished.

**Don't:** use red/green alone; add gradient washes, glassmorphism or glowing "AI" effects; use all-caps eyebrow labels; use monospace for ordinary labels; add decorative animation; put the notch on anything but Mandate cards; render document text as HTML; hand-type any benchmark number.

## 10. Asset notes

- Icons: a single outline set (e.g., Lucide) at 20px/1.75 stroke; custom SVG only for the verdict marks and the notch mask.
- Fonts: self-host Schibsted Grotesk, Hind Siliguri and IBM Plex Mono (check each licence — all are open-licence families — and record in `THIRD_PARTY.md`).
- Illustration: none needed. If an empty state needs an image, use a simple line drawing of a cheque stub with the notch.
