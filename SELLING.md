# Redveil — Go-to-Market

## positioning

**One-liner** : "Redveil — the red team phishing framework for modern initial access.
43 techniques, SaaS-native delivery, C2 over legitimate channels, offline licensing."

**for who** : independent pentesters, boutique red teams (2-10 people), MSSP consultants
who run social engineering engagements and need modern initial access beyond
the tired email attachment.

**why not Cobalt Strike** : CS costs ~$5k+/year, is overkill for a phishing engagement,
and requires a team to operate. Redveil is a focused tool: one binary, one DB,
43 techniques ready to serve, license in 10 seconds.

## pricing

| tier | price | limits |
|------|-------|--------|
| demo | free | 2 campaigns, 5 targets, watermark on reports |
| trial | free (14 days) | 3 campaigns, 10 targets |
| pro | $49/month or $399/year | unlimited campaigns + targets |
| team | $99/month or $799/year | pro + multi-seat + priority support |

annual = 2 months free. lifetime "founder" license at $999 for the first 50 buyers.

## landing page (one page, static)

1. **hero** — banner + one-liner + CTA "Start 14-day trial"
2. **technique catalog** — live table of the 43 techniques (export JSON, render client-side)
3. **how it works** — 3-step diagram: lure → paste → beacon (screenshots)
4. **features grid** — SaaS delivery, AiTM chain, C2 over Slack/Discord, offline license
5. **pricing** — 3 cards (trial / pro / team)
6. **FAQ** — "is this legal?", "do you phone home?", "what's in the license?"
7. **footer** — EULA link, contact, Discord

## sales channels

1. **direct** — landing page + Stripe (or LemonSqueezy for simpler VAT)
2. **twitter/x** — technical threads on modern initial access (clickfix, device code
   phishing, OAuth consent abuse). link in bio. this is where pentesters hang out.
3. **discord** — a support/community server. the persona already lives there.
4. **conferences** — a lightning talk at BSides / DEF CON village on clickfix
   techniques. demos sell tools.
5. **affiliate** — 30% rev-share for pentest influencers who demo it.

## what to build next (product)

1. **ed25519 license keys** — asymmetric so even a decompiled binary can't forge keys
2. **pyinstaller one-file build** — `redveil.exe` that just works, no python needed
3. **landing page** — static HTML, hosted on Cloudflare Pages (free)
4. **telemetry-free update check** — optional `--check-update` that hits a version JSON,
   off by default (pentesters hate phone-home)
5. **demo sandbox** — a hosted instance where prospects can click through a full
   engagement without installing anything

## compliance checklist before first sale

- [ ] EULA reviewed by a local attorney
- [ ] business entity registered (SASU / EURL / LLC)
- [ ] Stripe / LemonSqueezy account with security-tools category approved
- [ ] privacy policy (even if it just says "we collect nothing")
- [ ] refund policy (14-day no-questions)
- [ ] VAT / sales tax handling (Paddle/LemonSqueezy handles this as MoR)
