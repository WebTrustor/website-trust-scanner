# Project Progress Map

**Last updated:** 2026-06-22  
**Last SHA on main:** `2726da5`

---

## 1. Current State

| Component | Status |
|-----------|--------|
| Public Trust Check → Safe Scan Runner | ✅ Complete — PR #18 |
| Product Roadmap page | ✅ Complete — PR #19 |
| Owner Scan → Safe Scan Runner | ✅ Complete — PR #20 |
| Usage Decision UX (visitor result) | ✅ Complete — PR #21 |

---

## 2. Current Product Position

### Visitor (Public)
- Scans a URL → gets Trust Score → sees Usage Decision (4 cards, 3-state verdict)
- No sensitive technical details exposed
- **Status: Near MVP**

### Site Owner
- Can register a site, verify DNS ownership, trigger a scan
- Scan results stored in DB with full `result_json`
- **No frontend for owner results yet**
- Fix Plan feature is the next required step
- **Status: Foundation done, Fix Plan missing**

### Admin
- Lead creation, shallow audit, outreach report partially built
- Not first-launch priority
- **Status: Partial — deferred**

---

## 3. Completed PRs

| PR | Title | SHA | Notes |
|----|-------|-----|-------|
| #18 | Public Trust Check → Safe Scan Runner | `f5bbc58` | Squash merged |
| #19 | Product Roadmap page | `3825518` | Squash merged |
| #20 | Owner Scan → Safe Scan Runner | `d8d8896` | Squash merged |
| #21 | Usage Decision UX for visitor result | `2726da5` | Squash merged |

---

## 4. Next Recommended Phase

**Owner Fix Plan** — frontend only, no backend changes.

Goal: after a verified owner runs a scan, show them:
- What's wrong
- Why it matters
- How to fix it
- Text ready to copy for their developer

---

## 5. Remaining Product Work

### Near-term (owner journey)
- [ ] Owner Fix Plan component (`FixPlan.tsx`)
- [ ] Copy fix instructions button (`CopyButton.tsx`)
- [ ] Owner scan result page (needs auth/API decision first)
- [ ] Before/After score comparison

### Later
- [ ] Export developer task (file/integration)
- [ ] PDF/report polish
- [ ] Scheduled re-scan improvements
- [ ] Admin lead-to-subscription flow

---

## 6. Strict Boundaries (permanent)

These constraints apply to every session unless explicitly lifted with a new decision:

- No new scanners
- No deep/intrusive scanning
- No crawling
- No port scanning
- No exposed-files enumeration
- No backend changes without explicit approval
- No auto-merge of any PR
- No outbound requests outside URL validator
- No redirects without re-validation
- No raw headers, IPs, response bodies, or exploitable details in API or UI
- No new dependencies without explicit approval
- No scheduled/admin changes without explicit approval
- No PDF changes without explicit approval

---

## 7. Decision Rule

Before every new phase, answer these four questions:

1. **كنا فين؟** Where were we before this phase started?
2. **وصلنا لفين؟** What did this phase deliver?
3. **فاضل إيه؟** What is still remaining?
4. **المرحلة القادمة هدفها إيه؟** What is the concrete goal of the next phase?

Update this file at the end of each phase before opening a PR.

---

## 8. Architecture Snapshot

```
backend/
  app/
    core/
      safe_scan_runner.py   ← run_public_trust_scan + run_owner_trust_scan
      url_validator.py      ← SSRF protection (do not modify)
      scan_policy.py        ← scan type enforcement (do not modify)
    scanners/
      trust_score.py        ← compute_trust_report → sanitized dict only
    api/v1/
      public_trust.py       ← POST /public-trust-check
      owner_scans.py        ← POST/GET /sites/{id}/scans
    schemas/
      scan.py               ← TrustReport, ChecksSummary, Recommendations
      scan_result.py        ← ScanResultSummary, ScanResultDetail

frontend/
  src/
    app/[locale]/
      page.tsx              ← home (public scan + TrustResult)
      roadmap/page.tsx      ← static roadmap
      login/ register/      ← auth pages
    components/
      TrustResult.tsx       ← visitor scan result (Usage Decision UX)
      ScanForm.tsx
      AuthForm.tsx
    messages/
      ar.json               ← Arabic translations
      en.json               ← English translations
```
