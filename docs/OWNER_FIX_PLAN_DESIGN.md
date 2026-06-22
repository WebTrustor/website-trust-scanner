# Owner Fix Plan — Design Document

**Phase:** Product Phase 2  
**Scope:** Frontend only — no backend, no API, no scanners  
**Status:** Design approved, implementation pending review

---

## 1. المشكلة التي نحلها

صاحب الموقع الذي يشغّل scan يحصل حالياً على `trust_score` فقط.
هذا غير كافٍ لأنه يحتاج:

- **ما المشكلة تحديداً؟**
- **لماذا تهمه هذه المشكلة؟** (التأثير على المستخدمين والثقة)
- **كيف يصلحها؟** (خطوات عملية واضحة)
- **ماذا يرسل للمطور؟** (نص جاهز للنسخ)

الهدف: تحويل Score الرقمي إلى خطة عمل قابلة للتنفيذ.

---

## 2. البيانات المتاحة حالياً في `result_json`

`result_json` هو dict مطابق لـ `TrustReport` من `backend/app/schemas/scan.py`.  
يُنتج بواسطة `compute_trust_report()` في `backend/app/scanners/trust_score.py`.

```
result_json = {
  "domain":      str,                           # e.g. "example.com"
  "trust_score": int,                           # 0–100
  "trust_level": "low" | "medium" | "good" | "high",

  "checks": {
    "https":              bool,                 # HTTPS available
    "ssl_valid":          bool,                 # SSL certificate valid
    "ssl_expiry_warning": bool,                 # expires within ~30 days
    "hsts":               bool,                 # Strict-Transport-Security present
    "headers_score":      int,                  # e.g. 3
    "headers_max":        int,                  # always 5
    "reputation":         "clean" | "flagged" | "unknown"
  },

  "recommendations": {
    "safe_to_browse":  bool,
    "safe_for_email":  bool,
    "safe_for_account": bool,
    "safe_for_payment": bool
  },

  "warnings": ["ssl_expiry_soon"]               # list of warning keys, may be empty
}
```

**ملاحظة:** `result_json` لا يحتوي IPs، raw headers، cert details، server version،
response bodies. آمن للعرض المباشر بعد استخراج الحقول المسموحة فقط.

---

## 3. ما الذي يمكن اشتقاقه بأمان (Fix Plan items)

كل بند يُشتق بـ boolean condition واحدة من `checks`:

| Issue Key | الشرط | الأولوية |
|-----------|-------|----------|
| `no_https` | `checks.https === false` | عالية جداً |
| `ssl_invalid` | `checks.ssl_valid === false` | عالية جداً |
| `ssl_expiry_soon` | `checks.ssl_expiry_warning === true` | عالية |
| `no_hsts` | `checks.hsts === false && checks.https === true` | متوسطة |
| `weak_headers` | `checks.headers_score < checks.headers_max` | متوسطة |
| `bad_reputation` | `checks.reputation === "flagged"` | تحذير (خاص) |

**منطق الترتيب:**
1. `flagged` reputation يظهر أولاً كتحذير منفصل
2. High priority issues (https, ssl) تظهر قبل medium
3. إذا لم توجد مشاكل: رسالة إيجابية واحدة

---

## 4. ما الذي لا يجب عرضه

| ممنوع | السبب |
|-------|-------|
| عناوين IP | SSRF risk، معلومات استضافة |
| Raw HTTP headers | قد تكشف server version، config |
| Response body | معلومات حساسة |
| Server version | معلومات استغلال |
| SSL cert details (issuer, subject, serial) | fingerprinting |
| DNS records كاملة | infrastructure mapping |
| خطوات استغلال | out of scope كلياً |
| لغة مثل "مخترق" / "خطير جداً" / "آمن 100%" | مبالغة أو ادعاء مضلل |

النص المعروض **دائماً** من translations فقط — لا dynamic strings من الـ API.

---

## 5. شكل Fix Plan المقترح

### لكل Issue:

```
┌─ [أولوية: عالية] ─────────────────────────────────────────┐
│ العنوان: لا يوجد اتصال HTTPS                              │
│                                                            │
│ لماذا يهم؟                                                 │
│   الاتصال بين المتصفح والموقع غير مشفر. قد يؤثر ذلك      │
│   على ثقة الزوار ويُظهر تحذيرات في بعض المتصفحات.        │
│                                                            │
│ كيف تصلحها؟                                               │
│   فعّل شهادة SSL من لوحة تحكم الاستضافة أو من خلال       │
│   مزوّد الخدمة. يُنصح باستخدام Let's Encrypt إن أمكن.    │
│                                                            │
│ نص للمطور:                                                 │
│   ┌──────────────────────────────┐                         │
│   │ Enable HTTPS (SSL) on the   │ [ نسخ ]                 │
│   │ server. Redirect all HTTP   │                          │
│   │ traffic to HTTPS.           │                          │
│   └──────────────────────────────┘                         │
└────────────────────────────────────────────────────────────┘
```

### Priority Badge Colors:
- عالية جداً: أحمر (`text-red-400`, `border-red-800/50`, `bg-red-950/20`)
- عالية: برتقالي (`text-orange-400`, `border-orange-800/50`, `bg-orange-950/20`)
- متوسطة: أصفر (`text-amber-400`, `border-amber-800/50`, `bg-amber-950/20`)
- تحذير سمعة: بنفسجي (`text-purple-400`, `border-purple-800/50`, `bg-purple-950/20`)

### لا مشاكل:
```
✓ لم نكتشف مشاكل واضحة في هذا الفحص.
  راجع التفاصيل في قسم فحوصات الأمان أدناه.
```

---

## 6. Copy Instructions — ضوابط السلامة

النص المنسوخ يجب أن يكون:

- ✅ من translations فقط (ثوابت)
- ✅ بالإنجليزية (للمطور) — نسخة واحدة محددة مسبقاً
- ✅ يذكر المشكلة والحل فقط
- ❌ بدون domain name
- ❌ بدون IP
- ❌ بدون raw header values
- ❌ بدون أي دليل تقني خام (raw evidence)
- ❌ بدون أسرار أو tokens
- ❌ بدون خطوات استغلال
- ❌ بدون ادعاءات مطلقة

**مثال نص للنسخ (EN):**
```
[HIGH] No HTTPS detected
Why: The connection between browser and server is unencrypted.
     Visitors may see browser security warnings.
How to fix: Enable an SSL certificate via your hosting provider
            and redirect all HTTP traffic to HTTPS.
            Consider using Let's Encrypt if supported.
Note: Verify configuration with your developer before deploying.
```

**ما لا يجب أن يحتوي:**
```
❌ "Your server at 192.168.1.1 is missing..."
❌ "Server: Apache/2.4.51 is vulnerable..."
❌ "Your site has been compromised..."
❌ "100% secure after this fix"
```

---

## 7. Frontend Implementation Options

### Option A: FixPlan component فقط (مُوصى به الآن)
- إنشاء `FixPlan.tsx` كـ server component يستقبل props محددة
- إنشاء `CopyButton.tsx` كـ client component منفصل للنسخ
- **لا صفحة جديدة**، لا data fetching، لا auth
- يُربط لاحقاً عندما يُقرر شكل owner dashboard

**المزايا:**
- آمن تماماً — لا API، لا auth
- قابل للاختبار بشكل مستقل (mock props)
- يمكن عرضه في Storybook أو page بسيطة مستقبلاً

### Option B: صفحة scan detail كاملة
- إنشاء `/[locale]/dashboard/sites/[siteId]/scans/[scanId]/page.tsx`
- تجلب `ScanResultDetail` من API
- تعرض Trust Score + Fix Plan

**العوائق الحالية:**
- لا auth middleware مُكوَّن في frontend بعد
- لا `useSession` أو API helpers موجودة
- لا dashboard layout
- يفتح بابًا لـ data fetching قبل أن تُحدَّد معمارية auth

**الخلاصة:** Option B يحتاج قرارات معمارية إضافية غير جاهزة.

---

## 8. التوصية

**Option A — FixPlan component فقط.**

الأسباب:
1. لا يحتاج قرارات auth/dashboard غير جاهزة
2. البيانات تصل لاحقاً عبر props من أي مكان
3. النطاق محدود وقابل للمراجعة بدون مخاطر
4. يُنجز القيمة الأساسية (Fix Plan text + Copy) فوراً

---

## 9. Acceptance Criteria

قبل merge أي PR يتعلق بـ Fix Plan، يجب أن تتحقق جميع الشروط:

- [ ] لا backend changes
- [ ] لا API جديد
- [ ] لا data fetching داخل المكوّن
- [ ] لا scanners
- [ ] لا PDF
- [ ] لا Export file الآن
- [ ] لا تفاصيل حساسة معروضة أو منسوخة
- [ ] Translations موجودة في ar.json + en.json
- [ ] `CopyButton.tsx` منفصل، `'use client'` فقط فيه
- [ ] `FixPlan.tsx` يستقبل interface ضيقة (الحقول المسموحة فقط)
- [ ] `tsc --noEmit` نظيف بدون أخطاء
- [ ] لا `any` في TypeScript
- [ ] لغة حذرة: يُنصح / قد يساعد / راجع مع المطور
- [ ] لا: مخترق / خطير جداً / آمن 100% / مضمون

---

## 10. Interface المسموحة للـ FixPlan Component

```typescript
interface FixPlanChecks {
  https: boolean
  ssl_valid: boolean
  ssl_expiry_warning: boolean
  hsts: boolean
  headers_score: number
  headers_max: number
  reputation: 'clean' | 'flagged' | 'unknown'
}
```

فقط هذه الحقول — لا `domain`، لا `recommendations`، لا `trust_score` (يُعرض منفصلاً في البطاقة الأخرى).

---

## 11. ملاحظات تنفيذية

- `FixPlan.tsx` → Server Component (لا يحتاج state)
- `CopyButton.tsx` → Client Component (`'use client'`) — يستقبل `text: string`
- النص المنسوخ: دائماً بالإنجليزية للمطور، يُبنى من translations
- Clipboard API: `navigator.clipboard.writeText(text)` مع fallback لا شيء (لا تكسر التجربة)
- زر النسخ: يعرض "تم النسخ!" / "Copied!" لمدة 2 ثانية ثم يعود
- لا `setTimeout` طويل، لا animations معقدة
