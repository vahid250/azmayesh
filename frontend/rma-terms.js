/* R&MA terms acceptance gate. This records staging consent only; no payment is enabled here. */
(function () {
  "use strict";

  function mount(metadata) {
    const cta = document.getElementById("selectedPlanCta");
    if (!cta || document.getElementById("rmaTermsAcceptance")) return;

    const panel = document.createElement("section");
    panel.id = "rmaTermsAcceptance";
    panel.className = "w-full rounded-xl border border-outline-variant/50 bg-surface-container-lowest p-3 flex flex-col gap-2 text-right";

    const heading = document.createElement("div");
    heading.className = "text-[13px] font-bold text-on-surface";
    heading.textContent = "مطالعه و تأیید شرایط استفاده";

    const status = document.createElement("p");
    status.className = "text-[11px] leading-6 text-on-surface-variant";
    status.textContent = "نسخه " + metadata.version + " — پیش‌نویس آزمایشی برای بررسی فنی؛ هنوز قانون‌نامه نهایی و لازم‌الاجرا نیست.";

    const link = document.createElement("a");
    link.href = metadata.document_path;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.className = "text-[12px] text-primary underline";
    link.textContent = "مطالعه متن کامل شرایط و سیاست بازپرداخت";

    const label = document.createElement("label");
    label.className = "flex items-start gap-2 text-[12px] leading-6 text-on-surface cursor-pointer";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.id = "rmaTermsAccepted";
    checkbox.checked = false;
    checkbox.className = "mt-1 h-4 w-4 rounded border-outline accent-primary";
    const labelText = document.createElement("span");
    labelText.textContent = "این گزینه فقط پیش‌نمایش پذیرش است و تا فعال‌شدن سفارش ذخیره نمی‌شود؛ هنگام فعال‌سازی واقعی، نسخه جاری دوباره تأیید خواهد شد.";
    label.append(checkbox, labelText);

    const feedback = document.createElement("p");
    feedback.id = "rmaTermsFeedback";
    feedback.className = "text-[11px] text-on-surface-variant";
    feedback.setAttribute("role", "status");
    feedback.textContent = "بدون علامت‌زدن این گزینه، ادامه فرایند سفارش مجاز نخواهد بود.";

    panel.append(heading, status, link, label, feedback);
    cta.parentNode.insertBefore(panel, cta);

    cta.addEventListener("click", function (event) {
      if (!checkbox.checked) {
        event.preventDefault();
        event.stopImmediatePropagation();
        feedback.textContent = "برای ادامه، ابتدا متن شرایط را مطالعه و گزینه پذیرش را علامت بزنید.";
        checkbox.focus();
        return;
      }
      // Checkout remains disabled until a real payment provider and legal review are complete.
      event.preventDefault();
      feedback.textContent = "پذیرش آزمایشی ثبت نشده است؛ درگاه پرداخت هنوز غیرفعال است و هیچ سفارش یا وجهی دریافت نمی‌شود.";
    }, true);
  }

  function start() {
    if (!window.RMAApi || typeof window.RMAApi.termsMetadata !== "function") return;
    window.RMAApi.termsMetadata().then(function (metadata) {
      if (metadata && metadata.acceptance_enabled && metadata.status === "draft_testing_only") mount(metadata);
    }).catch(function () {
      const cta = document.getElementById("selectedPlanCta");
      if (!cta || document.getElementById("rmaTermsUnavailable")) return;
      const notice = document.createElement("p");
      notice.id = "rmaTermsUnavailable";
      notice.className = "text-[11px] text-error";
      notice.textContent = "متن شرایط در دسترس نیست؛ فرایند سفارش تا بازیابی آن متوقف می‌ماند.";
      cta.parentNode.insertBefore(notice, cta);
    });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start, { once: true });
  else start();
})();
