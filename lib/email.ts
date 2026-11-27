/**
 * Acc-06 / AUTH-03 email delivery through Gmail SMTP.
 *
 * Required environment variables (Google account with 2-Step Verification and
 * an app password — never the login password):
 *   GMAIL_USER        e.g. cleancsv.app@gmail.com
 *   GMAIL_APP_PASSWORD the 16-character app password
 *   FRONTEND_URL      public origin of the deployed frontend, used for links
 *
 * If the Gmail variables are missing the platform stays fully functional in
 * development: the single-use token is returned to the caller (dev-only field)
 * and nothing is sent. Nothing is faked as 'sent' when it was not.
 */
import nodemailer from "nodemailer";

/**
 * Common disposable/temporary mailbox domains. A real, reachable mailbox is
 * required because the single-use verification link is the proof of ownership —
 * a fake address can never access the platform (AUTH-03).
 */
const DISPOSABLE_DOMAINS = new Set([
  "mailinator.com", "10minutemail.com", "guerrillamail.com", "yopmail.com",
  "tempmail.com", "temp-mail.org", "throwawaymail.com", "trashmail.com",
  "getnada.com", "dispostable.com", "maildrop.cc", "sharklasers.com",
  "fakeinbox.com", "spam4.me", "grr.la", "mytemp.email", "moakt.com",
  "emailondeck.com", "burnermail.io", "33mail.com", "mailnesia.com",
  "tempr.email", "discard.email", "inboxbear.com", "tmpmail.net",
  "mailsac.com", "dropmail.me", "tmailor.com", "luxusmail.org", "1secmail.com",
]);

export function isDisposableEmail(email: string): boolean {
  const domain = email.split("@")[1]?.toLowerCase() ?? "";
  if (!domain) return true;
  return DISPOSABLE_DOMAINS.has(domain) || /(^|\.)temp(mail|orary)\./.test(domain);
}

export function emailConfigured(): boolean {
  return Boolean(process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD);
}

export function frontendUrl(): string {
  return (process.env.FRONTEND_URL ?? "http://localhost:3000").replace(/\/+$/, "");
}

function transport() {
  return nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_APP_PASSWORD,
    },
  });
}

export async function sendEmail(to: string, subject: string, text: string): Promise<boolean> {
  if (!emailConfigured()) {
    console.info(`[cleancsv] email not configured (GMAIL_USER/GMAIL_APP_PASSWORD). Would send "${subject}" to ${to.slice(0, 2)}***`);
    return false;
  }
  try {
    await transport().sendMail({
      from: `"${process.env.PLATFORM_EMAIL_NAME ?? "CleanCSV"}" <${process.env.GMAIL_USER}>`,
      to,
      subject,
      text,
    });
    return true;
  } catch (error) {
    // Delivery failure must never look like success (PRD: never report false success).
    console.error("[cleancsv] email delivery failed", error);
    return false;
  }
}

export function verificationEmail(name: string, link: string): { subject: string; text: string } {
  return {
    subject: "Verify your CleanCSV account",
    text: [
      `Hi ${name || "there"},`,
      "",
      "Welcome! Please verify your email address to continue:",
      link,
      "",
      "This single-use link expires after 24 hours. After verifying, you can submit your access request.",
      "",
      "If you did not sign up, ignore this message.",
    ].join("\n"),
  };
}

export function accessDecisionEmail(name: string, approved: boolean, reason?: string): { subject: string; text: string } {
  if (approved) {
    return {
      subject: "Your CleanCSV access request is approved",
      text: [
        `Hi ${name || "there"},`,
        "",
        "Your access request has been approved. You can sign in now:",
        frontendUrl() + "/signin",
      ].join("\n"),
    };
  }
  return {
    subject: "Your CleanCSV access request was not approved",
    text: [
      `Hi ${name || "there"},`,
      "",
      "Your access request was not approved.",
      reason ? `Reason: ${reason}` : "",
      "",
      "If you believe this is a mistake, contact support.",
    ].filter(Boolean).join("\n"),
  };
}
