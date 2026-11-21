const BLOCKED_EMAIL_DOMAINS = new Set([
  'aol.com',
  'gmail.com',
  'googlemail.com',
  'hotmail.com',
  'icloud.com',
  'live.com',
  'mail.com',
  'msn.com',
  'outlook.com',
  'pm.me',
  'proton.me',
  'protonmail.com',
  'yahoo.com',
  'yandex.com',
  'zoho.com',
]);

function getEmailDomain(email: string) {
  return email.trim().toLowerCase().split('@')[1] ?? '';
}

function isDisposableDomain(domain: string) {
  return /(^|\.)((10minutemail|guerrillamail|mailinator|tempmail|throwawaymail|yopmail)\.)/i.test(`${domain}.`);
}

export function invalidChecklistEmail(email: string): boolean {
  const domain = getEmailDomain(email)
  return BLOCKED_EMAIL_DOMAINS.has(domain) || isDisposableDomain(domain)
}