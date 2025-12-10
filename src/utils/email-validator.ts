/**
 * Email Validator Utility
 * Checks for disposable/fake email addresses and validates email format
 * ENHANCED: Now includes domain MX record validation
 */

import * as dns from 'dns';
import { promisify } from 'util';

const resolveMx = promisify(dns.resolveMx);

// List of known disposable/temporary email domains
const DISPOSABLE_EMAIL_DOMAINS = [
  // Common disposable email services
  'tempmail.com', 'temp-mail.org', 'guerrillamail.com', 'guerrillamail.org',
  '10minutemail.com', '10minutemail.net', 'mailinator.com', 'maildrop.cc',
  'throwaway.email', 'throwawaymail.com', 'fakeinbox.com', 'fakemailgenerator.com',
  'yopmail.com', 'yopmail.fr', 'email-temp.com', 'tempail.com',
  'dispostable.com', 'mailnesia.com', 'getnada.com', 'trashmail.com',
  'mohmal.com', 'tempinbox.com', 'sharklasers.com', 'getairmail.com',
  'tempmailaddress.com', 'tempr.email', 'discard.email', 'mailtemp.com',
  'burnermail.io', 'inboxkitten.com', 'minuteinbox.com', 'tempmailo.com',
  'mailsac.com', 'emailondeck.com', 'moakt.com', 'tmail.com',
  'mt2014.com', 'privacy.net', 'spamgourmet.com', 'mailexpire.com',
  'mailcatch.com', 'mytrashmail.com', 'hidemail.de', 'emailfake.com',
  'temp-mail.io', 'fakermail.com', '33mail.com', 'mbox.re',
  // Additional suspicious patterns
  'test.com', 'example.com', 'example.org', 'example.net',
  'mailinator.net', 'mailinator.org', 'spam.la', 'spamfree24.org',
  'trash-mail.com', 'guerrillamail.biz', 'guerrillamail.de', 'guerrillamail.net',
  'mail.tm', 'tempmailer.com', 'tempemailadress.com', 'dropmail.me',
  'cs.email', 'emkei.cz', 'anonymbox.com', 'sogetthis.com',
  // More disposable domains
  'mailshell.com', 'sneakemail.com', 'spam4.me', 'ghostmail.cc',
  'emlpro.com', 'armyspy.com', 'cuvox.de', 'dayrep.com',
  'einrot.com', 'fleckens.hu', 'gustr.com', 'jourrapide.com',
  'rhyta.com', 'superrito.com', 'teleworm.us', 'humaility.com',
  // Common fake/test domains
  'asd.com', 'asdf.com', 'qwerty.com', 'abc.com', 'xyz.com',
  'fake.com', 'test.org', 'testing.com', 'noemail.com', 'none.com',
];

// Suspicious email patterns
const SUSPICIOUS_PATTERNS = [
  /^test/i,
  /^fake/i,
  /^temp/i,
  /^spam/i,
  /^trash/i,
  /^junk/i,
  /^asdf/i,
  /^qwerty/i,
  /^xxx/i,
  /^asd$/i,
  /^abc$/i,
  /^\d{10,}@/,  // Emails starting with lots of numbers
  /^[a-z]{1,2}\d{5,}@/i,  // Pattern like a12345@
];

// Known valid email providers (skip MX check for these)
const KNOWN_VALID_DOMAINS = [
  'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 'hotmail.com',
  'outlook.com', 'live.com', 'msn.com', 'icloud.com', 'me.com', 'mac.com',
  'aol.com', 'protonmail.com', 'proton.me', 'zoho.com', 'mail.com',
  'gmx.com', 'gmx.net', 'yandex.com', 'yandex.ru', 'fastmail.com',
];

export interface EmailValidationResult {
  isValid: boolean;
  reason?: string;
  isFake?: boolean;
  isDisposable?: boolean;
  isSuspicious?: boolean;
  hasMxRecord?: boolean;
}

/**
 * Validates an email address for format and checks if it's disposable/fake
 * Synchronous version (no MX check)
 */
export function validateEmail(email: string): EmailValidationResult {
  if (!email || typeof email !== 'string') {
    return {
      isValid: false,
      reason: 'Email is required',
      isFake: true,
    };
  }

  // Basic format validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return {
      isValid: false,
      reason: 'Invalid email format',
      isFake: true,
    };
  }

  const normalizedEmail = email.toLowerCase().trim();
  const [localPart, domain] = normalizedEmail.split('@');

  // Check for disposable domains
  if (DISPOSABLE_EMAIL_DOMAINS.includes(domain)) {
    return {
      isValid: false,
      reason: 'Disposable email addresses are not allowed',
      isDisposable: true,
      isFake: true,
    };
  }

  // Check for suspicious patterns in local part
  for (const pattern of SUSPICIOUS_PATTERNS) {
    if (pattern.test(localPart)) {
      return {
        isValid: false,
        reason: 'Email appears to be fake or temporary',
        isSuspicious: true,
        isFake: true,
      };
    }
  }

  // Check for very short or very long local parts
  if (localPart.length < 2 || localPart.length > 64) {
    return {
      isValid: false,
      reason: 'Invalid email format',
      isFake: true,
    };
  }

  // Check for suspicious domain patterns
  if (domain.includes('temp') || domain.includes('fake') || domain.includes('trash')) {
    return {
      isValid: false,
      reason: 'Suspicious email domain',
      isDisposable: true,
      isFake: true,
    };
  }

  // Check for too many numbers in domain (often fake)
  const domainNumberCount = (domain.match(/\d/g) || []).length;
  if (domainNumberCount > 4) {
    return {
      isValid: false,
      reason: 'Suspicious email domain',
      isSuspicious: true,
      isFake: true,
    };
  }

  // Check for very short domains (likely fake)
  const domainParts = domain.split('.');
  if (domainParts[0].length < 3 && !KNOWN_VALID_DOMAINS.includes(domain)) {
    return {
      isValid: false,
      reason: 'Suspicious email domain',
      isSuspicious: true,
      isFake: true,
    };
  }

  return {
    isValid: true,
    isFake: false,
    isDisposable: false,
    isSuspicious: false,
  };
}

/**
 * Validates an email address with MX record check
 * Async version - use this for thorough validation
 */
export async function validateEmailWithMx(email: string): Promise<EmailValidationResult> {
  // First run basic validation
  const basicResult = validateEmail(email);
  if (!basicResult.isValid) {
    return basicResult;
  }

  const normalizedEmail = email.toLowerCase().trim();
  const domain = normalizedEmail.split('@')[1];

  // Skip MX check for known valid domains
  if (KNOWN_VALID_DOMAINS.includes(domain)) {
    return {
      ...basicResult,
      hasMxRecord: true,
    };
  }

  // Check MX records
  try {
    const mxRecords = await resolveMx(domain);
    if (!mxRecords || mxRecords.length === 0) {
      return {
        isValid: false,
        reason: 'Email domain does not have valid mail servers',
        isFake: true,
        hasMxRecord: false,
      };
    }
    return {
      ...basicResult,
      hasMxRecord: true,
    };
  } catch (error) {
    // DNS lookup failed - domain likely doesn't exist or has no MX records
    return {
      isValid: false,
      reason: 'Email domain is not valid or does not accept emails',
      isFake: true,
      hasMxRecord: false,
    };
  }
}

/**
 * Generates a unique recovery ID for account recovery
 * Format: XXXX-XXXX-XXXX-XXXX (16 alphanumeric characters)
 */
export function generateRecoveryId(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Removed confusing characters like 0, O, 1, I
  let result = '';
  
  for (let i = 0; i < 16; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
    if ((i + 1) % 4 === 0 && i < 15) {
      result += '-';
    }
  }
  
  return result;
}

/**
 * Normalizes recovery ID for comparison (removes dashes, uppercase)
 */
export function normalizeRecoveryId(recoveryId: string): string {
  return recoveryId.replace(/-/g, '').toUpperCase();
}
