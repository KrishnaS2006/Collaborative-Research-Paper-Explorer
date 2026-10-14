import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  validateEmail,
  validatePassword,
  validateRegisterPayload,
  validateLoginPayload,
} from '../utils/validation.js';

describe('Validation Utilities', () => {
  describe('validateEmail', () => {
    it('should accept valid email addresses', () => {
      const validEmails = [
        'student@university.edu',
        'researcher.one@lab.ac.in',
        'user+tag@domain.org',
        'admin_test@sub.example.com',
      ];
      for (const email of validEmails) {
        const result = validateEmail(email);
        assert.equal(result.valid, true, `Expected ${email} to be valid`);
      }
    });

    it('should reject invalid or malformed emails', () => {
      const invalidEmails = [
        '',
        '   ',
        null,
        undefined,
        12345,
        'notanemail',
        '@nodomain.com',
        'user@.com',
        'user@domain',
        'user@domain..com',
      ];
      for (const email of invalidEmails) {
        const result = validateEmail(email);
        assert.equal(result.valid, false, `Expected ${email} to be invalid`);
        assert.ok(result.error);
      }
    });

    it('should reject emails exceeding 255 characters', () => {
      const longEmail = 'a'.repeat(250) + '@example.com';
      const result = validateEmail(longEmail);
      assert.equal(result.valid, false);
      assert.match(result.error, /exceed 255 characters/);
    });
  });

  describe('validatePassword (Strong Password Policy)', () => {
    it('should accept passwords satisfying all policy criteria', () => {
      const strongPasswords = [
        'SecureP@ssw0rd',
        'Str0ng#2026!',
        'Lab-Explorer_99',
        'A1b2C3d4!@#$',
      ];
      for (const pwd of strongPasswords) {
        const result = validatePassword(pwd);
        assert.equal(result.valid, true, `Expected password ${pwd} to be accepted`);
      }
    });

    it('should reject passwords shorter than 8 characters', () => {
      const result = validatePassword('P@ss1');
      assert.equal(result.valid, false);
      assert.match(result.error, /at least 8 characters/);
    });

    it('should reject passwords exceeding 128 characters', () => {
      const longPassword = 'P@ssw0rd1' + 'a'.repeat(125);
      const result = validatePassword(longPassword);
      assert.equal(result.valid, false);
      assert.match(result.error, /cannot exceed 128 characters/);
    });

    it('should reject passwords missing uppercase letters', () => {
      const result = validatePassword('str0ng#pass');
      assert.equal(result.valid, false);
      assert.match(result.error, /uppercase/);
    });

    it('should reject passwords missing lowercase letters', () => {
      const result = validatePassword('STR0NG#PASS');
      assert.equal(result.valid, false);
      assert.match(result.error, /lowercase/);
    });

    it('should reject passwords missing numbers', () => {
      const result = validatePassword('Strong#Pass');
      assert.equal(result.valid, false);
      assert.match(result.error, /number/);
    });

    it('should reject passwords missing special characters', () => {
      const result = validatePassword('StrongPass123');
      assert.equal(result.valid, false);
      assert.match(result.error, /special character/);
    });

    it('should reject null or non-string passwords', () => {
      assert.equal(validatePassword(null).valid, false);
      assert.equal(validatePassword('').valid, false);
      assert.equal(validatePassword(12345678).valid, false);
    });
  });

  describe('validateRegisterPayload', () => {
    const validBase = {
      full_name: 'Dr. Jane Smith',
      email: 'jane.smith@univ.edu',
      password: ' StrongPassword1! ', // includes spaces
      role: 'RESEARCHER',
    };

    it('should accept valid registration payload and preserve password without trimming', () => {
      const result = validateRegisterPayload(validBase);
      assert.equal(result.valid, true);
      assert.equal(result.sanitized.full_name, 'Dr. Jane Smith');
      assert.equal(result.sanitized.email, 'jane.smith@univ.edu');
      assert.equal(result.sanitized.password, ' StrongPassword1! '); // untouched
      assert.equal(result.sanitized.role, 'RESEARCHER');
    });

    it('should reject non-object or array payloads', () => {
      assert.equal(validateRegisterPayload(null).valid, false);
      assert.equal(validateRegisterPayload([]).valid, false);
      assert.equal(validateRegisterPayload('string').valid, false);
      assert.equal(validateRegisterPayload(123).valid, false);
    });

    it('should default role to STUDENT when role is omitted', () => {
      const payload = { ...validBase };
      delete payload.role;
      const result = validateRegisterPayload(payload);
      assert.equal(result.valid, true);
      assert.equal(result.sanitized.role, 'STUDENT');
    });

    it('should reject payload missing full_name or empty full_name', () => {
      assert.equal(validateRegisterPayload({ ...validBase, full_name: '' }).valid, false);
      assert.equal(validateRegisterPayload({ ...validBase, full_name: '   ' }).valid, false);
      assert.equal(validateRegisterPayload({ ...validBase, full_name: null }).valid, false);
    });

    it('should reject full_name exceeding 150 characters', () => {
      const result = validateRegisterPayload({ ...validBase, full_name: 'A'.repeat(151) });
      assert.equal(result.valid, false);
      assert.match(result.error, /cannot exceed 150 characters/);
    });

    it('should reject unauthorized role selection (e.g. SYSTEM_ADMIN)', () => {
      const result = validateRegisterPayload({ ...validBase, role: 'SYSTEM_ADMIN' });
      assert.equal(result.valid, false);
      assert.match(result.error, /Only STUDENT or RESEARCHER/);
    });

    it('should reject weak password in registration payload', () => {
      const result = validateRegisterPayload({ ...validBase, password: 'weak' });
      assert.equal(result.valid, false);
      assert.match(result.error, /at least 8 characters/);
    });
  });

  describe('validateLoginPayload', () => {
    it('should accept valid login payload and preserve password without trimming', () => {
      const result = validateLoginPayload({
        email: 'User@Example.com',
        password: ' password with spaces ',
      });
      assert.equal(result.valid, true);
      assert.equal(result.sanitized.email, 'user@example.com');
      assert.equal(result.sanitized.password, ' password with spaces ');
    });

    it('should reject non-object or array login payloads', () => {
      assert.equal(validateLoginPayload(null).valid, false);
      assert.equal(validateLoginPayload([]).valid, false);
      assert.equal(validateLoginPayload('test').valid, false);
    });

    it('should reject missing email or password', () => {
      assert.equal(validateLoginPayload({ password: 'pwd' }).valid, false);
      assert.equal(validateLoginPayload({ email: 'u@example.com' }).valid, false);
      assert.equal(validateLoginPayload({ email: '', password: '' }).valid, false);
    });

    it('should reject malformed email on login', () => {
      const result = validateLoginPayload({
        email: 'invalid-email-format',
        password: 'password123',
      });
      assert.equal(result.valid, false);
      assert.match(result.error, /valid email/);
    });
  });
});
