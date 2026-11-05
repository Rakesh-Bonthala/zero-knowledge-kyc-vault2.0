process.env.NODE_ENV = 'test';
process.env.STORAGE_PROVIDER = 'mock';

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import request from 'supertest';
import mongoose from 'mongoose';
import app from '../backend/server.js';
import { config } from '../backend/config/config.js';
import { UserModel } from '../backend/models/user.model.js';
import { PendingRegistrationModel } from '../backend/models/pendingRegistration.model.js';
import { OtpChallengeModel } from '../backend/models/otpChallenge.model.js';
import { AuthService } from '../backend/services/auth.service.js';
import { EmailService } from '../backend/services/email.service.js';

describe('Authentication & Session Security Suite (Argon2id + OTP + Sessions)', () => {
  const testUser = {
    fullName: 'Jane Doe',
    username: 'janedoe_kyc',
    email: 'jane.doe@example.com',
    password: 'SecureP@ssw0rd2026!',
    confirmPassword: 'SecureP@ssw0rd2026!',
    termsAccepted: true
  };

  let pendingTargetId = null;
  let registrationOtp = null;
  let verifiedUserId = null;
  let sessionAgent = null;
  let csrfToken = null;

  before(async () => {
    sessionAgent = request.agent(app);

    if (mongoose.connection.readyState !== 1 && config.mongodb.uri) {
      await mongoose.connect(config.mongodb.uri, config.mongodb.options);
    }

    // Clean up test records
    await UserModel.deleteMany({ emailNormalized: testUser.email.toLowerCase() });
    await PendingRegistrationModel.deleteMany({ emailNormalized: testUser.email.toLowerCase() });
    await OtpChallengeModel.deleteMany({ email: testUser.email.toLowerCase() });
  });

  after(async () => {
    if (mongoose.connection && mongoose.connection.readyState === 1) {
      await UserModel.deleteMany({ emailNormalized: testUser.email.toLowerCase() });
      await PendingRegistrationModel.deleteMany({ emailNormalized: testUser.email.toLowerCase() });
      await OtpChallengeModel.deleteMany({ email: testUser.email.toLowerCase() });
      await mongoose.disconnect();
    }
  });

  it('GET /api/auth/csrf-token generates valid CSRF token and cookie', async () => {
    const res = await sessionAgent.get('/api/auth/csrf-token');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.ok(res.body.csrfToken);
    csrfToken = res.body.csrfToken;
  });

  it('POST /api/auth/register fails when passwords do not match', async () => {
    const res = await sessionAgent
      .post('/api/auth/register')
      .set('X-CSRF-Token', csrfToken)
      .send({
        ...testUser,
        confirmPassword: 'MismatchPassword123!'
      });

    assert.strictEqual(res.status, 400);
    assert.strictEqual(res.body.success, false);
    assert.ok(res.body.error.includes('do not match'));
  });

  it('POST /api/auth/register fails on weak password (< 10 chars, no special char)', async () => {
    const res = await sessionAgent
      .post('/api/auth/register')
      .set('X-CSRF-Token', csrfToken)
      .send({
        ...testUser,
        password: 'weak',
        confirmPassword: 'weak'
      });

    assert.strictEqual(res.status, 400);
    assert.strictEqual(res.body.success, false);
    assert.ok(res.body.error.includes('at least 10 characters'));
  });

  it('POST /api/auth/register succeeds, creates pending record and dispatches email OTP', async () => {
    const res = await sessionAgent
      .post('/api/auth/register')
      .set('X-CSRF-Token', csrfToken)
      .send(testUser);

    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.body.success, true);
    assert.ok(res.body.targetId);
    assert.strictEqual(res.body.purpose, 'register');

    pendingTargetId = res.body.targetId;

    // Verify PendingRegistration was saved with Argon2id hash (starts with $argon2id$)
    const pendingDoc = await PendingRegistrationModel.findById(pendingTargetId);
    assert.ok(pendingDoc);
    assert.strictEqual(pendingDoc.usernameNormalized, testUser.username.toLowerCase());
    assert.ok(pendingDoc.passwordHash.startsWith('$argon2id$'), 'Password must be hashed with Argon2id');

    // Retrieve the active challenge and derive the OTP to simulate user checking email
    const challenge = await OtpChallengeModel.findOne({
      targetId: pendingTargetId,
      purpose: 'register',
      used: false
    });
    assert.ok(challenge);
    assert.ok(challenge.otpHmac);

    // In test environment, retrieve the generated OTP
    registrationOtp = AuthService.lastGeneratedOtp;
    if (!registrationOtp) {
      for (let testNum = 100000; testNum <= 999999; testNum++) {
        if (AuthService.verifyOtpHmac(String(testNum), pendingTargetId, 'register', challenge.otpHmac)) {
          registrationOtp = String(testNum);
          break;
        }
      }
    }
    assert.ok(registrationOtp, 'Valid 6-digit OTP should be verifiable against HMAC');
  });

  it('POST /api/auth/verify-registration-otp fails with incorrect OTP', async () => {
    const res = await sessionAgent
      .post('/api/auth/verify-registration-otp')
      .set('X-CSRF-Token', csrfToken)
      .send({
        targetId: pendingTargetId,
        otp: '000000'
      });

    assert.strictEqual(res.status, 400);
    assert.strictEqual(res.body.success, false);
    assert.ok(res.body.error.includes('Invalid verification code'));
  });

  it('POST /api/auth/verify-registration-otp succeeds with correct OTP and creates verified User', async () => {
    const res = await sessionAgent
      .post('/api/auth/verify-registration-otp')
      .set('X-CSRF-Token', csrfToken)
      .send({
        targetId: pendingTargetId,
        otp: registrationOtp
      });

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.ok(res.body.user);

    verifiedUserId = res.body.user.id;

    // Verify user exists in UserModel
    const userDoc = await UserModel.findById(verifiedUserId);
    assert.ok(userDoc);
    assert.strictEqual(userDoc.isEmailVerified, true);
    assert.strictEqual(userDoc.accountStatus, 'active');

    // Verify pending registration was cleaned up
    const pendingStillExists = await PendingRegistrationModel.findById(pendingTargetId);
    assert.strictEqual(pendingStillExists, null);
  });

  it('POST /api/auth/register rejects duplicate username or email', async () => {
    const res = await sessionAgent
      .post('/api/auth/register')
      .set('X-CSRF-Token', csrfToken)
      .send(testUser);

    assert.strictEqual(res.status, 409);
    assert.strictEqual(res.body.success, false);
  });

  it('POST /api/auth/login rejects incorrect password (constant-time check)', async () => {
    const res = await sessionAgent
      .post('/api/auth/login')
      .set('X-CSRF-Token', csrfToken)
      .send({
        identifier: testUser.username,
        password: 'WrongPassword!2026'
      });

    assert.strictEqual(res.status, 401);
    assert.strictEqual(res.body.success, false);
    assert.strictEqual(res.body.error, 'Invalid username/email or password.');
  });

  it('POST /api/auth/login succeeds with valid credentials and triggers Login OTP', async () => {
    const res = await sessionAgent
      .post('/api/auth/login')
      .set('X-CSRF-Token', csrfToken)
      .send({
        identifier: testUser.username,
        password: testUser.password
      });

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.requiresOtp, true);
    assert.strictEqual(res.body.purpose, 'login');

    const challenge = await OtpChallengeModel.findOne({
      targetId: verifiedUserId,
      purpose: 'login',
      used: false
    });
    assert.ok(challenge);

    let loginOtp = AuthService.lastGeneratedOtp;
    if (!loginOtp) {
      for (let testNum = 100000; testNum <= 999999; testNum++) {
        if (AuthService.verifyOtpHmac(String(testNum), verifiedUserId, 'login', challenge.otpHmac)) {
          loginOtp = String(testNum);
          break;
        }
      }
    }

    // Verify Login OTP
    const verifyRes = await sessionAgent
      .post('/api/auth/verify-login-otp')
      .set('X-CSRF-Token', csrfToken)
      .send({
        targetId: verifiedUserId,
        otp: loginOtp
      });

    assert.strictEqual(verifyRes.status, 200);
    assert.strictEqual(verifyRes.body.success, true);
    assert.strictEqual(verifyRes.body.user.username, testUser.username);

    // Refresh CSRF token since session was regenerated on login
    const csrfRes = await sessionAgent.get('/api/auth/csrf-token');
    if (csrfRes.body.csrfToken) {
      csrfToken = csrfRes.body.csrfToken;
    }
  });

  it('GET /api/auth/me returns authenticated profile when session is established', async () => {
    const res = await sessionAgent.get('/api/auth/me');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.authenticated, true);
    assert.strictEqual(res.body.user.username, testUser.username);
  });

  it('GET /api/vault/documents allows authenticated session access', async () => {
    const res = await sessionAgent.get('/api/vault/documents');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.ok(Array.isArray(res.body.documents));
  });

  it('GET /api/vault/documents rejects unauthenticated request without session', async () => {
    const unauthenticatedAgent = request(app);
    const res = await unauthenticatedAgent.get('/api/vault/documents');
    assert.strictEqual(res.status, 401);
    assert.strictEqual(res.body.code, 'UNAUTHENTICATED');
  });

  it('POST /api/auth/logout terminates session and clears cookie', async () => {
    const res = await sessionAgent
      .post('/api/auth/logout')
      .set('X-CSRF-Token', csrfToken);

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);

    // Verify me is now unauthenticated
    const meRes = await sessionAgent.get('/api/auth/me');
    assert.strictEqual(meRes.body.authenticated, false);
  });
});

