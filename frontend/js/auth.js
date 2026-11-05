/**
 * Auth Client Module for Zero-Knowledge KYC Vault
 * Handles: CSRF tokens, registration, login, OTP verification,
 * password reset, and session management.
 *
 * ZERO-KNOWLEDGE COMPLIANCE:
 * - This module NEVER touches encryption passphrase, keys, or crypto workflows.
 * - Auth credentials (login password) are completely independent of encryption passphrase.
 */

const AUTH_API = '/api/auth';

// ─── CSRF Token Management ─────────────────────────────────────
let _csrfToken = null;

async function getCsrfToken() {
  try {
    const res = await fetch(`${AUTH_API}/csrf-token`, { credentials: 'include' });
    const data = await res.json();
    if (data.success && data.csrfToken) {
      _csrfToken = data.csrfToken;
    }
    return _csrfToken;
  } catch (e) {
    console.error('[Auth] Failed to fetch CSRF token:', e.message);
    return null;
  }
}

async function ensureCsrfToken() {
  if (!_csrfToken) await getCsrfToken();
  return _csrfToken;
}

/**
 * Wrapper for authenticated/CSRF-protected POST requests.
 */
async function authPost(endpoint, body) {
  const token = await ensureCsrfToken();
  const res = await fetch(`${AUTH_API}${endpoint}`, {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': token || ''
    },
    body: JSON.stringify(body)
  });
  const data = await res.json();
  // Refresh CSRF token after session-changing operations
  if (endpoint === '/verify-login-otp' || endpoint === '/logout' || endpoint === '/reset-password') {
    await getCsrfToken();
  }
  return { status: res.status, data };
}

/**
 * Check if user is currently authenticated.
 */
async function checkAuth() {
  try {
    const res = await fetch(`${AUTH_API}/me`, { credentials: 'include' });
    const data = await res.json();
    return data.authenticated ? data.user : null;
  } catch {
    return null;
  }
}

// ─── UI Helpers ─────────────────────────────────────────────────

function showAlert(elementId, message, type = 'error') {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.textContent = message;
  el.className = `auth-alert auth-alert-${type}`;
  el.style.display = 'block';
}

function hideAlert(elementId) {
  const el = document.getElementById(elementId);
  if (el) el.style.display = 'none';
}

function setLoading(btnId, loading, originalText = 'Submit') {
  const btn = document.getElementById(btnId);
  if (!btn) return;
  btn.disabled = loading;
  if (loading) {
    btn.innerHTML = `<span class="spinner"></span> Please wait...`;
  } else {
    btn.textContent = originalText;
  }
}

function showToast(message, type = 'info', duration = 4000) {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  const icons = { success: '✓', error: '✕', warning: '⚠', info: 'ℹ' };
  toast.innerHTML = `
    <div class="toast-icon">${icons[type] || 'ℹ'}</div>
    <div class="toast-body">${escapeHTML(message)}</div>
    <button class="toast-close" aria-label="Close">&times;</button>
  `;
  toast.querySelector('.toast-close').addEventListener('click', () => toast.remove());
  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.add('fade-out');
    setTimeout(() => toast.remove(), 400);
  }, duration);
}

function escapeHTML(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

// ─── Password Strength Indicator ────────────────────────────────

function evaluatePasswordStrength(password) {
  if (!password) return { score: 0, label: '', className: '' };
  let score = 0;
  if (password.length >= 10) score++;
  if (password.length >= 14) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^a-zA-Z0-9]/.test(password)) score++;

  if (score <= 1) return { score: 20, label: 'Weak', className: 'strength-weak' };
  if (score === 2) return { score: 40, label: 'Fair', className: 'strength-fair' };
  if (score === 3) return { score: 65, label: 'Good', className: 'strength-good' };
  return { score: 90, label: 'Strong', className: 'strength-strong' };
}

function updatePasswordStrength(inputId, fillId, textId) {
  const input = document.getElementById(inputId);
  const fill = document.getElementById(fillId);
  const text = document.getElementById(textId);
  if (!input || !fill || !text) return;

  input.addEventListener('input', () => {
    const { score, label, className } = evaluatePasswordStrength(input.value);
    fill.style.width = `${score}%`;
    fill.className = `password-strength-fill ${className}`;
    text.textContent = label ? `Strength: ${label}` : '';
  });
}

// ─── OTP Box Behavior ───────────────────────────────────────────

function initOtpBoxes(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const boxes = container.querySelectorAll('.otp-box');

  boxes.forEach((box, idx) => {
    box.addEventListener('input', (e) => {
      const val = e.target.value.replace(/\D/g, '');
      e.target.value = val.slice(0, 1);
      if (val && idx < boxes.length - 1) {
        boxes[idx + 1].focus();
      }
      updateOtpBoxStyles(boxes);
    });

    box.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !e.target.value && idx > 0) {
        boxes[idx - 1].focus();
        boxes[idx - 1].value = '';
      }
    });

    // Paste support: distribute digits across all boxes
    box.addEventListener('paste', (e) => {
      e.preventDefault();
      const pasted = (e.clipboardData.getData('text') || '').replace(/\D/g, '').slice(0, 6);
      for (let i = 0; i < boxes.length; i++) {
        boxes[i].value = pasted[i] || '';
      }
      const lastFilled = Math.min(pasted.length, boxes.length) - 1;
      if (lastFilled >= 0 && lastFilled < boxes.length - 1) {
        boxes[lastFilled + 1].focus();
      } else if (lastFilled === boxes.length - 1) {
        boxes[lastFilled].focus();
      }
      updateOtpBoxStyles(boxes);
    });
  });

  // Focus first box
  if (boxes[0]) boxes[0].focus();
}

function updateOtpBoxStyles(boxes) {
  boxes.forEach(b => {
    b.classList.toggle('filled', !!b.value);
  });
}

function getOtpValue(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return '';
  return Array.from(container.querySelectorAll('.otp-box')).map(b => b.value).join('');
}

function clearOtpBoxes(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.querySelectorAll('.otp-box').forEach(b => { b.value = ''; b.classList.remove('filled'); });
  const first = container.querySelector('.otp-box');
  if (first) first.focus();
}

// ─── Resend Countdown ───────────────────────────────────────────

let resendTimer = null;

function startResendCountdown(seconds = 60) {
  const btn = document.getElementById('resend-otp-btn');
  const span = document.getElementById('resend-countdown');
  if (!btn) return;

  let remaining = seconds;
  btn.disabled = true;
  if (span) span.textContent = remaining;
  btn.innerHTML = `Resend code in <span id="resend-countdown">${remaining}</span>s`;

  clearInterval(resendTimer);
  resendTimer = setInterval(() => {
    remaining--;
    const s = document.getElementById('resend-countdown');
    if (s) s.textContent = remaining;
    if (remaining <= 0) {
      clearInterval(resendTimer);
      btn.disabled = false;
      btn.textContent = 'Resend verification code';
    }
  }, 1000);
}

// ─── Show/Hide Password Toggle ──────────────────────────────────

function initPasswordToggles() {
  document.querySelectorAll('.btn-toggle-vis[data-target]').forEach(btn => {
    btn.addEventListener('click', () => {
      const input = document.getElementById(btn.dataset.target);
      if (!input) return;
      const isPassword = input.type === 'password';
      input.type = isPassword ? 'text' : 'password';
      btn.textContent = isPassword ? 'Hide' : 'Show';
    });
  });
}

// ─── OTP Flow State (stored in sessionStorage for page navigation) ────

function saveOtpFlowState(data) {
  try {
    sessionStorage.setItem('zk_otp_flow', JSON.stringify(data));
  } catch { }
}

function getOtpFlowState() {
  try {
    const raw = sessionStorage.getItem('zk_otp_flow');
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function clearOtpFlowState() {
  try {
    sessionStorage.removeItem('zk_otp_flow');
  } catch { }
}

// ─── Page-Specific Handlers ─────────────────────────────────────

function currentPage() {
  const path = window.location.pathname;
  if (path.includes('register')) return 'register';
  if (path.includes('otp')) return 'otp';
  if (path.includes('forgot-password')) return 'forgot';
  if (path.includes('reset-password')) return 'reset';
  if (path.includes('login')) return 'login';
  if (path === '/' || path.includes('index')) return 'dashboard';
  return 'login';
}

// ── LOGIN ─────────────────────────────────────────────────────

function initLoginPage() {
  const form = document.getElementById('login-form');
  if (!form) return;

  // If already authenticated, redirect to dashboard
  checkAuth().then(user => {
    if (user) window.location.href = '/';
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert('login-error');
    hideAlert('login-success');

    const identifier = document.getElementById('login-identifier')?.value?.trim();
    const password = document.getElementById('login-password')?.value;

    if (!identifier || !password) {
      showAlert('login-error', 'Please enter your username/email and password.');
      return;
    }

    setLoading('login-submit-btn', true, 'Sign In');

    try {
      const { status, data } = await authPost('/login', { identifier, password });

      if (data.success && data.requiresOtp) {
        // Save flow state and redirect to OTP page
        saveOtpFlowState({
          targetId: data.targetId,
          challengeId: data.challengeId,
          emailMasked: data.emailMasked,
          purpose: 'login',
          expiresInSeconds: data.expiresInSeconds,
          devPreviewUrl: data.devPreviewUrl
        });
        window.location.href = '/otp.html';
      } else {
        showAlert('login-error', data.error || 'Login failed. Please try again.');
      }
    } catch (err) {
      showAlert('login-error', 'Network error. Please check your connection.');
    } finally {
      setLoading('login-submit-btn', false, 'Sign In');
    }
  });
}

// ── REGISTER ──────────────────────────────────────────────────

function initRegisterPage() {
  const form = document.getElementById('register-form');
  if (!form) return;

  checkAuth().then(user => {
    if (user) window.location.href = '/';
  });

  updatePasswordStrength('reg-password', 'password-strength-fill', 'password-strength-text');

  // Username validation hint
  const usernameInput = document.getElementById('reg-username');
  const usernameHint = document.getElementById('username-hint');
  if (usernameInput && usernameHint) {
    usernameInput.addEventListener('input', () => {
      const val = usernameInput.value.trim();
      if (val && !/^[a-zA-Z0-9_.-]+$/.test(val)) {
        usernameHint.textContent = 'Only letters, numbers, underscores, dots, hyphens allowed';
        usernameHint.style.display = 'block';
        usernameHint.style.color = 'var(--accent-rose)';
      } else if (val && val.length < 3) {
        usernameHint.textContent = 'Username must be at least 3 characters';
        usernameHint.style.display = 'block';
        usernameHint.style.color = 'var(--accent-amber)';
      } else {
        usernameHint.style.display = 'none';
      }
    });
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert('register-error');
    hideAlert('register-success');

    const fullName = document.getElementById('reg-fullname')?.value?.trim();
    const username = document.getElementById('reg-username')?.value?.trim();
    const email = document.getElementById('reg-email')?.value?.trim();
    const password = document.getElementById('reg-password')?.value;
    const confirmPassword = document.getElementById('reg-confirm-password')?.value;
    const termsAccepted = document.getElementById('reg-terms')?.checked;

    // Client-side validations
    if (!fullName || !username || !email || !password || !confirmPassword) {
      showAlert('register-error', 'All fields are required.');
      return;
    }

    if (username.length < 3 || username.length > 30) {
      showAlert('register-error', 'Username must be between 3 and 30 characters.');
      return;
    }

    if (!/^[a-zA-Z0-9_.-]+$/.test(username)) {
      showAlert('register-error', 'Username may only contain letters, numbers, underscores, dots, or hyphens.');
      return;
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      showAlert('register-error', 'Please enter a valid email address.');
      return;
    }

    if (password.length < 10) {
      showAlert('register-error', 'Password must be at least 10 characters.');
      return;
    }

    if (password !== confirmPassword) {
      showAlert('register-error', 'Passwords do not match.');
      return;
    }

    if (!termsAccepted) {
      showAlert('register-error', 'You must accept the Terms of Service and Privacy Policy.');
      return;
    }

    setLoading('register-submit-btn', true, 'Create Account');

    try {
      const { status, data } = await authPost('/register', {
        fullName,
        username,
        email,
        password,
        confirmPassword,
        termsAccepted: true
      });

      if (data.success) {
        saveOtpFlowState({
          targetId: data.targetId,
          challengeId: data.challengeId,
          emailMasked: data.emailMasked,
          purpose: 'register',
          expiresInSeconds: data.expiresInSeconds,
          devPreviewUrl: data.devPreviewUrl
        });
        window.location.href = '/otp.html';
      } else {
        showAlert('register-error', data.error || 'Registration failed.');
      }
    } catch (err) {
      showAlert('register-error', 'Network error. Please check your connection.');
    } finally {
      setLoading('register-submit-btn', false, 'Create Account');
    }
  });
}

// ── OTP VERIFICATION ──────────────────────────────────────────

function initOtpPage() {
  const flow = getOtpFlowState();
  if (!flow || !flow.targetId || !flow.purpose) {
    // No OTP flow in progress, redirect back
    window.location.href = '/login.html';
    return;
  }

  // Update UI with flow info
  const subtitle = document.getElementById('otp-subtitle');
  const emailMasked = document.getElementById('otp-email-masked');

  if (flow.purpose === 'register') {
    if (subtitle) subtitle.textContent = 'Enter the code sent to verify your email';
  } else if (flow.purpose === 'login') {
    if (subtitle) subtitle.textContent = 'Enter the code sent to complete sign-in';
  }

  if (emailMasked) emailMasked.textContent = flow.emailMasked || 'your email';

  // Show dev preview URL if available
  if (flow.devPreviewUrl) {
    const container = document.getElementById('dev-preview-container');
    const link = document.getElementById('dev-preview-link');
    if (container && link) {
      link.href = flow.devPreviewUrl;
      container.style.display = 'block';
    }
  }

  initOtpBoxes('otp-boxes');
  startResendCountdown(60);

  // OTP form submission
  const form = document.getElementById('otp-form');
  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      hideAlert('otp-error');

      const otp = getOtpValue('otp-boxes');
      if (otp.length !== 6) {
        showAlert('otp-error', 'Please enter all 6 digits.');
        return;
      }

      setLoading('otp-submit-btn', true, 'Verify Code');

      try {
        const endpoint = flow.purpose === 'register'
          ? '/verify-registration-otp'
          : '/verify-login-otp';

        const { status, data } = await authPost(endpoint, {
          targetId: flow.targetId,
          otp
        });

        if (data.success) {
          clearOtpFlowState();

          if (flow.purpose === 'register') {
            showAlert('otp-success', 'Account verified! Redirecting to sign in...', 'success');
            setTimeout(() => { window.location.href = '/login.html'; }, 1500);
          } else {
            // Login OTP verified — session is now active
            showAlert('otp-success', 'Signed in successfully! Redirecting...', 'success');
            setTimeout(() => { window.location.href = '/'; }, 1000);
          }
        } else {
          showAlert('otp-error', data.error || 'Invalid code. Please try again.');
          clearOtpBoxes('otp-boxes');
        }
      } catch (err) {
        showAlert('otp-error', 'Network error. Please try again.');
      } finally {
        setLoading('otp-submit-btn', false, 'Verify Code');
      }
    });
  }

  // Resend OTP
  const resendBtn = document.getElementById('resend-otp-btn');
  if (resendBtn) {
    resendBtn.addEventListener('click', async () => {
      hideAlert('otp-error');
      hideAlert('otp-success');
      resendBtn.disabled = true;

      try {
        const { status, data } = await authPost('/resend-otp', {
          targetId: flow.targetId,
          purpose: flow.purpose
        });

        if (data.success) {
          showToast('New verification code sent!', 'success');
          startResendCountdown(60);

          // Update dev preview URL
          if (data.devPreviewUrl) {
            flow.devPreviewUrl = data.devPreviewUrl;
            saveOtpFlowState(flow);
            const link = document.getElementById('dev-preview-link');
            const container = document.getElementById('dev-preview-container');
            if (link) link.href = data.devPreviewUrl;
            if (container) container.style.display = 'block';
          }

          clearOtpBoxes('otp-boxes');
        } else {
          showAlert('otp-error', data.error || 'Failed to resend code.');
          startResendCountdown(10);
        }
      } catch (err) {
        showAlert('otp-error', 'Network error. Please try again.');
        startResendCountdown(10);
      }
    });
  }
}

// ── FORGOT PASSWORD ───────────────────────────────────────────

function initForgotPage() {
  const form = document.getElementById('forgot-form');
  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert('forgot-error');
    hideAlert('forgot-success');

    const email = document.getElementById('forgot-email')?.value?.trim();
    if (!email) {
      showAlert('forgot-error', 'Please enter your email address.');
      return;
    }

    setLoading('forgot-submit-btn', true, 'Send Reset Code');

    try {
      const { status, data } = await authPost('/forgot-password', { email });

      if (data.success) {
        // Always show generic success
        showAlert('forgot-success', data.message || 'If an account exists, a reset code has been sent.', 'success');

        // If the response includes a targetId, user exists -> redirect to reset page
        if (data.targetId) {
          saveOtpFlowState({
            targetId: data.targetId,
            challengeId: data.challengeId,
            emailMasked: data.emailMasked,
            purpose: 'reset',
            expiresInSeconds: data.expiresInSeconds,
            devPreviewUrl: data.devPreviewUrl
          });
          setTimeout(() => { window.location.href = '/reset-password.html'; }, 1500);
        }
      } else {
        showAlert('forgot-error', data.error || 'Request failed.');
      }
    } catch (err) {
      showAlert('forgot-error', 'Network error. Please try again.');
    } finally {
      setLoading('forgot-submit-btn', false, 'Send Reset Code');
    }
  });
}

// ── RESET PASSWORD ────────────────────────────────────────────

function initResetPage() {
  const flow = getOtpFlowState();
  if (!flow || !flow.targetId || flow.purpose !== 'reset') {
    window.location.href = '/forgot-password.html';
    return;
  }

  const emailMasked = document.getElementById('reset-email-masked');
  if (emailMasked) emailMasked.textContent = flow.emailMasked || 'your email';

  initOtpBoxes('reset-otp-boxes');
  updatePasswordStrength('reset-new-password', 'reset-strength-fill', 'reset-strength-text');

  // Show dev preview URL
  if (flow.devPreviewUrl) {
    // Reuse dev preview if available (same page doesn't have its own container, so add dynamically)
    const card = document.querySelector('.auth-card');
    if (card && !document.getElementById('dev-preview-container')) {
      const div = document.createElement('div');
      div.id = 'dev-preview-container';
      div.className = 'dev-preview';
      div.innerHTML = `📧 Dev Mail Preview: <a id="dev-preview-link" href="${escapeHTML(flow.devPreviewUrl)}" target="_blank" rel="noopener noreferrer">Open in Ethereal</a>`;
      card.insertBefore(div, card.querySelector('.auth-links'));
    }
  }

  const form = document.getElementById('reset-form');
  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      hideAlert('reset-error');
      hideAlert('reset-success');

      const otp = getOtpValue('reset-otp-boxes');
      const newPassword = document.getElementById('reset-new-password')?.value;
      const confirmPassword = document.getElementById('reset-confirm-password')?.value;

      if (otp.length !== 6) {
        showAlert('reset-error', 'Please enter all 6 digits of the verification code.');
        return;
      }

      if (!newPassword || newPassword.length < 10) {
        showAlert('reset-error', 'New password must be at least 10 characters.');
        return;
      }

      if (newPassword !== confirmPassword) {
        showAlert('reset-error', 'Passwords do not match.');
        return;
      }

      setLoading('reset-submit-btn', true, 'Reset Password');

      try {
        const { status, data } = await authPost('/reset-password', {
          targetId: flow.targetId,
          otp,
          newPassword,
          confirmPassword
        });

        if (data.success) {
          clearOtpFlowState();
          showAlert('reset-success', 'Password updated! Redirecting to sign in...', 'success');
          setTimeout(() => { window.location.href = '/login.html'; }, 2000);
        } else {
          showAlert('reset-error', data.error || 'Reset failed. Please try again.');
          clearOtpBoxes('reset-otp-boxes');
        }
      } catch (err) {
        showAlert('reset-error', 'Network error. Please try again.');
      } finally {
        setLoading('reset-submit-btn', false, 'Reset Password');
      }
    });
  }
}

// ─── Page Router ────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
  await getCsrfToken();
  initPasswordToggles();

  const page = currentPage();
  switch (page) {
    case 'login': initLoginPage(); break;
    case 'register': initRegisterPage(); break;
    case 'otp': initOtpPage(); break;
    case 'forgot': initForgotPage(); break;
    case 'reset': initResetPage(); break;
  }
});

