/* ============================================================
   PhishGuard — Main JavaScript
   ============================================================ */

// ── Password toggle ───────────────────────────────────────────────────────────
function togglePassword(fieldId) {
  const field = document.getElementById(fieldId);
  if (!field) return;
  field.type = field.type === "password" ? "text" : "password";
}

// ── Password strength meter ───────────────────────────────────────────────────
function checkStrength(password) {
  const bar   = document.getElementById("strength-bar");
  const label = document.getElementById("strength-label");
  if (!bar || !label) return;

  let score = 0;
  if (password.length >= 8)                        score++;
  if (/[A-Z]/.test(password))                     score++;
  if (/[0-9]/.test(password))                     score++;
  if (/[^A-Za-z0-9]/.test(password))              score++;
  if (password.length >= 12)                       score++;

  const levels = [
    { width: "0%",   bg: "",          text: ""              },
    { width: "25%",  bg: "#ef4444",   text: "Weak"          },
    { width: "50%",  bg: "#f97316",   text: "Fair"          },
    { width: "75%",  bg: "#eab308",   text: "Good"          },
    { width: "100%", bg: "#22c55e",   text: "Strong"        },
  ];

  const level = levels[Math.min(score, 4)];
  bar.style.width      = level.width;
  bar.style.background = level.bg;
  label.textContent    = level.text;
  label.style.color    = level.bg;

  // Check confirm match
  const confirm = document.getElementById("confirm_password");
  if (confirm && confirm.value) {
    checkMatch(password, confirm.value);
  }
}

// ── Confirm password match ────────────────────────────────────────────────────
function checkMatch(pw, confirm) {
  const msg = document.getElementById("match-msg");
  if (!msg) return;
  if (!confirm) { msg.textContent = ""; return; }
  if (pw === confirm) {
    msg.textContent  = "✓ Passwords match";
    msg.style.color  = "#15803d";
  } else {
    msg.textContent  = "✗ Passwords do not match";
    msg.style.color  = "#dc2626";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const confirmInput = document.getElementById("confirm_password");
  const pwInput      = document.getElementById("password");
  if (confirmInput && pwInput) {
    confirmInput.addEventListener("input", () => {
      checkMatch(pwInput.value, confirmInput.value);
    });
  }

  // Auto-dismiss alerts after 5 seconds
  document.querySelectorAll(".alert").forEach(el => {
    setTimeout(() => {
      el.style.transition = "opacity .5s";
      el.style.opacity    = "0";
      setTimeout(() => el.remove(), 500);
    }, 5000);
  });
});
