document.addEventListener('DOMContentLoaded', function() {
    // Row-level show/hide and copy interactions
    document.querySelectorAll('.password-secret').forEach((wrap) => {
        const dots = wrap.querySelector('.pw-dots');
        const text = wrap.querySelector('.pw-text');
        const showBtn = wrap.querySelector('.pw-visibility-btn');
        const copyBtn = wrap.querySelector('.copy-btn-min');
        const secret = wrap.getAttribute('data-password') || '';
        if (showBtn) {
            showBtn.addEventListener('click', () => {
                const showing = text.style.display !== 'none' && text.textContent.length > 0;
                if (showing) {
                    text.style.display = 'none';
                    dots.style.display = '';
                    showBtn.innerHTML = '<i class="fa-regular fa-eye"></i>';
                } else {
                    text.textContent = secret;
                    text.style.display = '';
                    dots.style.display = 'none';
                    showBtn.innerHTML = '<i class="fa-regular fa-eye-slash"></i>';
                }
            });
        }
        if (copyBtn) {
            copyBtn.addEventListener('click', async () => {
                try {
                    await navigator.clipboard.writeText(secret);
                    const icon = copyBtn.querySelector('i');
                    const prev = icon.className;
                    icon.className = 'fa-solid fa-check';
                    setTimeout(() => { icon.className = prev; }, 1000);
                } catch (e) {
                    console.error('Copy failed', e);
                }
            });
        }
    });

    // New card-level copy button outside the secret box
    document.querySelectorAll('.password-card').forEach((card) => {
        const wrap = card.querySelector('.password-secret');
        const copyBtn = card.querySelector('.copy-btn-card');
        if (!wrap || !copyBtn) return;
        const secret = wrap.getAttribute('data-password') || '';
        copyBtn.addEventListener('click', async () => {
            try {
                await navigator.clipboard.writeText(secret);
                const icon = copyBtn.querySelector('i');
                const prev = icon.className;
                icon.className = 'fa-solid fa-check';
                setTimeout(() => { icon.className = prev; }, 1000);
            } catch (e) {
                console.error('Copy failed', e);
            }
        });
    });
    // Profile dropdown toggle
    const profileBtn = document.getElementById('profileButton');
    const profileDropdown = document.getElementById('profileDropdown');
    if (profileBtn && profileDropdown) {
        profileBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            const isOpen = profileDropdown.classList.contains('show');
            profileDropdown.classList.toggle('show', !isOpen);
            profileBtn.setAttribute('aria-expanded', String(!isOpen));
        });
        // Close on outside click
        document.addEventListener('click', () => {
            profileDropdown.classList.remove('show');
            profileBtn.setAttribute('aria-expanded', 'false');
        });
        // Prevent closing when clicking inside
        profileDropdown.addEventListener('click', (e) => e.stopPropagation());
    }

    // Absolute timeout (20 minutes) — no reset on activity
    // Matches server: absolute PERMANENT_SESSION_LIFETIME = 20 minutes
    const ABS_TIMEOUT_MS = 20 * 60 * 1000;
    if (document.body.classList.contains('vault_page')) {
        setTimeout(() => {
            window.location.href = '/login';
        }, ABS_TIMEOUT_MS);
    }

    // Mobile sidebar toggle
    const menuBtn = document.getElementById('menuToggle');
    const menuBtnTop = document.getElementById('menuToggleTop');
    const sidebarToggle = document.getElementById('sidebarToggle');
    const sidebar = document.getElementById('sidebar');
    const backdrop = document.getElementById('sidebarBackdrop');
    function openSidebar() {
        if (!sidebar) return;
        if (window.innerWidth <= 750) {
            sidebar.classList.add('open');
            if (backdrop) backdrop.hidden = false;
            document.documentElement.style.overflow = 'hidden';
        } else {
            sidebar.classList.remove('collapsed');
        }
        if (menuBtn) menuBtn.setAttribute('aria-expanded', 'true');
        if (menuBtnTop) menuBtnTop.setAttribute('aria-expanded', 'true');
        sidebar.setAttribute('aria-hidden', 'false');
    }
    function closeSidebar() {
        if (!sidebar) return;
        if (window.innerWidth <= 750) {
            sidebar.classList.remove('open');
            if (backdrop) backdrop.hidden = true;
            document.documentElement.style.overflow = '';
            sidebar.setAttribute('aria-hidden', 'true');
        } else {
            sidebar.classList.add('collapsed');
            sidebar.setAttribute('aria-hidden', 'false');
        }
        if (menuBtn) menuBtn.setAttribute('aria-expanded', 'false');
        if (menuBtnTop) menuBtnTop.setAttribute('aria-expanded', 'false');
    }
    function toggleSidebarDesktopCollapse() {
        if (!sidebar) return;
        const collapsed = sidebar.classList.toggle('collapsed');
        if (collapsed) {
            sidebar.setAttribute('aria-hidden', 'false');
        }
    }
    if (menuBtn && sidebar) {
        menuBtn.addEventListener('click', () => {
            const isOpen = sidebar.classList.contains('open');
            if (window.innerWidth <= 750) {
                if (isOpen) closeSidebar(); else openSidebar();
            } else {
                toggleSidebarDesktopCollapse();
            }
        });
    }
    if (menuBtnTop && sidebar) {
        menuBtnTop.addEventListener('click', () => {
            const isOpen = sidebar.classList.contains('open');
            if (window.innerWidth <= 750) {
                if (isOpen) closeSidebar(); else openSidebar();
            } else {
                toggleSidebarDesktopCollapse();
            }
        });
    }
    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', () => {
            if (window.innerWidth <= 750) {
                const isOpen = sidebar.classList.contains('open');
                if (isOpen) closeSidebar(); else openSidebar();
            } else {
                toggleSidebarDesktopCollapse();
            }
        });
    }
    if (backdrop) {
        backdrop.addEventListener('click', closeSidebar);
    }
    // Close on ESC
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeSidebar();
    });
    // Close when clicking a link in sidebar (for better UX on mobile)
    if (sidebar) {
        sidebar.addEventListener('click', (e) => {
            const link = e.target.closest('a');
            if (link) closeSidebar();
        });
    }
    // Reset state when resizing to desktop
    window.addEventListener('resize', () => {
        if (!sidebar) return;
        if (window.innerWidth > 750) {
            // desktop: ensure offcanvas closed and no backdrop
            sidebar.classList.remove('open');
            if (backdrop) backdrop.hidden = true;
            document.documentElement.style.overflow = '';
            // keep collapsed state as-is
        } else {
            // mobile: remove collapsed, use offcanvas
            sidebar.classList.remove('collapsed');
        }
    });

    // Live search filtering
    const searchInput = document.getElementById('vault-search');
    const noResults = document.getElementById('no-results');
    function filterCards(q) {
        const query = (q || '').trim().toLowerCase();
        const cards = document.querySelectorAll('.password-card');
        let visibleCount = 0;
        cards.forEach(card => {
            const title = card.querySelector('.site-title')?.textContent?.toLowerCase() || '';
            const subtitle = card.querySelector('.site-subtitle')?.textContent?.toLowerCase() || '';
            const match = query === '' || title.includes(query) || subtitle.includes(query);
            card.style.display = match ? '' : 'none';
            if (match) visibleCount++;
        });
        if (noResults) noResults.style.display = (visibleCount === 0) ? '' : 'none';
    }
    const debounceSearch = (fn => {
        let t; return (v) => { clearTimeout(t); t = setTimeout(() => fn(v), 150); };
    })(filterCards);
    if (searchInput) {
        searchInput.addEventListener('input', (e) => debounceSearch(e.target.value));
    }
    // No button needed; filtering is live.























    const slider = document.getElementById('myRange');
    const lengthDisplay = document.getElementById('length-display');
    const passwordInput = document.getElementById('generated-password');

    // Function to check the status of checkboxes live
    function getPasswordOptions() {
        const uppercaseChecked = document.querySelector('input[name="uppercase"]')?.checked || false;
        const lowercaseChecked = document.querySelector('input[name="lowercase"]')?.checked || false;
        const numbersChecked = document.querySelector('input[name="numbers"]')?.checked || false;
        const symbolsChecked = document.querySelector('input[name="symbols"]')?.checked || false;
        
        return {
            uppercase: uppercaseChecked,
            lowercase: lowercaseChecked,
            numbers: numbersChecked,
            symbols: symbolsChecked
        };
    }
    
    // Function to generate new password live
    window.generateNewPassword = function() {
        if (!passwordInput) return;
        
        const length = slider ? slider.value : 12;
        const options = getPasswordOptions();
        
        const params = new URLSearchParams({
            length: length,
            uppercase: options.uppercase,
            lowercase: options.lowercase,
            numbers: options.numbers,
            symbols: options.symbols
        });
        
        fetch(`/generate-password?${params}`)
            .then(response => response.json())
            .then(data => {
                passwordInput.value = data.password;
            })
            .catch(error => {
                console.error('Error generating password:', error);
            });
    }
    
    // Function to change length buttons live
    function updateLengthButtons() {
        const decreaseBtn = document.querySelector('.length-controls .length-btn:first-child');
        const increaseBtn = document.querySelector('.length-controls .length-btn:last-child');
        const currentLength = parseInt(slider.value);
        
        if (decreaseBtn) {
            if (currentLength <= 8) {
                decreaseBtn.classList.add('disabled');
                decreaseBtn.style.pointerEvents = 'none';
                decreaseBtn.style.opacity = '0.5';
            } else {
                decreaseBtn.classList.remove('disabled');
                decreaseBtn.style.pointerEvents = 'auto';
                decreaseBtn.style.opacity = '1';
            }
        }
        if (increaseBtn) {
            if (currentLength >= 32) {
                increaseBtn.classList.add('disabled');
                increaseBtn.style.pointerEvents = 'none';
                increaseBtn.style.opacity = '0.5';
            } else {
                increaseBtn.classList.remove('disabled');
                increaseBtn.style.pointerEvents = 'auto';
                increaseBtn.style.opacity = '1';
            }
        }
    }
    
    // functions for + and - buttons to change length live
    window.increaseLength = function(event) {
        event.preventDefault();
        if (slider && parseInt(slider.value) < 32) {
            slider.value = parseInt(slider.value) + 1;
            lengthDisplay.textContent = slider.value;
            updateLengthButtons();
            window.generateNewPassword();
        }
    }
    window.decreaseLength = function(event) {
        event.preventDefault();
        if (slider && parseInt(slider.value) > 8) {
            slider.value = parseInt(slider.value) - 1;
            lengthDisplay.textContent = slider.value;
            updateLengthButtons();
            window.generateNewPassword();
        }
    }
    
    // Slider live length change
    if (slider && lengthDisplay) {
        slider.addEventListener('input', function() {
            const newLength = this.value;
            lengthDisplay.textContent = newLength;
            updateLengthButtons();
            window.generateNewPassword();
        });
        updateLengthButtons();
    }
    
    // Checkbox functionality to change the password live
    const checkboxes = document.querySelectorAll('.password-options-section input[type="checkbox"]');
    checkboxes.forEach(checkbox => {
        checkbox.addEventListener('change', function() {
            const checkedBoxes = document.querySelectorAll('.password-options-section input[type="checkbox"]:checked');
            if (checkedBoxes.length === 0) {
                this.checked = true;
                return;
            }
            window.generateNewPassword();
        });
    });

    // Security Check popup logic
    const secInput = document.getElementById('seccheck-input');
    const fill = document.getElementById('meter-fill');
    const strengthLabel = document.getElementById('strength-label');
    const entropyLabel = document.getElementById('entropy-label');
    const timeLabel = document.getElementById('time-label');

    function setMeter(score, entropy, crackTime, label) {
        if (!fill) return;
        const percent = Math.min(100, Math.max(0, (score / 4) * 100));
        fill.style.width = `${percent}%`;
        // reset previous score color classes
        fill.classList.remove('score-0','score-1','score-2','score-3','score-4');
        fill.classList.add(`score-${score}`);
        if (strengthLabel) strengthLabel.textContent = `Strength: ${label}`;
        if (entropyLabel) entropyLabel.textContent = `Entropy: ${entropy} bits`;
        if (timeLabel) timeLabel.textContent = `Crack time: ${crackTime}`;
    }

    // Debounce helper
    function debounce(fn, wait) {
        let t;
        return (...args) => {
            clearTimeout(t);
            t = setTimeout(() => fn(...args), wait);
        };
    }

    const evaluate = debounce(async function(pw){
        if (!pw) { setMeter(0, 0, '—', 'Very Weak'); return; }
        try {
            const res = await fetch('/password-strength', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: pw })
            });
            const data = await res.json();
            if (data && data.ok) {
                setMeter(data.score, data.entropy_bits, data.crack_time_display, data.label);
            } else {
                setMeter(0, 0, '—', 'Very Weak');
            }
        } catch (e) {
            console.error('Strength check failed', e);
        }
    }, 250);

    if (secInput && fill) {
        secInput.addEventListener('input', (e) => evaluate(e.target.value));
    }
});

// for show/hide password
function togglePassword() {
    const passwordInput = document.getElementById('password');
    const toggleIcon = document.getElementById('toggle-icon');
    
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        toggleIcon.className = 'ri-eye-off-line';
    } else {
        passwordInput.type = 'password';
        toggleIcon.className = 'ri-eye-line';
    }
}

// Generic visibility toggle for auth fields
function toggleVisibility(inputId, iconId) {
    const input = document.getElementById(inputId);
    const icon = document.getElementById(iconId);
    if (!input || !icon) return;
    const isPwd = input.type === 'password';
    input.type = isPwd ? 'text' : 'password';
    icon.className = isPwd ? 'ri-eye-off-line' : 'ri-eye-line';
}

// changing the appearance of copy button on click
document.addEventListener('click', async (e) => {
  const btn = e.target.closest('.copy-btn');
  if (!btn) return;

    const pwd = document.getElementById('generated-password').value || '';
  try {
    await navigator.clipboard.writeText(pwd);

    const icon = btn.querySelector('i');
    const originalClass = 'fa-regular fa-copy';
    const successClass = 'fa-solid fa-check';

    icon.className = successClass;

    // revert after 1 second
    setTimeout(() => {
      icon.className = originalClass;
    }, 1000);

  } catch (err) {
    console.error('Copy failed:', err);
  }
});

// toggle visibility for security check input
function toggleSecCheckPassword() {
    const inp = document.getElementById('seccheck-input');
    const icon = document.getElementById('seccheck-toggle-icon');
    if (!inp || !icon) return;
    if (inp.type === 'password') {
        inp.type = 'text';
        icon.className = 'ri-eye-off-line';
    } else {
        inp.type = 'password';
        icon.className = 'ri-eye-line';
    }
}