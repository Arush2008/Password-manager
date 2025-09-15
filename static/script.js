document.addEventListener('DOMContentLoaded', function() {
    const slider = document.getElementById('myRange');
    const lengthDisplay = document.getElementById('length-display');
    const passwordInput = document.getElementById('generated-password');

    // Function to check the status of checkboxes
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
    
    // Function to generate new password 
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
    
    // Function to change length buttons
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
    
    // functions for + and - buttons
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

// changing the appearance of copy button on click
document.addEventListener('click', async (e) => {
  const btn = e.target.closest('.copy-btn');
  if (!btn) return;

  const pwd = btn.getAttribute('data-password') || '';
  try {
    await navigator.clipboard.writeText(pwd);

    const icon = btn.querySelector('i');
    const originalClass = 'fa-regular fa-copy';
    const successClass = 'fa-solid fa-check';

    // swap to success
    icon.className = successClass;

    // revert after 1 second
    setTimeout(() => {
      icon.className = originalClass;
    }, 1000);

  } catch (err) {
    console.error('Copy failed:', err);
  }
});