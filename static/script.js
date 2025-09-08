// for live length change
document.addEventListener('DOMContentLoaded', function() {
    const slider = document.getElementById('myRange');
    const lengthDisplay = document.getElementById('length-display');
    const passwordInput = document.getElementById('generated-password');
    
    if (slider && lengthDisplay) {
        slider.addEventListener('input', function() {
            const newLength = this.value;
            lengthDisplay.textContent = newLength;
            
            if (passwordInput) {
                fetch(`/generate-password?length=${newLength}`)
                    .then(response => response.json())
                    .then(data => {
                        passwordInput.value = data.password;
                    })
            }
        });
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
