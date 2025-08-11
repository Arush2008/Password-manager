document.addEventListener('DOMContentLoaded', function() {
    const slider = document.getElementById('myRange');
    const lengthDisplay = document.getElementById('length-display');
    const passwordInput = document.getElementById('generated-password');
    
    if (slider && lengthDisplay) {
        // Update the length display when slider moves
        slider.addEventListener('input', function() {
            const newLength = this.value;
            lengthDisplay.textContent = newLength;
            
            // Generate new password with Python backend
            if (passwordInput) {
                fetch(`/generate-password?length=${newLength}`)
                    .then(response => response.json())
                    .then(data => {
                        passwordInput.value = data.password;
                    })
                    .catch(error => {
                        console.log('Error:', error);
                    });
            }
        });
    }
});
