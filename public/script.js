function showError(messageId, message) {
    const messageElement = document.getElementById(messageId);
    if (messageElement) {
        messageElement.textContent = message;
        messageElement.style.display = "block";
    }
}

function hideError(messageId) {
    const messageElement = document.getElementById(messageId);
    if (messageElement) {
        messageElement.textContent = "";
        messageElement.style.display = "none";
    }
}


//SIGNUP-----------------------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', function() {
    // Signup form handling
    const signupForm = document.getElementById('signup-form');
    const emailInputSignup = document.getElementById('email');
    const passFields = ['pass1', 'pass2'];
    const togglePass1 = document.getElementById('toggle-pass1');
    const togglePass2 = document.getElementById('toggle-pass2');

    if (signupForm) {
        signupForm.addEventListener('submit', submitSignUp);
    }

    if (emailInputSignup) {
        emailInputSignup.addEventListener('input', function() {
            validateEmail(emailInputSignup.value, 'signup_error_message');
        });
    }

    passFields.forEach(field => {
        const passField = document.getElementById(field);
        if (passField) {
            passField.addEventListener('input', function() {
                verifyPassword();
                checkPasswordStrength(this.value);
            });
        }
    });

    if (togglePass1) {
        togglePass1.addEventListener('click', function() {
            togglePassword('pass1');
        });
    }

    if (togglePass2) {
        togglePass2.addEventListener('click', function() {
            togglePassword('pass2');
        });
    }
});

//LOGIN-----------------------------------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', function() {
    // Login form handling
    const loginForm = document.getElementById('login-form');
    const emailInputLogin = document.getElementById('email');
    const loginErrorMessage = 'login_error_message';
    const togglePassword = document.getElementById('togglePassword');

    if (loginForm) {
        loginForm.addEventListener('submit', submitLogin);
    }

    if (emailInputLogin) {
        emailInputLogin.addEventListener('input', function() {
            validateEmail(emailInputLogin.value, loginErrorMessage);
        });
    }

    if (togglePassword) {
        togglePassword.addEventListener('click', function() {
            const passwordField = document.getElementById('password');
            const type = passwordField.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordField.setAttribute('type', type); // Change input type
        });
    }
});

//FORGOT PASSWORD-------------------------------------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', function () {
    const forgotPasswordForm = document.getElementById('forgot-password-form');
    const emailInput = document.getElementById('email');
    const emailMessage = document.getElementById('email_message');
    const submitButton = document.getElementById('submit-button');

    // Handle form submission
    if (forgotPasswordForm) {
        forgotPasswordForm.addEventListener('submit', function (event) {
            event.preventDefault();
            const email = emailInput.value;

            // Clear previous error messages
            emailMessage.style.display = 'none';
            submitButton.disabled = true;

            // Send request to server to send reset token
            fetch('/forgot-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: email })
            })
            .then(response => {
                if (!response.ok) {
                    return response.json().then(data => { throw new Error(data.message || 'Error sending reset token'); });
                }
                return response.json();
            })
            .then(data => {
                alert('Reset token sent to your email.');
                window.location.href = 'reset-password.html'; // Redirect to reset password page
            })
            .catch(error => {
                emailMessage.textContent = error.message;
                emailMessage.style.display = 'block';
                console.error('Error:', error);
                submitButton.disabled = false; // Re-enable submit button
            });
        });
    }
});

//RESET PASSWORD--------------------------------------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', function() {
    // Reset password form handling
    const resetForm = document.getElementById('reset-password-form');
    const tokenInput = document.getElementById('reset-token');
    const passwordInput = document.getElementById('new-password');
    const confirmPasswordInput = document.getElementById('confirm-password');
    const togglePassword1 = document.getElementById('togglePassword1');
    const togglePassword2 = document.getElementById('togglePassword2');
    const tokenMessage = document.getElementById('token_message');
    const verifyMessage = document.getElementById('verify_message');

    // Submit event listener for reset password form
    if (resetForm) {
        resetForm.addEventListener('submit', submitResetPassword);
    }

    // Event listener for token input (if needed for validation)
    if (tokenInput) {
        tokenInput.addEventListener('input', function() {
            // You can add token validation logic here if necessary
        });
    }

    // Toggle password visibility for new password field
    if (togglePassword1 && passwordInput) {
        togglePassword1.addEventListener('click', function() {
            togglePasswordVisibility(passwordInput);
        });
    }

    // Toggle password visibility for confirm password field
    if (togglePassword2 && confirmPasswordInput) {
        togglePassword2.addEventListener('click', function() {
            togglePasswordVisibility(confirmPasswordInput);
        });
    }

    // Check password strength or matching
    if (passwordInput) {
        passwordInput.addEventListener('input', checkPasswordStrength);
    }

    if (confirmPasswordInput) {
        confirmPasswordInput.addEventListener('input', checkPasswordMatch);
    }
});


//SIGN UP FUNCTIONS------------------------------------------------------------------------------------------

function isValidEmailFormat(email) {
    return /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(email);
}

function verifyPassword() {
    const newPassword = document.getElementById('pass1').value;
    const confirmPassword = document.getElementById('pass2').value;
    const messageId = 'verify_message';
    hideError(messageId);

    if (newPassword !== confirmPassword) {
        showError(messageId, "Passwords do not match.");
        return false;
    } else if (newPassword.length < 8) {
        showError(messageId, "Password must be at least 8 characters long.");
        return false;
    } else if (!/[!@#$%^&*(),.?":{}|<>]/.test(newPassword)) {
        showError(messageId, "Password must contain at least one special character.");
        return false;
    } else if (!/[0-9]/.test(newPassword)) {
        showError(messageId, "Password must contain at least one number.");
        return false;
    }
    return true;
}

function checkPasswordStrength(password) {
    const strength = [/[A-Z]/, /[0-9]/, /[!@#$%^&*(),.?":{}|<>]/]
        .filter(regex => regex.test(password)).length;
    
    const strengthText = ['Weak', 'Medium', 'Strong'][Math.min(strength, 2)];
    const strengthColor = ['red', 'orange', 'green'][Math.min(strength, 2)];

    const passwordStrength = document.getElementById("password_strength");
    if (passwordStrength) {
        passwordStrength.textContent = strengthText;
        passwordStrength.style.color = strengthColor;
    }
}

function togglePassword(inputId) {
    const passwordInput = document.getElementById(inputId); 
    const newInputType = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordInput.setAttribute('type', newInputType);
}

function submitSignUp(event) {
    event.preventDefault();

    const fullName = document.getElementById('full_name').value;
    const mobileNumber = document.getElementById('mob_number').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('pass1').value;

    if (!isValidEmailFormat(email) || !verifyPassword()) return;

    const payload = { full_name: fullName, mob_number: mobileNumber, email: email, password: password };
    let hasProcessed = false;

    fetch('/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
    })
    .then(response => response.json())
    .then(data => {
        if (hasProcessed) return;
        hasProcessed = true;

        if (data.success) {
            alert('Account created successfully! Redirecting...');
            window.location.href = 'login.html';
        } else {
            alert(data.message);
        }
    })
    .catch(error => {
        if (hasProcessed) return;
        hasProcessed = true;
        console.error('Error during signup:', error);
        alert('An error occurred. Please try again.');
    });
}

//LOG IN FUNCTIONS------------------------------------------------------------------------------------------
function submitLogin(event) {
    event.preventDefault();
    
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    if (!validateEmail(email, 'login_error_message')) {
        return;
    }

    if (password.trim() === "") {
        showError('login_error_message', "Password cannot be empty.");
        return;
    }

    const payload = { email: email, password: password };

    fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('Login successful! Redirecting...');
            window.location.href = 'dashboard.html';
        } else {
            showError('login_error_message', data.message);
        }
    })
    .catch(error => {
        console.error('Error during login:', error);
        showError('login_error_message', 'An error occurred. Please try again.');
    });
}


function validateEmail(email, messageId) {
    hideError(messageId);
    if (!isValidEmailFormat(email)) {
        showError(messageId, "Please enter a valid email address.");
        return false;
    }
    return true;
}


//RESET PASSWORD FUNCTIONS------------------------------------------------------------------------------------------

function togglePasswordVisibility(inputField) {
    const type = inputField.getAttribute('type') === 'password' ? 'text' : 'password';
    inputField.setAttribute('type', type);
}

function checkPasswordStrength() {
    const password = document.getElementById('new-password').value;
    const strengthMessage = document.getElementById('password_strength');
    if (password.length < 8) {
        strengthMessage.textContent = 'Password is too weak';
        strengthMessage.style.color = 'red';
    } else {
        strengthMessage.textContent = 'Password is strong';
        strengthMessage.style.color = 'green';
    }
}

function checkPasswordMatch() {
    const password = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;
    const verifyMessage = document.getElementById('verify_message');
    
    if (password !== confirmPassword) {
        verifyMessage.textContent = 'Passwords do not match';
        verifyMessage.style.display = 'block';
        verifyMessage.style.color = 'red';
    } else {
        verifyMessage.style.display = 'none';
    }
}

function submitResetPassword(event) {
    event.preventDefault();

    const token = document.getElementById('reset-token').value;
    const password = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;

    if (!token || !password || !confirmPassword) {
        showError('token_message', 'Please fill in all fields.');
        return;
    }

    if (password !== confirmPassword) {
        showError('verify_message', 'Passwords do not match.');
        return;
    }

    const payload = { resetKey: token, newPassword: password };


    fetch('/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('Password reset successful!');
            window.location.href = 'login.html'; // Redirect to login page after successful reset
        } else {
            showError('token_message', data.message || 'Reset token invalid or expired');
        }
    })
    .catch(error => {
        console.error('Error resetting password:', error);
        showError('token_message', 'An error occurred. Please try again.');
    });
}


//DASHBOARD-----------------------------------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', function () {
    const logoutLink = document.getElementById('logoutLink');
    const userEmailElement = document.getElementById('userEmail');
    
    // Fetch user details only if the user is logged in
    if (userEmailElement) {
        fetchUserDetails();
    }

    // Add logout event listener, but only if the logout link exists
    if (logoutLink) {
        logoutLink.addEventListener('click', function (event) {
            event.preventDefault();
            performLogout();
        });
    }
});

async function fetchUserDetails() {
    try {
        const response = await fetch('/user-details', { credentials: 'include' });

        if (!response.ok) {
            throw new Error('Failed to fetch user details.');
        }

        const data = await response.json();
        console.log(data);

        if (data.success && document.getElementById('userEmail')) {
            document.getElementById('userEmail').textContent = data.user.email;
        } else {
            console.error('Failed to fetch user details:', data.message);
        }
    } catch (error) {
        console.error('Error fetching user details:', error);
    }
}

async function performLogout() {
    try {
        const response = await fetch('/logout', {
            method: 'POST',
            credentials: 'include'
        });

        if (response.ok) {
            window.location.href = 'login.html'; // Redirect to login page after logout
        } else {
            console.error('Logout failed');
        }
    } catch (error) {
        console.error('Error during logout:', error);
    }
}
