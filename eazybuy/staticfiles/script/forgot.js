document.addEventListener('DOMContentLoaded', function () {
    const form = document.querySelector('.login_form');
    const identifierInput = document.getElementById('identifier');
    const codeInput = document.getElementById('code');
    const newPasswordInput = document.getElementById('new_password');
    const confirmPasswordInput = document.getElementById('confirm_password');

    form.addEventListener('submit', async function (e) {
        e.preventDefault(); // Prevent the form from being submitted by default

        const identifier = identifierInput.value.trim();
        const code = codeInput.value.trim();
        const newPassword = newPasswordInput.value.trim();
        const confirmPassword = confirmPasswordInput.value.trim();

        // Basic validation
        if (!identifier) {
            alert('Please enter your registered phone number or email ID.');
            return;
        }
        if (!code) {
            alert('Please enter the verification code.');
            return;
        }
        if (!newPassword) {
            alert('Please enter your new password.');
            return;
        }
        if (newPassword !== confirmPassword) {
            alert('Passwords do not match.');
            return;
        }

        // Send data to the server via AJAX
        const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;

        try {
            const response = await fetch('/reset-password/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken,
                },
                body: JSON.stringify({
                    identifier: identifier,
                    code: code,
                    new_password: newPassword,
                }),
            });

            if (response.ok) {
                const result = await response.json();
                if (result.success) {
                    alert('Password reset successful. You can now log in with your new password.');
                    window.location.href = '/login/'; // Redirect to login page
                } else {
                    alert(result.message || 'An error occurred. Please try again.');
                }
            } else {
                alert('Failed to reset password. Please try again later.');
            }
        } catch (error) {
            console.error('Error:', error);
            alert('An unexpected error occurred. Please try again later.');
        }
    });
});