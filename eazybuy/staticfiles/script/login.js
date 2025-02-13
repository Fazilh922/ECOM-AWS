document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('loginForm');
    const loginButton = document.getElementById('loginButton');
    const errorContainer = document.getElementById('error-container');

    if (loginForm && loginButton && errorContainer) {
        loginForm.addEventListener('submit', async function(event) {
            event.preventDefault();

            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const rememberMe = document.getElementById('rememberMe').checked;

            errorContainer.innerHTML = ''; // Clear previous errors

            if (!username || !password) {
                displayError("Please enter both username and password.");
                return;
            }

            try {
                const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;

                const response = await fetch('{% url "login" %}', { // Use your login URL
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrfToken,
                    },
                    body: JSON.stringify({
                        username: username,
                        password: password,
                        remember_me: rememberMe // Send remember me status to backend
                    }),
                });

                const result = await response.json();

                if (response.ok) {
                    // Redirect on successful login
                    window.location.href = '{% url "index" %}'; // Or wherever you want to redirect
                } else {
                    if (result.error) {
                        displayError(result.error);
                    } else if (result.errors) {
                        let errorMessages = "";
                        for (const key in result.errors) {
                            errorMessages += `${key}: ${result.errors[key].join(", ")}\n`;
                        }
                        displayError(errorMessages);
                    } else {
                        displayError("Invalid credentials."); // Generic error
                    }
                }
            } catch (error) {
                console.error("Login error:", error);
                displayError("An error occurred during login. Please try again later.");
            }
        });
    } else {
        console.error("Required elements not found.");
    }

    function displayError(message) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        errorDiv.textContent = message;
        errorContainer.appendChild(errorDiv);
    }
});