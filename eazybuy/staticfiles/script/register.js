document.getElementById('registerButton').addEventListener('click', async function (event) {
    event.preventDefault(); // Prevent form default submission

    // Retrieve form values
    const name = document.getElementById('name').value.trim();
    const email = document.getElementById('email').value.trim();
    const phone = document.getElementById('phone').value.trim();
    const password = document.getElementById('password').value.trim();
    const confirmPassword = document.getElementById('confirm_password').value.trim();
    const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;

    // Basic validation
    if (!name || !email || !phone || !password || !confirmPassword) {
        alert('All fields are required.');
        return;
    }

    if (password !== confirmPassword) {
        alert('Passwords do not match.');
        return;
    }

    // Create the request payload
    const requestData = {
        name: name,
        email: email,
        phone: phone,
        password: password,
        confirm_password: confirmPassword,
    };

    try {
        // Sending the POST request
        const response = await fetch('/register/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken,
            },
            body: JSON.stringify(requestData),
        });

        // Handle non-success response
        if (!response.ok) {
            let errorData;
            try {
                errorData = await response.json();
            } catch (error) {
                errorData = { error: 'Failed to parse error response' };
            }
            alert(errorData.error || 'Registration failed.');
            return;
        }
        
        

        // Successful registration
        const result = await response.json();
        alert(result.message || 'User registered successfully!');
        window.location.href = '/login/'; // Redirect to login page
    } catch (error) {
        console.error('Error occurred:', error);
        alert('An error occurred. Please try again.');
    }
});


