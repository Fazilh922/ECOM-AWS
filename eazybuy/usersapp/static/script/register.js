
    document.getElementById('registerButton').addEventListener('click', async function (event) {
        event.preventDefault(); // Prevent default button behavior

        // Retrieve form values
        const name = document.getElementById('name').value.trim();
        const email = document.getElementById('email').value.trim();
        const phone = document.getElementById('phone').value.trim();
        const password = document.getElementById('password').value.trim();
        const confirmPassword = document.getElementById('confirm_password').value.trim();
        const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;

        // Basic validation
        if (!name || !email || !phone || !password || !confirmPassword) {
            Swal.fire("Error", "All fields are required.", "error");
            return;
        }

        if (password !== confirmPassword) {
            Swal.fire("Error", "Passwords do not match.", "error");
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
                Swal.fire("Registration Failed", errorData.error || "Something went wrong.", "error");
                return;
            }

            // Successful registration
            const result = await response.json();
            Swal.fire({
                title: "User Created Successfully!",
                text: "Click OK to go to the login page.",
                icon: "success",
                confirmButtonText: "OK"
            }).then(() => {
                window.location.href = "{% url 'login' %}"; // Correct Django URL redirection
            });

        } catch (error) {
            console.error("Error occurred:", error);
            Swal.fire("Error", "An error occurred. Please try again.", "error");
        }
    });

    // Handle form submission with ENTER key
    document.getElementById('registerForm').addEventListener('submit', function(event) {
        event.preventDefault();  // Prevent default form submission

        document.getElementById('registerButton').click(); // Trigger the button click event
    });




