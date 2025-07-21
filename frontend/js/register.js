// Loader and alert utility functions
window.showLoader = () => document.body.classList.add('loading');
window.hideLoader = () => document.body.classList.remove('loading');
window.showAlert = (msg) => alert(msg);

// Token storage utility
function storeTokens(access_token, refresh_token, user) {
    localStorage.setItem('authToken', access_token);
    localStorage.setItem('refreshToken', refresh_token);
    localStorage.setItem('userData', JSON.stringify(user));
    console.log("✅ Tokens stored successfully in localStorage.");
}

// API base and header config
const API_BASE = 'http://127.0.0.1:5000/api/user'; // Adjust as needed

function getHeaders(auth = true) {
    const headers = {
        'Content-Type': 'application/json'
    };
    if (auth) {
        const token = localStorage.getItem('authToken');
        if (token) headers['Authorization'] = `Bearer ${token}`;
    }
    return headers;
}

// Error handler
window.handleAPIError = (error, message = "Something went wrong.") => {
    console.error("❌", error);
    document.getElementById('register-result').textContent = message;
};

// Form logic
document.addEventListener('DOMContentLoaded', () => {
    const registerForm = document.getElementById('register-form');

    if (!registerForm) {
        console.error("❌ Register form not found in DOM.");
        return;
    }

    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const username = document.getElementById('register-username')?.value?.trim();
        const email = document.getElementById('register-email')?.value?.trim();
        const password = document.getElementById('register-password')?.value?.trim();

        if (!username || !email || !password) {
            showAlert("⚠️ Please fill in all fields: username, email, and password.");
            return;
        }

        const userData = { username, email, password };
        console.log("📩 Submitting user registration form:", userData);
        showLoader();

        try {
            const response = await fetch(`${API_BASE}/register`, {
                method: 'POST',
                headers: getHeaders(false), // ⬅️ false disables auth header
                body: JSON.stringify(userData)
            });

            // Handle Conflict (409) - Duplicate username or email
            if (response.status === 409) {
                const err = await response.json();
                showAlert("⚠️ Username or email already exists. Please try again.");
                return;
            }

            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.message || 'Registration failed');
            }

            const result = await response.json();
            console.log("✅ Registration successful:", result);

            if (result.user) {
                storeTokens(result.access_token, result.refresh_token, result.user);
            }

            document.getElementById('register-result').textContent = "🎉 Registration successful! Redirecting...";
            setTimeout(() => {
                window.location.href = "/dashboard"; // Redirect path
            }, 2000);

        } catch (error) {
            handleAPIError(error, "Registration failed. Please try again.");
        } finally {
            hideLoader();
        }
    });
});

