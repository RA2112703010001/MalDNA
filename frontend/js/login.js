import { handleAPIError, showLoader, hideLoader, showAlert } from './utils.js';

const API_BASE = 'http://localhost:5000/api/user';

// DOMContentLoaded ensures the DOM is fully loaded before the script runs
document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const loginForm = document.getElementById('loginForm');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const loginMessage = document.getElementById('loginMessage');

    // Check if loginForm exists
    if (!loginForm) {
        console.error('loginForm element not found!');
        return;
    }

    // Handle Login
    loginForm.addEventListener('submit', async (event) => {
        event.preventDefault(); // Prevent form submission

        const username = usernameInput.value.trim();
        const password = passwordInput.value.trim();

        if (!username || !password) {
            loginMessage.textContent = "Username and password are required.";
            loginMessage.style.color = 'red';
            return;
        }

        try {
            showLoader();
            const response = await fetch(`${API_BASE}/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();
            if (!response.ok) throw new Error(data.message || "Login failed");

            // Store tokens in localStorage
            localStorage.setItem('authToken', data.access_token); // Store the access token
            localStorage.setItem('refreshToken', data.refresh_token); // Store the refresh token

            // Optionally store user data if needed
            localStorage.setItem('user', JSON.stringify(data.user));

            // Success message and redirect
            loginMessage.textContent = "Login successful.";
            loginMessage.style.color = 'green';
            window.location.href = '/dashboard'; // Redirect to dashboard
        } catch (error) {
            loginMessage.textContent = "An error occurred. Please try again later.";
            loginMessage.style.color = 'red';
        } finally {
            hideLoader();
        }
    });

    // Refresh access token if needed
    async function refreshAuthToken() {
        const refreshToken = localStorage.getItem('refreshToken');
        if (!refreshToken) return;

        try {
            const response = await fetch(`${API_BASE}/token/refresh`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ refresh_token: refreshToken })
            });

            const data = await response.json();
            if (!response.ok) throw new Error(data.message || "Failed to refresh token");

            // Update tokens in localStorage
            localStorage.setItem('authToken', data.access_token); // Update the access token
            localStorage.setItem('refreshToken', data.refresh_token); // Update the refresh token
            return data.access_token;
        } catch (error) {
            console.error("Error refreshing token:", error);
        }
    }

    // List all users (admin feature)
    async function listUsers() {
        try {
            showLoader();
            let token = localStorage.getItem('authToken'); // Retrieve the access token from localStorage

            if (!token) {
                window.location.href = '/login'; // Redirect to login page if no token is available
                return;
            }

            const response = await fetch(`${API_BASE}/list`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                }
            });

            if (!response.ok && response.status === 401) {
                token = await refreshAuthToken();
                if (token) {
                    return await listUsers(); // Retry after refreshing the token
                }
            }

            const data = await response.json();
            if (!response.ok) throw new Error(data.message || "Failed to fetch users");
            return data;
        } catch (error) {
            handleAPIError(error, "Could not retrieve users.");
        } finally {
            hideLoader();
        }
    }

    // Update user role (admin)
    async function updateUserRole(userId, newRole) {
        try {
            showLoader();
            let token = localStorage.getItem('authToken');

            if (!token) {
                window.location.href = '/login'; // Redirect to login page
                return;
            }

            const response = await fetch(`${API_BASE}/update_role/${userId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ role: newRole })
            });

            if (!response.ok && response.status === 401) {
                token = await refreshAuthToken();
                if (token) {
                    return await updateUserRole(userId, newRole); // Retry after refreshing the token
                }
            }

            const data = await response.json();
            if (!response.ok) throw new Error(data.message || "Failed to update role");
            return data;
        } catch (error) {
            handleAPIError(error, "Failed to update user role.");
        } finally {
            hideLoader();
        }
    }

    // Optional: Handle form submission via enter key
    passwordInput.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
            loginForm.submit();
        }
    });
});

