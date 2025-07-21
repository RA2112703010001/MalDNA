import { handleAPIError, showLoader, hideLoader, showAlert } from './utils.js';

const API_BASE = 'http://localhost:5000/api/user';

// Register a new user
export async function registerUser(userData) {
    try {
        showLoader();
        const response = await fetch(`${API_BASE}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(userData)
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.message || "Registration failed");

        showAlert('User registered successfully.');
        return data;
    } catch (error) {
        handleAPIError(error, "User registration failed.");
    } finally {
        hideLoader();
    }
}

// Login existing user
export async function loginUser(credentials) {
    try {
        showLoader();
        const response = await fetch(`${API_BASE}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(credentials)
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.message || "Login failed");

        // Store both the access and refresh tokens in localStorage
        localStorage.setItem('authToken', data.access_token); // Store the access token
        localStorage.setItem('refreshToken', data.refresh_token); // Store the refresh token

        showAlert('Login successful.');
        return data;
    } catch (error) {
        handleAPIError(error, "Login failed.");
    } finally {
        hideLoader();
    }
}

// Refresh access token
export async function refreshAuthToken() {
    const refreshToken = localStorage.getItem('refreshToken');
    if (!refreshToken) return;

    try {
        const response = await fetch(`${API_BASE}/refresh`, {
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
export async function listUsers() {
    try {
        showLoader();
        let token = localStorage.getItem('authToken'); // Retrieve the access token from localStorage

        if (!token) {
            // If no token is found, redirect to login page
            window.location.href = '/login'; // Redirect to login page if no token is available
            return;
        }

        // Attempt to fetch data
        const response = await fetch(`${API_BASE}/list`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}` // Send the access token in the Authorization header
            }
        });

        if (!response.ok && response.status === 401) {
            // If unauthorized (token expired), attempt to refresh the token
            token = await refreshAuthToken();
            if (token) {
                // Retry the request with the new token
                return await listUsers(); // Retry fetching users after refreshing the token
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
export async function updateUserRole(userId, newRole) {
    try {
        showLoader();
        let token = localStorage.getItem('authToken'); // Retrieve the access token from localStorage

        if (!token) {
            // If no token is found, redirect to login page
            window.location.href = '/login'; // Redirect to login page if no token is available
            return;
        }

        // Attempt to update user role
        const response = await fetch(`${API_BASE}/update_role/${userId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}` // Send the access token in the Authorization header
            },
            body: JSON.stringify({ role: newRole })
        });

        if (!response.ok && response.status === 401) {
            // If unauthorized (token expired), attempt to refresh the token
            token = await refreshAuthToken();
            if (token) {
                // Retry the request with the new token
                return await updateUserRole(userId, newRole); // Retry after refreshing the token
            }
        }

        const data = await response.json();
        if (!response.ok) throw new Error(data.message || "Role update failed");

        showAlert('User role updated successfully.');
        return data;
    } catch (error) {
        handleAPIError(error, "Failed to update user role.");
    } finally {
        hideLoader();
    }
}

// Deactivate a user (admin)
export async function deactivateUser(userId) {
    try {
        showLoader();
        let token = localStorage.getItem('authToken'); // Retrieve the access token from localStorage

        if (!token) {
            // If no token is found, redirect to login page
            window.location.href = '/login'; // Redirect to login page if no token is available
            return;
        }

        // Attempt to deactivate the user
        const response = await fetch(`${API_BASE}/deactivate/${userId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}` // Send the access token in the Authorization header
            }
        });

        if (!response.ok && response.status === 401) {
            // If unauthorized (token expired), attempt to refresh the token
            token = await refreshAuthToken();
            if (token) {
                // Retry the request with the new token
                return await deactivateUser(userId); // Retry after refreshing the token
            }
        }

        const data = await response.json();
        if (!response.ok) throw new Error(data.message || "Deactivation failed");

        showAlert('User deactivated.');
        return data;
    } catch (error) {
        handleAPIError(error, "Failed to deactivate user.");
    } finally {
        hideLoader();
    }
}

