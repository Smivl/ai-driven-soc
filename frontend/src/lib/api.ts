// Shared HTTP client for talking to the backend. Every call goes through here so
// the login token is attached automatically and an expired session sends the
// user back to the login page.

import axios from "axios";

export const TOKEN_KEY = "soc_token";

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL ?? "http://localhost:8000",
  headers: {
    "Content-Type": "application/json",
  },
});

// Attach the JWT (if present) to every request.
api.interceptors.request.use((config) => {
  const token = sessionStorage.getItem(TOKEN_KEY);
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// On 401, drop the stale session and bounce to login.
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      sessionStorage.removeItem(TOKEN_KEY);
      sessionStorage.removeItem("soc_user");
      if (window.location.pathname !== "/login") {
        window.location.href = "/login";
      }
    }
    return Promise.reject(error);
  },
);
