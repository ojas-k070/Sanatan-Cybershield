// VULNERABILITY: Hardcoded Credentials
// const API_KEY = "12345-ABCDE-SECRET-KEY";
// const DB_PASSWORD = "admin_password_2026";

// Recommendation: Store API keys and database passwords securely using environment variables or a secrets management system.
const API_KEY = process.env.API_KEY;
const DB_PASSWORD = process.env.DB_PASSWORD;