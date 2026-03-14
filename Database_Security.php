<?php
/**
 * DATABASE SECURITY LAYER
 * Purpose: Prevent SQL Injection, XSS, and handle connection hardening.
 */

class DatabaseSecurity {
    private static $instance = null;

    /**
     * Hardened PDO Connection
     * Uses SSL (if available) and disables prepared statement emulation.
     */
    public static function getConnection() {
        if (self::$instance === null) {
            $host = 'localhost';
            $db   = 'my_secure_app';
            $user = 'db_user';
            $pass = 'your_ultra_strong_password';
            
            $dsn = "mysql:host=$host;dbname=$db;charset=utf8mb4";
            
            $options = [
                // 1. Force real prepared statements (stops SQL Injection)
                PDO::ATTR_EMULATE_PREPARES   => false, 
                // 2. Throw exceptions for every tiny error
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                // 3. Fetch as associative arrays by default
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                // 4. Secure connection (uncomment if using SSL)
                // PDO::MYSQL_ATTR_SSL_CA => '/path/to/ca-cert.pem',
            ];

            try {
                self::$instance = new PDO($dsn, $user, $pass, $options);
            } catch (PDOException $e) {
                // Log the error but don't show the user the DB credentials
                error_log("Connection Failed: " . $e->getMessage());
                die("Database connection error. Please check logs.");
            }
        }
        return self::$instance;
    }

    /**
     * Sanitizes output to prevent Cross-Site Scripting (XSS)
     * Use this whenever you echo data from the DB to the HTML.
     */
    public static function xss_clean($data) {
        return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    }

    /**
     * Prevents timing attacks on sensitive comparisons
     */
    public static function secure_compare($a, $b) {
        return hash_equals($a, $b);
    }
}
