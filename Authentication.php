<?php
session_start();
require_once 'db_connect.php';

/**
 * Validates user credentials
 */
function login($username, $password, $pdo) {
    $stmt = $pdo->prepare("SELECT id, password FROM users WHERE username = ? LIMIT 1");
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user['password'])) {
        // Prevent Session Fixation
        session_regenerate_id(true);
        
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['last_login'] = time();
        return true;
    }
    
    return false;
}

/**
 * Protects private pages
 */
function check_auth() {
    if (!isset($_SESSION['user_id'])) {
        header("Location: login_form.php?error=unauthorized");
        exit();
    }
}

/**
 * Destroys session
 */
function logout() {
    session_unset();
    session_destroy();
    header("Location: login_form.php");
    exit();
}
