<?php
// Database configuration
define('DB_HOST', 'localhost');
define('DB_NAME', 'uptime_monitor');
define('DB_USER', 'root');
define('DB_PASS', '');

// Create database connection
try {
    $pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME, DB_USER, DB_PASS);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Create tables if they don't exist
    $sql = "
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        telegram_bot_token VARCHAR(255) DEFAULT NULL,
        telegram_chat_id VARCHAR(100) DEFAULT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS websites (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        url VARCHAR(255) NOT NULL,
        name VARCHAR(100) NOT NULL,
        check_interval INT DEFAULT 5,
        proxy VARCHAR(255) DEFAULT NULL,
        is_active BOOLEAN DEFAULT TRUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    
    CREATE TABLE IF NOT EXISTS status_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        website_id INT NOT NULL,
        status_code INT,
        response_time FLOAT,
        is_online BOOLEAN,
        checked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (website_id) REFERENCES websites(id) ON DELETE CASCADE
    );
    ";
    
    $pdo->exec($sql);
} catch(PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}

// Session management
session_start();

// Authentication functions
function registerUser($username, $email, $password) {
    global $pdo;
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $pdo->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
    return $stmt->execute([$username, $email, $hashedPassword]);
}

function loginUser($username, $password) {
    global $pdo;
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch();
    
    if ($user && password_verify($password, $user['password'])) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        return true;
    }
    return false;
}

function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function logoutUser() {
    session_destroy();
    header("Location: index.php");
    exit;
}

// Website monitoring functions
function addWebsite($url, $name, $interval = 5, $proxy = null) {
    global $pdo;
    if (!isLoggedIn()) return false;
    
    $stmt = $pdo->prepare("INSERT INTO websites (user_id, url, name, check_interval, proxy) VALUES (?, ?, ?, ?, ?)");
    return $stmt->execute([$_SESSION['user_id'], $url, $name, $interval, $proxy]);
}

function getWebsites() {
    global $pdo;
    if (!isLoggedIn()) return [];
    
    $stmt = $pdo->prepare("SELECT * FROM websites WHERE user_id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    return $stmt->fetchAll();
}

function checkWebsiteStatus($websiteId) {
    global $pdo;
    
    $stmt = $pdo->prepare("SELECT * FROM websites WHERE id = ?");
    $stmt->execute([$websiteId]);
    $website = $stmt->fetch();
    
    if (!$website) return false;
    
    $startTime = microtime(true);
    
    // Set up options for the request
    $options = [
        CURLOPT_URL => $website['url'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_NOBODY => true,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
    ];
    
    // Add proxy if configured
    if (!empty($website['proxy'])) {
        $options[CURLOPT_PROXY] = $website['proxy'];
    }
    
    $ch = curl_init();
    curl_setopt_array($ch, $options);
    curl_exec($ch);
    
    $statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $responseTime = round(microtime(true) - $startTime, 2);
    $isOnline = ($statusCode >= 200 && $statusCode < 400) && curl_errno($ch) === 0;
    
    curl_close($ch);
    
    // Log the status
    $stmt = $pdo->prepare("INSERT INTO status_logs (website_id, status_code, response_time, is_online) VALUES (?, ?, ?, ?)");
    $stmt->execute([$websiteId, $statusCode, $responseTime, $isOnline]);
    
    // Send Telegram notification if website is down
    if (!$isOnline) {
        sendTelegramNotification($website);
    }
    
    return [
        'status_code' => $statusCode,
        'response_time' => $responseTime,
        'is_online' => $isOnline
    ];
}

function sendTelegramNotification($website) {
    global $pdo;
    
    // Get user's Telegram settings
    $stmt = $pdo->prepare("SELECT telegram_bot_token, telegram_chat_id FROM users WHERE id = ?");
    $stmt->execute([$website['user_id']]);
    $user = $stmt->fetch();
    
    if (empty($user['telegram_bot_token']) || empty($user['telegram_chat_id'])) {
        return false;
    }
    
    $message = "🚨 Website Down Alert!\n\n";
    $message .= "Website: " . $website['name'] . "\n";
    $message .= "URL: " . $website['url'] . "\n";
    $message .= "Time: " . date('Y-m-d H:i:s') . "\n";
    $message .= "Status: Offline";
    
    $url = "https://api.telegram.org/bot" . $user['telegram_bot_token'] . "/sendMessage";
    $data = [
        'chat_id' => $user['telegram_chat_id'],
        'text' => $message
    ];
    
    $options = [
        'http' => [
            'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
            'method' => 'POST',
            'content' => http_build_query($data)
        ]
    ];
    
    $context = stream_context_create($options);
    file_get_contents($url, false, $context);
    
    return true;
}

function getWebsiteStats($websiteId) {
    global $pdo;
    
    // Get uptime percentage for last 24 hours
    $stmt = $pdo->prepare("
        SELECT 
            COUNT(*) as total_checks,
            SUM(is_online) as online_checks,
            AVG(response_time) as avg_response_time
        FROM status_logs 
        WHERE website_id = ? AND checked_at >= NOW() - INTERVAL 1 DAY
    ");
    $stmt->execute([$websiteId]);
    $stats = $stmt->fetch();
    
    if ($stats['total_checks'] > 0) {
        $uptimePercentage = round(($stats['online_checks'] / $stats['total_checks']) * 100, 2);
        $avgResponseTime = round($stats['avg_response_time'], 2);
    } else {
        $uptimePercentage = 0;
        $avgResponseTime = 0;
    }
    
    // Get status history for chart
    $stmt = $pdo->prepare("
        SELECT 
            DATE_FORMAT(checked_at, '%Y-%m-%d %H:00') as hour,
            AVG(response_time) as avg_response_time,
            SUM(is_online) as online_count,
            COUNT(*) as total_checks
        FROM status_logs 
        WHERE website_id = ? AND checked_at >= NOW() - INTERVAL 7 DAY
        GROUP BY DATE_FORMAT(checked_at, '%Y-%m-%d %H:00')
        ORDER BY hour
    ");
    $stmt->execute([$websiteId]);
    $history = $stmt->fetchAll();
    
    return [
        'uptime_percentage' => $uptimePercentage,
        'avg_response_time' => $avgResponseTime,
        'history' => $history
    ];
}

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'register':
                if (registerUser($_POST['username'], $_POST['email'], $_POST['password'])) {
                    header("Location: index.php?message=Registration successful. Please login.");
                    exit;
                }
                break;
                
            case 'login':
                if (loginUser($_POST['username'], $_POST['password'])) {
                    header("Location: dashboard.php");
                    exit;
                }
                break;
                
            case 'add_website':
                if (addWebsite($_POST['url'], $_POST['name'], $_POST['check_interval'], $_POST['proxy'])) {
                    header("Location: dashboard.php?message=Website added successfully");
                    exit;
                }
                break;
                
            case 'update_telegram':
                if (isLoggedIn()) {
                    $stmt = $pdo->prepare("UPDATE users SET telegram_bot_token = ?, telegram_chat_id = ? WHERE id = ?");
                    if ($stmt->execute([$_POST['bot_token'], $_POST['chat_id'], $_SESSION['user_id']])) {
                        header("Location: dashboard.php?message=Telegram settings updated");
                        exit;
                    }
                }
                break;
                
            case 'check_website':
                if (isset($_POST['website_id'])) {
                    checkWebsiteStatus($_POST['website_id']);
                    header("Location: dashboard.php");
                    exit;
                }
                break;
        }
    }
}

// Handle logout
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    logoutUser();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Uptime Monitor</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        .card { margin-bottom: 20px; }
        .status-online { color: #28a745; }
        .status-offline { color: #dc3545; }
        .uptime-stats { background: #f8f9fa; padding: 15px; border-radius: 5px; }
        .navbar { margin-bottom: 30px; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="index.php">Uptime Monitor</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <?php if (isLoggedIn()): ?>
                        <li class="nav-item"><a class="nav-link" href="dashboard.php">Dashboard</a></li>
                        <li class="nav-item"><a class="nav-link" href="?action=logout">Logout</a></li>
                    <?php else: ?>
                        <li class="nav-item"><a class="nav-link" href="index.php">Login</a></li>
                        <li class="nav-item"><a class="nav-link" href="index.php?register=1">Register</a></li>
                    <?php endif; ?>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container">
        <?php if (isset($_GET['message'])): ?>
            <div class="alert alert-info"><?= htmlspecialchars($_GET['message']) ?></div>
        <?php endif; ?>

        <?php if (!isLoggedIn()): ?>
            <!-- Login/Registration Form -->
            <?php if (isset($_GET['register'])): ?>
                <div class="row justify-content-center">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">Register</div>
                            <div class="card-body">
                                <form method="POST">
                                    <input type="hidden" name="action" value="register">
                                    <div class="mb-3">
                                        <label class="form-label">Username</label>
                                        <input type="text" name="username" class="form-control" required>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">Email</label>
                                        <input type="email" name="email" class="form-control" required>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">Password</label>
                                        <input type="password" name="password" class="form-control" required>
                                    </div>
                                    <button type="submit" class="btn btn-primary">Register</button>
                                    <a href="index.php" class="btn btn-link">Already have an account? Login</a>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            <?php else: ?>
                <div class="row justify-content-center">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">Login</div>
                            <div class="card-body">
                                <form method="POST">
                                    <input type="hidden" name="action" value="login">
                                    <div class="mb-3">
                                        <label class="form-label">Username</label>
                                        <input type="text" name="username" class="form-control" required>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">Password</label>
                                        <input type="password" name="password" class="form-control" required>
                                    </div>
                                    <button type="submit" class="btn btn-primary">Login</button>
                                    <a href="index.php?register=1" class="btn btn-link">Create an account</a>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endif; ?>
        <?php else: ?>
            <!-- Dashboard Content -->
            <div class="row">
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">Add Website to Monitor</div>
                        <div class="card-body">
                            <form method="POST">
                                <input type="hidden" name="action" value="add_website">
                                <div class="mb-3">
                                    <label class="form-label">Website Name</label>
                                    <input type="text" name="name" class="form-control" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">URL</label>
                                    <input type="url" name="url" class="form-control" placeholder="https://example.com" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Check Interval (minutes)</label>
                                    <input type="number" name="check_interval" class="form-control" value="5" min="1" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Proxy (optional)</label>
                                    <input type="text" name="proxy" class="form-control" placeholder="http://proxyip:port">
                                </div>
                                <button type="submit" class="btn btn-primary">Add Website</button>
                            </form>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">Telegram Notification Settings</div>
                        <div class="card-body">
                            <form method="POST">
                                <input type="hidden" name="action" value="update_telegram">
                                <div class="mb-3">
                                    <label class="form-label">Bot Token</label>
                                    <input type="text" name="bot_token" class="form-control">
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Chat ID</label>
                                    <input type="text" name="chat_id" class="form-control">
                                </div>
                                <button type="submit" class="btn btn-primary">Save Settings</button>
                            </form>
                        </div>
                    </div>
                </div>

                <div class="col-md-8">
                    <h2>Monitored Websites</h2>
                    
                    <?php
                    $websites = getWebsites();
                    if (count($websites) > 0):
                        foreach ($websites as $website):
                            $stats = getWebsiteStats($website['id']);
                    ?>
                    <div class="card">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <h5 class="mb-0"><?= htmlspecialchars($website['name']) ?></h5>
                            <form method="POST" class="d-inline">
                                <input type="hidden" name="action" value="check_website">
                                <input type="hidden" name="website_id" value="<?= $website['id'] ?>">
                                <button type="submit" class="btn btn-sm btn-outline-primary">Check Now</button>
                            </form>
                        </div>
                        <div class="card-body">
                            <p><strong>URL:</strong> <?= htmlspecialchars($website['url']) ?></p>
                            <p><strong>Check Interval:</strong> Every <?= $website['check_interval'] ?> minutes</p>
                            
                            <div class="uptime-stats mb-3">
                                <div class="row">
                                    <div class="col-md-4">
                                        <h6>Uptime (24h)</h6>
                                        <h3 class="<?= $stats['uptime_percentage'] > 95 ? 'status-online' : 'status-offline' ?>">
                                            <?= $stats['uptime_percentage'] ?>%
                                        </h3>
                                    </div>
                                    <div class="col-md-4">
                                        <h6>Avg. Response Time</h6>
                                        <h3><?= $stats['avg_response_time'] ?>s</h3>
                                    </div>
                                    <div class="col-md-4">
                                        <h6>Status</h6>
                                        <?php
                                        $lastCheck = checkWebsiteStatus($website['id']);
                                        if ($lastCheck && $lastCheck['is_online']):
                                        ?>
                                            <span class="status-online"><h3>Online</h3></span>
                                        <?php else: ?>
                                            <span class="status-offline"><h3>Offline</h3></span>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </div>
                            
                            <canvas id="chart-<?= $website['id'] ?>" height="100"></canvas>
                            <script>
                                document.addEventListener('DOMContentLoaded', function() {
                                    var ctx = document.getElementById('chart-<?= $website['id'] ?>').getContext('2d');
                                    var chart = new Chart(ctx, {
                                        type: 'line',
                                        data: {
                                            labels: [<?php 
                                                foreach ($stats['history'] as $point) {
                                                    echo "'" . date('M j H:i', strtotime($point['hour'])) . "',";
                                                }
                                            ?>],
                                            datasets: [{
                                                label: 'Response Time (s)',
                                                data: [<?php 
                                                    foreach ($stats['history'] as $point) {
                                                        echo $point['avg_response_time'] . ',';
                                                    }
                                                ?>],
                                                borderColor: 'rgb(75, 192, 192)',
                                                tension: 0.1
                                            }]
                                        },
                                        options: {
                                            scales: {
                                                y: {
                                                    beginAtZero: true
                                                }
                                            }
                                        }
                                    });
                                });
                            </script>
                        </div>
                    </div>
                    <?php endforeach; else: ?>
                    <div class="alert alert-info">
                        You haven't added any websites to monitor yet. Add one using the form on the left.
                    </div>
                    <?php endif; ?>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
