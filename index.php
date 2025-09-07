<?php
// Define file paths for data storage
define('USERS_FILE', 'users.json');
define('WEBSITES_FILE', 'websites.json');
define('STATUS_LOGS_FILE', 'status_logs.json');

// Initialize data files if they don't exist
function initDataFiles() {
    if (!file_exists(USERS_FILE)) {
        file_put_contents(USERS_FILE, json_encode([]));
    }
    if (!file_exists(WEBSITES_FILE)) {
        file_put_contents(WEBSITES_FILE, json_encode([]));
    }
    if (!file_exists(STATUS_LOGS_FILE)) {
        file_put_contents(STATUS_LOGS_FILE, json_encode([]));
    }
}

// Initialize data files
initDataFiles();

// Session management
session_start();

// Authentication functions
function registerUser($username, $email, $password) {
    $users = json_decode(file_get_contents(USERS_FILE), true);
    
    // Check if username already exists
    foreach ($users as $user) {
        if ($user['username'] === $username) {
            return false;
        }
    }
    
    // Add new user
    $users[] = [
        'id' => uniqid(),
        'username' => $username,
        'email' => $email,
        'password' => password_hash($password, PASSWORD_DEFAULT),
        'telegram_bot_token' => '',
        'telegram_chat_id' => '',
        'created_at' => date('Y-m-d H:i:s')
    ];
    
    return file_put_contents(USERS_FILE, json_encode($users));
}

function loginUser($username, $password) {
    $users = json_decode(file_get_contents(USERS_FILE), true);
    
    foreach ($users as $user) {
        if ($user['username'] === $username && password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            return true;
        }
    }
    
    return false;
}

function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function getCurrentUser() {
    if (!isLoggedIn()) return null;
    
    $users = json_decode(file_get_contents(USERS_FILE), true);
    
    foreach ($users as $user) {
        if ($user['id'] === $_SESSION['user_id']) {
            return $user;
        }
    }
    
    return null;
}

function logoutUser() {
    session_destroy();
    header("Location: index.php");
    exit;
}

// Website monitoring functions
function addWebsite($url, $name, $interval = 5, $proxy = null) {
    if (!isLoggedIn()) return false;
    
    $websites = json_decode(file_get_contents(WEBSITES_FILE), true);
    
    $websites[] = [
        'id' => uniqid(),
        'user_id' => $_SESSION['user_id'],
        'url' => $url,
        'name' => $name,
        'check_interval' => $interval,
        'proxy' => $proxy,
        'is_active' => true,
        'created_at' => date('Y-m-d H:i:s')
    ];
    
    return file_put_contents(WEBSITES_FILE, json_encode($websites));
}

function getWebsites() {
    if (!isLoggedIn()) return [];
    
    $websites = json_decode(file_get_contents(WEBSITES_FILE), true);
    $userWebsites = [];
    
    foreach ($websites as $website) {
        if ($website['user_id'] === $_SESSION['user_id']) {
            $userWebsites[] = $website;
        }
    }
    
    return $userWebsites;
}

function checkWebsiteStatus($websiteId) {
    $websites = json_decode(file_get_contents(WEBSITES_FILE), true);
    $website = null;
    
    foreach ($websites as $w) {
        if ($w['id'] === $websiteId) {
            $website = $w;
            break;
        }
    }
    
    if (!$website) return false;
    
    $startTime = microtime(true);
    
    // Set up options for the request
    $options = [
        'http' => [
            'method' => 'GET',
            'header' => "User-Agent: UptimeMonitor/1.0\r\n",
            'timeout' => 10,
            'ignore_errors' => true
        ]
    ];
    
    // Add proxy if configured
    if (!empty($website['proxy'])) {
        $options['http']['proxy'] = $website['proxy'];
        $options['http']['request_fulluri'] = true;
    }
    
    $context = stream_context_create($options);
    
    try {
        $response = file_get_contents($website['url'], false, $context);
        $statusCode = isset($http_response_header[0]) ? extractStatusCode($http_response_header[0]) : 0;
        $isOnline = $statusCode >= 200 && $statusCode < 400;
    } catch (Exception $e) {
        $statusCode = 0;
        $isOnline = false;
    }
    
    $responseTime = round(microtime(true) - $startTime, 2);
    
    // Log the status
    $logs = json_decode(file_get_contents(STATUS_LOGS_FILE), true);
    $logs[] = [
        'id' => uniqid(),
        'website_id' => $websiteId,
        'status_code' => $statusCode,
        'response_time' => $responseTime,
        'is_online' => $isOnline,
        'checked_at' => date('Y-m-d H:i:s')
    ];
    file_put_contents(STATUS_LOGS_FILE, json_encode($logs));
    
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

function extractStatusCode($header) {
    preg_match('/HTTP\/\d\.\d\s(\d{3})/', $header, $matches);
    return isset($matches[1]) ? (int)$matches[1] : 0;
}

function sendTelegramNotification($website) {
    $users = json_decode(file_get_contents(USERS_FILE), true);
    $user = null;
    
    foreach ($users as $u) {
        if ($u['id'] === $website['user_id']) {
            $user = $u;
            break;
        }
    }
    
    if (!$user || empty($user['telegram_bot_token']) || empty($user['telegram_chat_id'])) {
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
    @file_get_contents($url, false, $context);
    
    return true;
}

function getWebsiteStats($websiteId) {
    $logs = json_decode(file_get_contents(STATUS_LOGS_FILE), true);
    $websiteLogs = [];
    
    // Get logs for this website from the last 24 hours
    $oneDayAgo = strtotime('-1 day');
    
    foreach ($logs as $log) {
        if ($log['website_id'] === $websiteId && strtotime($log['checked_at']) >= $oneDayAgo) {
            $websiteLogs[] = $log;
        }
    }
    
    if (count($websiteLogs) > 0) {
        $totalChecks = count($websiteLogs);
        $onlineChecks = 0;
        $totalResponseTime = 0;
        
        foreach ($websiteLogs as $log) {
            if ($log['is_online']) {
                $onlineChecks++;
            }
            $totalResponseTime += $log['response_time'];
        }
        
        $uptimePercentage = round(($onlineChecks / $totalChecks) * 100, 2);
        $avgResponseTime = round($totalResponseTime / $totalChecks, 2);
    } else {
        $uptimePercentage = 0;
        $avgResponseTime = 0;
    }
    
    return [
        'uptime_percentage' => $uptimePercentage,
        'avg_response_time' => $avgResponseTime,
        'logs' => $websiteLogs
    ];
}

function updateTelegramSettings($botToken, $chatId) {
    if (!isLoggedIn()) return false;
    
    $users = json_decode(file_get_contents(USERS_FILE), true);
    
    foreach ($users as &$user) {
        if ($user['id'] === $_SESSION['user_id']) {
            $user['telegram_bot_token'] = $botToken;
            $user['telegram_chat_id'] = $chatId;
            break;
        }
    }
    
    return file_put_contents(USERS_FILE, json_encode($users));
}

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'register':
                if (registerUser($_POST['username'], $_POST['email'], $_POST['password'])) {
                    header("Location: index.php?message=Registration successful. Please login.");
                    exit;
                } else {
                    $error = "Username already exists";
                }
                break;
                
            case 'login':
                if (loginUser($_POST['username'], $_POST['password'])) {
                    header("Location: dashboard.php");
                    exit;
                } else {
                    $error = "Invalid username or password";
                }
                break;
                
            case 'add_website':
                if (addWebsite($_POST['url'], $_POST['name'], $_POST['check_interval'], $_POST['proxy'])) {
                    header("Location: dashboard.php?message=Website added successfully");
                    exit;
                }
                break;
                
            case 'update_telegram':
                if (updateTelegramSettings($_POST['bot_token'], $_POST['chat_id'])) {
                    header("Location: dashboard.php?message=Telegram settings updated");
                    exit;
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

// Get current user
$currentUser = getCurrentUser();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Uptime Monitor</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --primary: #4361ee;
            --secondary: #3f37c9;
            --success: #4cc9f0;
            --danger: #f72585;
            --dark: #212529;
            --light: #f8f9fa;
        }
        
        body {
            background-color: #f5f7fb;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .navbar {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }
        
        .card {
            border-radius: 12px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08);
            transition: transform 0.3s ease;
            border: none;
            margin-bottom: 20px;
        }
        
        .card:hover {
            transform: translateY(-5px);
        }
        
        .card-header {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
            border-radius: 12px 12px 0 0 !important;
            font-weight: 600;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            border: none;
            border-radius: 8px;
            padding: 10px 20px;
            font-weight: 600;
        }
        
        .btn-primary:hover {
            background: linear-gradient(135deg, var(--secondary), var(--primary));
            transform: translateY(-2px);
        }
        
        .status-badge {
            padding: 8px 15px;
            border-radius: 30px;
            font-weight: 600;
        }
        
        .status-online {
            background-color: rgba(76, 201, 240, 0.2);
            color: #4cc9f0;
        }
        
        .status-offline {
            background-color: rgba(247, 37, 133, 0.2);
            color: #f72585;
        }
        
        .dashboard-stat {
            text-align: center;
            padding: 20px;
            border-radius: 12px;
            background: white;
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.05);
        }
        
        .stat-value {
            font-size: 2.5rem;
            font-weight: 700;
            margin: 10px 0;
        }
        
        .stat-label {
            font-size: 0.9rem;
            color: #6c757d;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .website-card {
            border-left: 4px solid var(--primary);
        }
        
        .website-card.offline {
            border-left-color: var(--danger);
        }
        
        .login-container {
            max-width: 400px;
            margin: 100px auto;
            padding: 30px;
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
        }
        
        .form-control {
            border-radius: 8px;
            padding: 12px 15px;
            border: 1px solid #e2e8f0;
        }
        
        .form-control:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 0.25rem rgba(67, 97, 238, 0.15);
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container">
            <a class="navbar-brand" href="index.php">
                <i class="fas fa-heartbeat me-2"></i>Uptime Monitor
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <?php if (isLoggedIn()): ?>
                        <li class="nav-item">
                            <span class="nav-link">Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?></span>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="dashboard.php">Dashboard</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="?action=logout">Logout</a>
                        </li>
                    <?php else: ?>
                        <li class="nav-item">
                            <a class="nav-link" href="index.php">Login</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="index.php?register=1">Register</a>
                        </li>
                    <?php endif; ?>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container py-4">
        <?php if (isset($_GET['message'])): ?>
            <div class="alert alert-info alert-dismissible fade show" role="alert">
                <?php echo htmlspecialchars($_GET['message']); ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>

        <?php if (isset($error)): ?>
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                <?php echo htmlspecialchars($error); ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>

        <?php if (!isLoggedIn()): ?>
            <!-- Login/Registration Form -->
            <div class="login-container">
                <?php if (isset($_GET['register'])): ?>
                    <h2 class="text-center mb-4">Create Account</h2>
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
                        <button type="submit" class="btn btn-primary w-100">Register</button>
                        <div class="text-center mt-3">
                            <a href="index.php">Already have an account? Login</a>
                        </div>
                    </form>
                <?php else: ?>
                    <h2 class="text-center mb-4">Login</h2>
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
                        <button type="submit" class="btn btn-primary w-100">Login</button>
                        <div class="text-center mt-3">
                            <a href="index.php?register=1">Create an account</a>
                        </div>
                    </form>
                <?php endif; ?>
            </div>
        <?php else: ?>
            <!-- Dashboard Content -->
            <div class="row">
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-plus-circle me-2"></i>Add Website to Monitor
                        </div>
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
                                <button type="submit" class="btn btn-primary w-100">
                                    <i class="fas fa-plus me-2"></i>Add Website
                                </button>
                            </form>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <i class="fab fa-telegram me-2"></i>Telegram Notification Settings
                        </div>
                        <div class="card-body">
                            <form method="POST">
                                <input type="hidden" name="action" value="update_telegram">
                                <div class="mb-3">
                                    <label class="form-label">Bot Token</label>
                                    <input type="text" name="bot_token" class="form-control" 
                                           value="<?php echo htmlspecialchars($currentUser['telegram_bot_token'] ?? ''); ?>">
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Chat ID</label>
                                    <input type="text" name="chat_id" class="form-control" 
                                           value="<?php echo htmlspecialchars($currentUser['telegram_chat_id'] ?? ''); ?>">
                                </div>
                                <button type="submit" class="btn btn-primary w-100">
                                    <i class="fas fa-save me-2"></i>Save Settings
                                </button>
                            </form>
                        </div>
                    </div>
                </div>

                <div class="col-md-8">
                    <h2 class="mb-4">Monitored Websites</h2>
                    
                    <?php
                    $websites = getWebsites();
                    if (count($websites) > 0):
                        foreach ($websites as $website):
                            $stats = getWebsiteStats($website['id']);
                            $lastCheck = checkWebsiteStatus($website['id']);
                    ?>
                    <div class="card website-card <?php echo $lastCheck && $lastCheck['is_online'] ? '' : 'offline'; ?>">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <h5 class="mb-0">
                                <i class="fas fa-globe me-2"></i><?php echo htmlspecialchars($website['name']); ?>
                            </h5>
                            <form method="POST" class="d-inline">
                                <input type="hidden" name="action" value="check_website">
                                <input type="hidden" name="website_id" value="<?php echo $website['id']; ?>">
                                <button type="submit" class="btn btn-sm btn-outline-primary">
                                    <i class="fas fa-sync-alt me-1"></i>Check Now
                                </button>
                            </form>
                        </div>
                        <div class="card-body">
                            <p><strong>URL:</strong> <?php echo htmlspecialchars($website['url']); ?></p>
                            <p><strong>Check Interval:</strong> Every <?php echo $website['check_interval']; ?> minutes</p>
                            
                            <div class="row mb-3">
                                <div class="col-md-4">
                                    <div class="dashboard-stat">
                                        <div class="stat-label">Uptime (24h)</div>
                                        <div class="stat-value <?php echo $stats['uptime_percentage'] > 95 ? 'status-online' : 'status-offline'; ?>">
                                            <?php echo $stats['uptime_percentage']; ?>%
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-4">
                                    <div class="dashboard-stat">
                                        <div class="stat-label">Avg. Response Time</div>
                                        <div class="stat-value"><?php echo $stats['avg_response_time']; ?>s</div>
                                    </div>
                                </div>
                                <div class="col-md-4">
                                    <div class="dashboard-stat">
                                        <div class="stat-label">Status</div>
                                        <?php if ($lastCheck && $lastCheck['is_online']): ?>
                                            <div class="stat-value status-online">Online</div>
                                        <?php else: ?>
                                            <div class="stat-value status-offline">Offline</div>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="mt-3">
                                <canvas id="chart-<?php echo $website['id']; ?>" height="100"></canvas>
                            </div>
                        </div>
                    </div>
                    <?php endforeach; else: ?>
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i>
                        You haven't added any websites to monitor yet. Add one using the form on the left.
                    </div>
                    <?php endif; ?>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Simple chart initialization
        document.addEventListener('DOMContentLoaded', function() {
            <?php
            if (isLoggedIn() && count($websites) > 0):
                foreach ($websites as $website):
                    $stats = getWebsiteStats($website['id']);
                    $labels = [];
                    $data = [];
                    
                    // Get last 10 logs for the chart
                    $recentLogs = array_slice(array_reverse($stats['logs']), 0, 10);
                    
                    foreach ($recentLogs as $log) {
                        $labels[] = date('H:i', strtotime($log['checked_at']));
                        $data[] = $log['response_time'];
                    }
            ?>
            var ctx = document.getElementById('chart-<?php echo $website['id']; ?>').getContext('2d');
            var chart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: <?php echo json_encode($labels); ?>,
                    datasets: [{
                        label: 'Response Time (s)',
                        data: <?php echo json_encode($data); ?>,
                        borderColor: 'rgb(67, 97, 238)',
                        backgroundColor: 'rgba(67, 97, 238, 0.1)',
                        tension: 0.1,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Seconds'
                            }
                        },
                        x: {
                            title: {
                                display: true,
                                text: 'Time'
                            }
                        }
                    }
                }
            });
            <?php
                endforeach;
            endif;
            ?>
        });
    </script>
</body>
</html>
