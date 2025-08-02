<?php
// config.php - Database connection
$host = 'localhost';
$dbname = 'quickdesk';
$username = 'root';
$password = '';

$conn = new mysqli($host, $username, $password, $dbname);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
    }
    ?>

    <!-- register.php -->
    <?php
    include 'config.php';

    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        $fullname = $_POST['fullname'];
            $email = $_POST['email'];
                $username = $_POST['username'];
                    $password = password_hash($_POST['password'], PASSWORD_DEFAULT);
                        $role = $_POST['role'];

                            $stmt = $conn->prepare("INSERT INTO users (fullname, email, username, password, role) VALUES (?, ?, ?, ?, ?)");
                                $stmt->bind_param("sssss", $fullname, $email, $username, $password, $role);
                                    
                                        if ($stmt->execute()) {
                                                header("Location: ../index.html");
                                                    } else {
                                                            echo "Error: " . $stmt->error;
                                                                }
                                                                    $stmt->close();
                                                                        $conn->close();
                                                                        }
                                                                        ?>

                                                                        <!-- login.php -->
                                                                        <?php
                                                                        include 'config.php';
                                                                        session_start();

                                                                        if ($_SERVER['REQUEST_METHOD'] == 'POST') {
                                                                            $username = $_POST['username'];
                                                                                $password = $_POST['password'];
                                                                                    $role = $_POST['role'];

                                                                                        $stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND role = ?");
                                                                                            $stmt->bind_param("ss", $username, $role);
                                                                                                $stmt->execute();
                                                                                                    $result = $stmt->get_result();

                                                                                                        if ($result->num_rows === 1) {
                                                                                                                $user = $result->fetch_assoc();
                                                                                                                        if (password_verify($password, $user['password'])) {
                                                                                                                                    $_SESSION['user_id'] = $user['id'];
                                                                                                                                                $_SESSION['role'] = $user['role'];

                                                                                                                                                            if ($role == 'user') header("Location: ../dashboard.html");
                                                                                                                                                                        elseif ($role == 'agent') header("Location: ../agent_dashboard.html");
                                                                                                                                                                                    elseif ($role == 'admin') header("Location: ../admin_dashboard.html");
                                                                                                                                                                                                exit();
                                                                                                                                                                                                        }
                                                                                                                                                                                                            }
                                                                                                                                                                                                                echo "Invalid credentials.";
                                                                                                                                                                                                                }
                                                                                                                                                                                                                ?>

                                                                                                                                                                                                                <!-- create_ticket.php -->
                                                                                                                                                                                                                <?php
                                                                                                                                                                                                                include 'config.php';
                                                                                                                                                                                                                session_start();

                                                                                                                                                                                                                if ($_SERVER['REQUEST_METHOD'] == 'POST') {
                                                                                                                                                                                                                    $user_id = $_SESSION['user_id'];
                                                                                                                                                                                                                        $subject = $_POST['subject'];
                                                                                                                                                                                                                            $category = $_POST['category'];
                                                                                                                                                                                                                                $description = $_POST['description'];

                                                                                                                                                                                                                                    $attachment = '';
                                                                                                                                                                                                                                        if (isset($_FILES['attachment']) && $_FILES['attachment']['error'] == 0) {
                                                                                                                                                                                                                                                $upload_dir = '../uploads/';
                                                                                                                                                                                                                                                        $attachment = basename($_FILES['attachment']['name']);
                                                                                                                                                                                                                                                                move_uploaded_file($_FILES['attachment']['tmp_name'], $upload_dir . $attachment);
                                                                                                                                                                                                                                                                    }

                                                                                                                                                                                                                                                                        $stmt = $conn->prepare("INSERT INTO tickets (user_id, subject, category, description, attachment, status) VALUES (?, ?, ?, ?, ?, 'Open')");
                                                                                                                                                                                                                                                                            $stmt->bind_param("issss", $user_id, $subject, $category, $description, $attachment);

                                                                                                                                                                                                                                                                                if ($stmt->execute()) {
                                                                                                                                                                                                                                                                                        header("Location: ../view_ticket.html");
                                                                                                                                                                                                                                                                                            } else {
                                                                                                                                                                                                                                                                                                    echo "Error: " . $stmt->error;
                                                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                                                            $stmt->close();
                                                                                                                                                                                                                                                                                                                $conn->close();
                                                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                                                ?>

                                                                                                                                                                                                                                                                                                                <!-- fetch_tickets.php -->
                                                                                                                                                                                                                                                                                                                <?php
                                                                                                                                                                                                                                                                                                                include 'config.php';
                                                                                                                                                                                                                                                                                                                session_start();

                                                                                                                                                                                                                                                                                                                $status = $_GET['status'] ?? '';
                                                                                                                                                                                                                                                                                                                $sort = $_GET['sort'] ?? 'date_created DESC';
                                                                                                                                                                                                                                                                                                                $role = $_GET['role'] ?? '';
                                                                                                                                                                                                                                                                                                                $user_id = $_SESSION['user_id'] ?? null;

                                                                                                                                                                                                                                                                                                                $sql = "SELECT * FROM tickets";
                                                                                                                                                                                                                                                                                                                $conditions = [];

                                                                                                                                                                                                                                                                                                                if ($role == 'user' && $user_id) {
                                                                                                                                                                                                                                                                                                                    $conditions[] = "user_id = $user_id";
                                                                                                                                                                                                                                                                                                                    } elseif ($role == 'agent' && $user_id) {
                                                                                                                                                                                                                                                                                                                        $conditions[] = "assigned_to = $user_id";
                                                                                                                                                                                                                                                                                                                        }

                                                                                                                                                                                                                                                                                                                        if (!empty($status)) {
                                                                                                                                                                                                                                                                                                                            $conditions[] = "status = '" . $conn->real_escape_string($status) . "'";
                                                                                                                                                                                                                                                                                                                            }

                                                                                                                                                                                                                                                                                                                            if (!empty($conditions)) {
                                                                                                                                                                                                                                                                                                                                $sql .= " WHERE " . implode(" AND ", $conditions);
                                                                                                                                                                                                                                                                                                                                }

                                                                                                                                                                                                                                                                                                                                $sql .= " ORDER BY $sort";

                                                                                                                                                                                                                                                                                                                                $result = $conn->query($sql);
                                                                                                                                                                                                                                                                                                                                $tickets = [];

                                                                                                                                                                                                                                                                                                                                if ($result->num_rows > 0) {
                                                                                                                                                                                                                                                                                                                                    while ($row = $result->fetch_assoc()) {
                                                                                                                                                                                                                                                                                                                                            $tickets[] = $row;
                                                                                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                                                                                }

                                                                                                                                                                                                                                                                                                                                                header('Content-Type: application/json');
                                                                                                                                                                                                                                                                                                                                                echo json_encode($tickets);
                                                                                                                                                                                                                                                                                                                                                ?>
                                                                                                                                                                                                                                                                                                                                                