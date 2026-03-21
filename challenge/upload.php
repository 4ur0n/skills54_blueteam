<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];
    if ($file['error'] !== UPLOAD_ERR_OK) {
        http_response_code(400);
        echo json_encode(['error' => 'Upload error: ' . $file['error']]);
        exit;
    }
    $dest = __DIR__ . '/uploads/' . basename($file['name']);
    if (move_uploaded_file($file['tmp_name'], $dest)) {
        echo json_encode([
            'success' => true,
            'filename' => basename($file['name']),
            'url' => '/uploads/' . basename($file['name']),
        ]);
    } else {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to move file']);
    }
} else {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
}
