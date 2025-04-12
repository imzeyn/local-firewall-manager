CREATE DATABASE firewall_logs;

USE firewall_logs;

CREATE TABLE logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    ip VARCHAR(45) NOT NULL,
    port INT,
    protocol VARCHAR(10),
    reason TEXT
);
