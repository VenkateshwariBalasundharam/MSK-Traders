CREATE DATABASE MSKTraders;

USE MSKTraders;

-- Create Suppliers Table
CREATE TABLE suppliers (
  Id        INT IDENTITY(1,1) PRIMARY KEY,
  name      NVARCHAR(100) NOT NULL,
  contact   NVARCHAR(20)  NOT NULL,
  createdAt DATETIME DEFAULT GETDATE()
);

-- Create Products Table
CREATE TABLE products (
  Id             INT IDENTITY(1,1) PRIMARY KEY,
  name           NVARCHAR(100) NOT NULL,
  batch_no       NVARCHAR(50)  NOT NULL,
  supplier       NVARCHAR(100),
  category       NVARCHAR(50),
  quantity       INT           DEFAULT 0,
  purchase_price DECIMAL(10,2) DEFAULT 0,
  selling_price  DECIMAL(10,2) DEFAULT 0,
  expiry_date    DATE,
  status         NVARCHAR(20)  DEFAULT 'Received',
  createdAt      DATETIME DEFAULT GETDATE()
);

-- View all products
SELECT * FROM products ORDER BY createdAt DESC;

-- View all suppliers
SELECT * FROM suppliers ORDER BY name ASC;

-- Count total products
SELECT COUNT(*) AS total_products FROM products;

-- Count total suppliers
SELECT COUNT(*) AS total_suppliers FROM suppliers;

drop table suppliers

-- Insert sample suppliers
INSERT INTO suppliers (name, contact) VALUES
  ('MedLife Pharma',    '9876543210'),
  ('Sun Pharma Ltd',    '9123456780'),
  ('Cipla Distributors','9988776655'),
  ('Apollo Medicines',  '9001122334');

-- Insert sample products
INSERT INTO products (name, batch_no, supplier, category, quantity, purchase_price, selling_price, expiry_date, status) VALUES
  ('Paracetamol 500mg', 'B1001', 'MedLife Pharma',     'Tablet',    200, 10.00, 15.00, '2025-12-31', 'Received'),
  ('Amoxicillin 250mg', 'B1002', 'Sun Pharma Ltd',     'Capsule',   150, 25.00, 35.00, '2025-06-30', 'Received'),
  ('Cough Syrup 100ml', 'B1003', 'Cipla Distributors', 'Syrup',      30, 40.00, 60.00, '2024-03-01', 'Received'),
  ('Vitamin C Tablet',  'B1004', 'Apollo Medicines',   'Tablet',     20, 5.00,  10.00, '2026-01-15', 'Pending'),
  ('Eye Drops 10ml',    'B1005', 'MedLife Pharma',     'Drops',      80, 30.00, 45.00, '2025-09-20', 'Received');

-- Verify
SELECT Id, username, password, LEN(password) AS length FROM admin;

Select * from admin

-- Add purchase_date column to existing products table
ALTER TABLE products
ADD purchase_date DATE NULL;