// ============================================
//  MSK TRADERS - Node.js + SQL Server Backend
//  server.js — LocalDB Version (Windows Auth)
// ============================================

const express = require("express");
const sql     = require("mssql/msnodesqlv8");
const cors    = require("cors");
const path    = require("path");

const app  = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ============================================
//  SQL SERVER CONFIG — LocalDB Windows Auth
// ============================================
const dbConfig = {
  connectionString: "Driver={ODBC Driver 17 for SQL Server};Server=(localdb)\\MSSQLLocalDB;Database=MSKTraders;Trusted_Connection=Yes;"
};

// ============================================
//  DB CONNECTION POOL
// ============================================
let pool;

async function connectDB() {
  try {
    pool = await sql.connect(dbConfig);
    console.log("✅ Connected to SQL Server (LocalDB) successfully!");
    await createTables();
  } catch (err) {
    console.error("❌ SQL Server connection failed:");
    console.error("   Message :", err.message);
    console.error("   Code    :", err.code);
    console.error("   Full    :", JSON.stringify(err, null, 2));
    process.exit(1);
  }
}

// ============================================
//  AUTO CREATE TABLES
// ============================================
async function createTables() {
  try {
    // Suppliers table
    await pool.request().query(`
      IF NOT EXISTS (
        SELECT * FROM sysobjects WHERE name='suppliers' AND xtype='U'
      )
      CREATE TABLE suppliers (
        id        INT IDENTITY(1,1) PRIMARY KEY,
        name      NVARCHAR(100) NOT NULL,
        contact   NVARCHAR(20)  NOT NULL,
        createdAt DATETIME      DEFAULT GETDATE()
      )
    `);

    // Products table
    await pool.request().query(`
      IF NOT EXISTS (
        SELECT * FROM sysobjects WHERE name='products' AND xtype='U'
      )
      CREATE TABLE products (
        id             INT IDENTITY(1,1) PRIMARY KEY,
        name           NVARCHAR(100) NOT NULL,
        batch_no       NVARCHAR(50)  NOT NULL,
        supplier       NVARCHAR(100),
        category       NVARCHAR(50),
        quantity       INT           DEFAULT 0,
        purchase_price DECIMAL(10,2) DEFAULT 0,
        selling_price  DECIMAL(10,2) DEFAULT 0,
        purchase_date  DATE,
        expiry_date    DATE,
        status         NVARCHAR(20)  DEFAULT 'Received',
        createdAt      DATETIME      DEFAULT GETDATE()
      )
    `);

    // Admin table — stores username & password
    await pool.request().query(`
      IF NOT EXISTS (
        SELECT * FROM sysobjects WHERE name='admin' AND xtype='U'
      )
      CREATE TABLE admin (
        id        INT IDENTITY(1,1) PRIMARY KEY,
        username  NVARCHAR(50)  NOT NULL UNIQUE,
        password  NVARCHAR(100) NOT NULL,
        updatedAt DATETIME      DEFAULT GETDATE()
      )
    `);

    // Insert default admin if not exists (username: admin, password: 1234)
    await pool.request().query(`
      IF NOT EXISTS (SELECT * FROM admin WHERE username = 'admin')
      INSERT INTO admin (username, password) VALUES ('admin', '1234')
    `);

    console.log("✅ Tables ready (products, suppliers, admin)");
  } catch (err) {
    console.error("❌ Table creation failed:", err.message);
  }
}

// ============================================
//  API — STATUS
// ============================================
app.get("/api/status", (req, res) => {
  if (!pool) {
    return res.status(500).json({ status: "disconnected" });
  }
  res.json({ status: "connected", message: "LocalDB connected successfully" });
});

// ============================================
//  API — DEBUG (check admin table)
//  Visit: http://localhost:3000/api/debug-admin
// ============================================
app.get("/api/debug-admin", async (req, res) => {
  try {
    const result = await pool.request().query(`
      SELECT
        id,
        username,
        password,
        LEN(password)        AS pw_length,
        DATALENGTH(password) AS pw_bytes,
        updatedAt
      FROM admin
    `);
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================
//  API — AUTH (Login & Password Change)
// ============================================

// POST — Login
app.post("/api/login", async (req, res) => {
  const username = (req.body.username || "").trim();
  const password = (req.body.password || "").trim();

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  try {
    // Get ALL admin records and compare in JS to avoid SQL encoding issues
    const result = await pool.request().query(`SELECT id, username, password FROM admin`);

    console.log("All admin records:", JSON.stringify(result.recordset));
    console.log("Login attempt — username:", username, "| password:", password);

    const admin = result.recordset.find(a =>
      a.username.trim().toLowerCase() === username.toLowerCase() &&
      a.password.trim() === password
    );

    if (!admin) {
      console.log("Login FAILED — no matching record");
      return res.status(401).json({ error: "Invalid username or password" });
    }

    console.log("Login SUCCESS for:", admin.username);
    res.json({ success: true, username: admin.username });

  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST — Change Password
app.post("/api/change-password", async (req, res) => {
  const username        = (req.body.username        || "").trim();
  const currentPassword = (req.body.currentPassword || "").trim();
  const newPassword     = (req.body.newPassword     || "").trim();

  if (!username || !currentPassword || !newPassword) {
    return res.status(400).json({ error: "All fields are required" });
  }

  if (newPassword.length < 4) {
    return res.status(400).json({ error: "New password must be at least 4 characters" });
  }

  try {
    // Get all admin records and compare in JS
    const result = await pool.request().query(`SELECT id, username, password FROM admin`);

    console.log("Change PW — all records:", JSON.stringify(result.recordset));
    console.log("Change PW — entered current:", currentPassword);

    const admin = result.recordset.find(a =>
      a.username.trim().toLowerCase() === username.toLowerCase() &&
      a.password.trim() === currentPassword
    );

    if (!admin) {
      console.log("Change PW FAILED — current password incorrect");
      return res.status(401).json({ error: "Current password is incorrect" });
    }

    // Update with new password
    await pool.request()
      .input("id",          sql.Int,           admin.id)
      .input("newPassword", sql.NVarChar(100), newPassword)
      .query(`
        UPDATE admin
        SET password  = @newPassword,
            updatedAt = GETDATE()
        WHERE id = @id
      `);

    console.log(`Password changed for: ${username} → new: ${newPassword}`);
    res.json({ success: true, message: "Password changed successfully" });

  } catch (err) {
    console.error("Change PW error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================
//  API — PRODUCTS
// ============================================

// GET all products
app.get("/api/products", async (req, res) => {
  try {
    const result = await pool.request().query(`
      SELECT
        id,
        name,
        batch_no,
        supplier,
        category,
        quantity,
        purchase_price,
        selling_price,
        CONVERT(VARCHAR(10), purchase_date, 23) AS purchase_date,
        CONVERT(VARCHAR(10), expiry_date,   23) AS expiry_date,
        status,
        createdAt
      FROM products
      ORDER BY createdAt DESC
    `);
    res.json(result.recordset);
  } catch (err) {
    console.error("GET /api/products error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST — add product
app.post("/api/products", async (req, res) => {
  const {
    name, batch_no, supplier, category,
    quantity, purchase_price, selling_price,
    purchase_date, expiry_date, status
  } = req.body;

  if (!name || !batch_no || !quantity || !expiry_date) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    const result = await pool.request()
      .input("name",           sql.NVarChar(100), name)
      .input("batch_no",       sql.NVarChar(50),  batch_no)
      .input("supplier",       sql.NVarChar(100), supplier       || "")
      .input("category",       sql.NVarChar(50),  category       || "")
      .input("quantity",       sql.Int,            parseInt(quantity))
      .input("purchase_price", sql.Decimal(10,2),  parseFloat(purchase_price) || 0)
      .input("selling_price",  sql.Decimal(10,2),  parseFloat(selling_price)  || 0)
      .input("purchase_date",  sql.Date,           purchase_date  || null)
      .input("expiry_date",    sql.Date,           expiry_date)
      .input("status",         sql.NVarChar(20),  status         || "Received")
      .query(`
        INSERT INTO products
          (name, batch_no, supplier, category, quantity,
           purchase_price, selling_price, purchase_date, expiry_date, status)
        OUTPUT
          INSERTED.id,
          INSERTED.name,
          INSERTED.batch_no,
          INSERTED.supplier,
          INSERTED.category,
          INSERTED.quantity,
          INSERTED.purchase_price,
          INSERTED.selling_price,
          CONVERT(VARCHAR(10), INSERTED.purchase_date, 23) AS purchase_date,
          CONVERT(VARCHAR(10), INSERTED.expiry_date,   23) AS expiry_date,
          INSERTED.status
        VALUES
          (@name, @batch_no, @supplier, @category, @quantity,
           @purchase_price, @selling_price, @purchase_date, @expiry_date, @status)
      `);
    res.json(result.recordset[0]);
  } catch (err) {
    console.error("POST /api/products error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// PUT — update product
app.put("/api/products/:id", async (req, res) => {
  const {
    name, batch_no, supplier, category,
    quantity, purchase_price, selling_price,
    purchase_date, expiry_date, status
  } = req.body;

  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: "Invalid product ID" });

  try {
    const result = await pool.request()
      .input("id",             sql.Int,            id)
      .input("name",           sql.NVarChar(100), name)
      .input("batch_no",       sql.NVarChar(50),  batch_no)
      .input("supplier",       sql.NVarChar(100), supplier       || "")
      .input("category",       sql.NVarChar(50),  category       || "")
      .input("quantity",       sql.Int,            parseInt(quantity))
      .input("purchase_price", sql.Decimal(10,2),  parseFloat(purchase_price) || 0)
      .input("selling_price",  sql.Decimal(10,2),  parseFloat(selling_price)  || 0)
      .input("purchase_date",  sql.Date,           purchase_date  || null)
      .input("expiry_date",    sql.Date,           expiry_date)
      .input("status",         sql.NVarChar(20),  status         || "Received")
      .query(`
        UPDATE products SET
          name           = @name,
          batch_no       = @batch_no,
          supplier       = @supplier,
          category       = @category,
          quantity       = @quantity,
          purchase_price = @purchase_price,
          selling_price  = @selling_price,
          purchase_date  = @purchase_date,
          expiry_date    = @expiry_date,
          status         = @status
        WHERE id = @id
      `);

    if (result.rowsAffected[0] === 0) {
      return res.status(404).json({ error: "Product not found" });
    }
    res.json({ success: true, message: "Product updated" });
  } catch (err) {
    console.error("PUT /api/products error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// DELETE — product
app.delete("/api/products/:id", async (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: "Invalid product ID" });

  try {
    const result = await pool.request()
      .input("id", sql.Int, id)
      .query("DELETE FROM products WHERE id = @id");

    if (result.rowsAffected[0] === 0) {
      return res.status(404).json({ error: "Product not found" });
    }
    res.json({ success: true, message: "Product deleted" });
  } catch (err) {
    console.error("DELETE /api/products error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================
//  API — SUPPLIERS
// ============================================

// GET all suppliers
app.get("/api/suppliers", async (req, res) => {
  try {
    const result = await pool.request().query(`
      SELECT id, name, contact, createdAt
      FROM suppliers
      ORDER BY name ASC
    `);
    res.json(result.recordset);
  } catch (err) {
    console.error("GET /api/suppliers error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST — add supplier
app.post("/api/suppliers", async (req, res) => {
  const { name, contact } = req.body;

  if (!name || !contact) {
    return res.status(400).json({ error: "Missing required fields: name, contact" });
  }

  try {
    const result = await pool.request()
      .input("name",    sql.NVarChar(100), name)
      .input("contact", sql.NVarChar(20),  contact)
      .query(`
        INSERT INTO suppliers (name, contact)
        OUTPUT INSERTED.id, INSERTED.name, INSERTED.contact
        VALUES (@name, @contact)
      `);
    res.json(result.recordset[0]);
  } catch (err) {
    console.error("POST /api/suppliers error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// DELETE — supplier
app.delete("/api/suppliers/:id", async (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: "Invalid supplier ID" });

  try {
    const result = await pool.request()
      .input("id", sql.Int, id)
      .query("DELETE FROM suppliers WHERE id = @id");

    if (result.rowsAffected[0] === 0) {
      return res.status(404).json({ error: "Supplier not found" });
    }
    res.json({ success: true, message: "Supplier deleted" });
  } catch (err) {
    console.error("DELETE /api/suppliers error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================
//  STATIC ROUTES — serve HTML pages explicitly
// ============================================
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "login.html"));
});

app.get("/login.html", (req, res) => {
  res.sendFile(path.join(__dirname, "login.html"));
});

app.get("/index.html", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Catch all other routes — serve index.html
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// ============================================
//  START SERVER
// ============================================
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log("================================================");
    console.log(`🚀  Server running at http://localhost:${PORT}`);
    console.log(`🌐  Open browser → http://localhost:${PORT}`);
    console.log("================================================");
  });
}).catch(err => {
  console.error("Failed to start:", err.message);
  process.exit(1);
});