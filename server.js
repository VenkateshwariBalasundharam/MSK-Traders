// ============================================
//  MSK TRADERS - Node.js + SQL Server Backend
//  server.js — LocalDB Version (Windows Auth)
//  ✅ bcrypt password hashing
//  ✅ Tailscale ready (0.0.0.0)
// ============================================

const express = require("express");
const sql     = require("mssql/msnodesqlv8");
const cors    = require("cors");
const path    = require("path");
const bcrypt  = require("bcrypt");

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

    // Admin table — NVARCHAR(255) to hold bcrypt hash
    await pool.request().query(`
      IF NOT EXISTS (
        SELECT * FROM sysobjects WHERE name='admin' AND xtype='U'
      )
      CREATE TABLE admin (
        id        INT IDENTITY(1,1) PRIMARY KEY,
        username  NVARCHAR(50)  NOT NULL UNIQUE,
        password  NVARCHAR(255) NOT NULL,
        updatedAt DATETIME      DEFAULT GETDATE()
      )
    `);

    // Expand column if it was created as NVARCHAR(100) before
    await pool.request().query(`
      IF EXISTS (
        SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_NAME = 'admin'
          AND COLUMN_NAME = 'password'
          AND CHARACTER_MAXIMUM_LENGTH < 255
      )
      ALTER TABLE admin ALTER COLUMN password NVARCHAR(255) NOT NULL
    `);

    // Check if admin row exists
    const existing = await pool.request().query(
      `SELECT COUNT(*) AS cnt FROM admin WHERE username = 'admin'`
    );

    if (existing.recordset[0].cnt === 0) {
      // No admin — create with hashed password
      const hashed = await bcrypt.hash("1234", 10);
      await pool.request()
        .input("username", sql.NVarChar(50),  "admin")
        .input("password", sql.NVarChar(255), hashed)
        .query(`INSERT INTO admin (username, password) VALUES (@username, @password)`);
      console.log("✅ Default admin created with hashed password");
    } else {
      // Admin exists — if password is plain text, upgrade to bcrypt
      const row = await pool.request().query(
        `SELECT id, password FROM admin WHERE username = 'admin'`
      );
      const pw = (row.recordset[0]?.password || "").trim();
      if (!pw.startsWith("$2b$") && !pw.startsWith("$2a$")) {
        const hashed = await bcrypt.hash(pw, 10);
        await pool.request()
          .input("id", sql.Int,           row.recordset[0].id)
          .input("pw", sql.NVarChar(255), hashed)
          .query(`UPDATE admin SET password = @pw WHERE id = @id`);
        console.log("✅ Plain-text password upgraded to bcrypt hash");
      }
    }

    console.log("✅ Tables ready (products, suppliers, admin)");
  } catch (err) {
    console.error("❌ Table creation failed:", err.message);
  }
}

// ============================================
//  API — STATUS
// ============================================
app.get("/api/status", (req, res) => {
  if (!pool) return res.status(500).json({ status: "disconnected" });
  res.json({ status: "connected", message: "LocalDB connected successfully" });
});

// ============================================
//  API — DEBUG (safe, no plain password shown)
// ============================================
app.get("/api/debug-admin", async (req, res) => {
  try {
    const result = await pool.request().query(`
      SELECT id, username,
        LEFT(password, 10) + '...' AS password_preview,
        LEN(password) AS pw_length, updatedAt
      FROM admin
    `);
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================
//  API — LOGIN
// ============================================
app.post("/api/login", async (req, res) => {
  const username = (req.body.username || "").trim();
  const password = (req.body.password || "").trim();

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  try {
    const result = await pool.request().query(
      `SELECT id, username, password FROM admin`
    );

    console.log("Login attempt — username:", username);

    const user = result.recordset.find(a =>
      a.username.trim().toLowerCase() === username.toLowerCase()
    );

    if (!user) {
      console.log("Login FAILED — username not found");
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const match = await bcrypt.compare(password, user.password.trim());

    if (!match) {
      console.log("Login FAILED — wrong password");
      return res.status(401).json({ error: "Invalid username or password" });
    }

    console.log("Login SUCCESS for:", user.username);
    res.json({ success: true, username: user.username });

  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================
//  API — CHANGE PASSWORD
// ============================================
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
    const result = await pool.request().query(
      `SELECT id, username, password FROM admin`
    );

    const user = result.recordset.find(a =>
      a.username.trim().toLowerCase() === username.toLowerCase()
    );

    if (!user) {
      return res.status(401).json({ error: "Current password is incorrect" });
    }

    const match = await bcrypt.compare(currentPassword, user.password.trim());
    if (!match) {
      console.log("Change PW FAILED — wrong current password");
      return res.status(401).json({ error: "Current password is incorrect" });
    }

    const hashedNew = await bcrypt.hash(newPassword, 10);
    await pool.request()
      .input("id", sql.Int,           user.id)
      .input("pw", sql.NVarChar(255), hashedNew)
      .query(`UPDATE admin SET password = @pw, updatedAt = GETDATE() WHERE id = @id`);

    console.log("✅ Password changed for:", username);
    res.json({ success: true, message: "Password changed successfully" });

  } catch (err) {
    console.error("Change PW error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================
//  API — PRODUCTS
// ============================================

app.get("/api/products", async (req, res) => {
  try {
    const result = await pool.request().query(`
      SELECT id, name, batch_no, supplier, category, quantity,
        purchase_price, selling_price,
        CONVERT(VARCHAR(10), purchase_date, 23) AS purchase_date,
        CONVERT(VARCHAR(10), expiry_date,   23) AS expiry_date,
        status, createdAt
      FROM products ORDER BY createdAt DESC
    `);
    res.json(result.recordset);
  } catch (err) {
    console.error("GET /api/products error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

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
          INSERTED.id, INSERTED.name, INSERTED.batch_no, INSERTED.supplier,
          INSERTED.category, INSERTED.quantity, INSERTED.purchase_price,
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
          name = @name, batch_no = @batch_no, supplier = @supplier,
          category = @category, quantity = @quantity,
          purchase_price = @purchase_price, selling_price = @selling_price,
          purchase_date = @purchase_date, expiry_date = @expiry_date, status = @status
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

app.get("/api/suppliers", async (req, res) => {
  try {
    const result = await pool.request().query(`
      SELECT id, name, contact, createdAt FROM suppliers ORDER BY name ASC
    `);
    res.json(result.recordset);
  } catch (err) {
    console.error("GET /api/suppliers error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

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
//  STATIC ROUTES
// ============================================
app.get("/",          (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/login",     (req, res) => res.sendFile(path.join(__dirname, "login.html")));
app.get("/login.html",(req, res) => res.sendFile(path.join(__dirname, "login.html")));
app.get("/index.html",(req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("*",          (req, res) => res.sendFile(path.join(__dirname, "index.html")));

// ============================================
//  START SERVER — 0.0.0.0 for Tailscale
// ============================================
connectDB().then(() => {
  app.listen(PORT, "0.0.0.0", () => {
    console.log("================================================");
    console.log(`🚀  Server running at http://localhost:${PORT}`);
    console.log(`🌐  Open browser → http://localhost:${PORT}`);
    console.log(`🔒  bcrypt hashing     : ENABLED`);
    console.log(`📡  Tailscale (0.0.0.0): ENABLED`);
    console.log("================================================");
  });
}).catch(err => {
  console.error("Failed to start:", err.message);
  process.exit(1);
});