const bcrypt = require("bcrypt");
const sql = require("mssql/msnodesqlv8");

const cfg = {
  connectionString: "Driver={ODBC Driver 17 for SQL Server};Server=(localdb)\\MSSQLLocalDB;Database=MSKTraders;Trusted_Connection=Yes;"
};

bcrypt.hash("1234", 10).then(async (hash) => {
  const pool = await sql.connect(cfg);
  await pool.request()
    .input("pw", sql.NVarChar(255), hash)
    .query("UPDATE admin SET password = @pw WHERE username = 'admin'");
  console.log("✅ Password updated successfully!");
  console.log("🔐 Length:", hash.length, "(should be 60)");
  process.exit(0);
}).catch(err => {
  console.error("❌ Error:", err.message);
  process.exit(1);
});