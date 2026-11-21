import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';

export function createDatabase(databasePath) {
  fs.mkdirSync(path.dirname(databasePath), { recursive: true });
  const db = new Database(databasePath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      expires_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS vulnerabilities (
      cve_id TEXT PRIMARY KEY,
      description TEXT,
      published TEXT,
      modified TEXT,
      severity TEXT,
      cvss_score REAL,
      cvss_vector TEXT,
      cwes TEXT NOT NULL DEFAULT '[]',
      cpes TEXT NOT NULL DEFAULT '[]',
      "references" TEXT NOT NULL DEFAULT '[]',
      source_metadata TEXT NOT NULL,
      retrieved_at TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS epss_scores (
      cve_id TEXT PRIMARY KEY,
      score REAL,
      percentile REAL,
      score_date TEXT,
      source_metadata TEXT NOT NULL,
      retrieved_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS osv_records (
      osv_id TEXT NOT NULL,
      ecosystem TEXT NOT NULL,
      package_name TEXT NOT NULL,
      queried_version TEXT NOT NULL,
      summary TEXT,
      details TEXT,
      severity TEXT,
      published TEXT,
      modified TEXT,
      cve_ids TEXT NOT NULL DEFAULT '[]',
      fixed_versions TEXT NOT NULL DEFAULT '[]',
      "references" TEXT NOT NULL DEFAULT '[]',
      source_metadata TEXT NOT NULL,
      retrieved_at TEXT NOT NULL,
      PRIMARY KEY (osv_id, ecosystem, package_name, queried_version)
    );

    CREATE TABLE IF NOT EXISTS kev_records (
      cve_id TEXT PRIMARY KEY,
      vendor_project TEXT,
      product TEXT,
      date_added TEXT,
      due_date TEXT,
      required_action TEXT,
      known_ransomware_campaign_use TEXT,
      short_description TEXT,
      source_metadata TEXT NOT NULL,
      retrieved_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS source_records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      provider TEXT NOT NULL,
      record_id TEXT NOT NULL,
      source_url TEXT NOT NULL,
      retrieved_at TEXT NOT NULL,
      last_modified TEXT,
      source_update TEXT,
      data_version TEXT,
      license TEXT,
      payload TEXT,
      UNIQUE(provider, record_id)
    );

    CREATE TABLE IF NOT EXISTS source_status (
      provider TEXT PRIMARY KEY,
      availability TEXT NOT NULL,
      last_attempt_at TEXT,
      last_success_at TEXT,
      last_error TEXT,
      records_retrieved INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS sync_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      provider TEXT NOT NULL,
      status TEXT NOT NULL,
      started_at TEXT NOT NULL,
      completed_at TEXT,
      records_processed INTEGER NOT NULL DEFAULT 0,
      message TEXT,
      error TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
    CREATE INDEX IF NOT EXISTS idx_vulnerabilities_published ON vulnerabilities(published);
  `);

  // Correct older accidental schema variants safely.
  db.exec(`
    CREATE TABLE IF NOT EXISTS remediation_tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cve_id TEXT,
      title TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'open',
      owner TEXT,
      due_at TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      completed_at TEXT
    );
  `);

  return db;
}
