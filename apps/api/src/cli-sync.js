import 'dotenv/config';
import path from 'node:path';
import { createDatabase } from './db.js';
import { SyncEngine } from './sync.js';

const databasePath = path.resolve(process.env.DATABASE_PATH || './data/sentinel.db');
const db = createDatabase(databasePath);
const engine = new SyncEngine(db, process.env);
const results = await engine.syncAll();
console.log(JSON.stringify(results, null, 2));
db.close();
