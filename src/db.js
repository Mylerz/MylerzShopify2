import Dexie from 'dexie';

export const db = new Dexie('myDatabase');
db.version(1).stores({
  tokens: 'key, value', // Primary key and indexed props
});