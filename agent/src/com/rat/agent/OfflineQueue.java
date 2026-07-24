package com.rat.agent;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import org.json.JSONObject;

public class OfflineQueue {

    private static final String DB_NAME = "rat_queue.db";
    private static final int DB_VERSION = 1;
    private final SQLiteOpenHelper helper;

    public OfflineQueue(Context ctx) {
        helper = new SQLiteOpenHelper(ctx, DB_NAME, null, DB_VERSION) {
            @Override
            public void onCreate(SQLiteDatabase db) {
                db.execSQL("CREATE TABLE IF NOT EXISTS queue (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                    "cmd_id TEXT," +
                    "data_type TEXT," +
                    "payload TEXT," +
                    "created_at INTEGER," +
                    "sent INTEGER DEFAULT 0)");
            }
            @Override
            public void onUpgrade(SQLiteDatabase db, int oldV, int newV) {
                db.execSQL("DROP TABLE IF EXISTS queue");
                onCreate(db);
            }
        };
    }

    public void enqueue(String cmdId, String dataType, String payload) {
        SQLiteDatabase db = helper.getWritableDatabase();
        ContentValues cv = new ContentValues();
        cv.put("cmd_id", cmdId);
        cv.put("data_type", dataType);
        cv.put("payload", payload);
        cv.put("created_at", System.currentTimeMillis());
        cv.put("sent", 0);
        db.insert("queue", null, cv);
    }

    public int getPendingCount() {
        SQLiteDatabase db = helper.getReadableDatabase();
        Cursor c = db.rawQuery("SELECT COUNT(*) FROM queue WHERE sent=0", null);
        int count = 0;
        if (c.moveToFirst()) count = c.getInt(0);
        c.close();
        return count;
    }

    public Cursor getUnsent() {
        SQLiteDatabase db = helper.getReadableDatabase();
        return db.rawQuery("SELECT * FROM queue WHERE sent=0 ORDER BY created_at ASC", null);
    }

    public void markSent(int id) {
        SQLiteDatabase db = helper.getWritableDatabase();
        ContentValues cv = new ContentValues();
        cv.put("sent", 1);
        db.update("queue", cv, "id=?", new String[]{String.valueOf(id)});
    }

    public void clearSent() {
        SQLiteDatabase db = helper.getWritableDatabase();
        db.delete("queue", "sent=1", null);
    }

    public void clearAll() {
        SQLiteDatabase db = helper.getWritableDatabase();
        db.delete("queue", null, null);
    }
}
