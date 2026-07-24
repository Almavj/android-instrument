package com.instrument.test;

import android.Manifest;
import android.app.Activity;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.provider.ContactsContract;
import android.provider.MediaStore;
import android.util.Log;
import android.widget.TextView;

import androidx.core.app.ActivityCompat;
import androidx.core.app.NotificationCompat;
import androidx.core.content.ContextCompat;

import java.io.File;
import java.io.FileOutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * Test App for Android Instrumentation Validation.
 *
 * Requests common permissions and logs sensor data to a local SQLite database.
 * Displays a persistent notification. No network communication.
 * Purpose: validates that the instrumentation framework correctly hooks API calls.
 */
public class MainActivity extends Activity {

    private static final String TAG = "InstrumentTest";
    private static final String CHANNEL_ID = "research_channel";
    private static final int NOTIFICATION_ID = 9999;
    private static final int PERMISSION_REQUEST_CODE = 100;

    private SQLiteDatabase db;
    private Handler handler;
    private LocationManager locationManager;
    private TextView statusText;
    private boolean monitoring = false;

    private final String[] requiredPermissions = {
        Manifest.permission.READ_SMS,
        Manifest.permission.READ_CONTACTS,
        Manifest.permission.READ_CALL_LOG,
        Manifest.permission.CAMERA,
        Manifest.permission.RECORD_AUDIO,
        Manifest.permission.ACCESS_FINE_LOCATION,
        Manifest.permission.ACCESS_COARSE_LOCATION,
        Manifest.permission.READ_PHONE_STATE,
        Manifest.permission.READ_EXTERNAL_STORAGE,
        Manifest.permission.WRITE_EXTERNAL_STORAGE,
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        statusText = findViewById(R.id.status_text);
        handler = new Handler(Looper.getMainLooper());

        createNotificationChannel();
        startForegroundNotification();

        db = new InstrumentDB(this).getWritableDatabase();
        locationManager = (LocationManager) getSystemService(LOCATION_SERVICE);

        requestPermissions();

        logEvent("app_start", "Application launched");
        statusText.setText("Test App Active\nLogging to local database\nNo data sent externally");
    }

    private void createNotificationChannel() {
        NotificationChannel channel = new NotificationChannel(
            CHANNEL_ID,
            "Research Monitoring",
            NotificationManager.IMPORTANCE_LOW
        );
        channel.setDescription("Instrumentation test - research use only");
        NotificationManager nm = getSystemService(NotificationManager.class);
        nm.createNotificationChannel(channel);
    }

    private void startForegroundNotification() {
        Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Test App - Data Logging Active")
            .setContentText("Research instrumentation running. All data stays local.")
            .setSmallIcon(android.R.drawable.ic_menu_info_details)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build();

        startForeground(NOTIFICATION_ID, notification);
    }

    private void requestPermissions() {
        boolean allGranted = true;
        for (String perm : requiredPermissions) {
            if (ContextCompat.checkSelfPermission(this, perm) != PackageManager.PERMISSION_GRANTED) {
                allGranted = false;
                break;
            }
        }
        if (!allGranted) {
            ActivityCompat.requestPermissions(this, requiredPermissions, PERMISSION_REQUEST_CODE);
        } else {
            onAllPermissionsGranted();
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        if (requestCode == PERMISSION_REQUEST_CODE) {
            StringBuilder sb = new StringBuilder("Permission results:\n");
            for (int i = 0; i < permissions.length; i++) {
                String status = grantResults[i] == PackageManager.PERMISSION_GRANTED ? "GRANTED" : "DENIED";
                sb.append(permissions[i].substring(permissions[i].lastIndexOf('.') + 1))
                  .append(": ").append(status).append("\n");
                logEvent("permission", permissions[i] + " -> " + status);
            }
            statusText.setText(sb.toString());
            onAllPermissionsGranted();
        }
    }

    private void onAllPermissionsGranted() {
        monitoring = true;
        startLocationMonitoring();
        startPeriodicLogging();
        logEvent("monitoring", "All monitoring started");
    }

    private void startLocationMonitoring() {
        try {
            if (ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED) {
                locationManager.requestLocationUpdates(
                    LocationManager.GPS_PROVIDER, 5000, 10,
                    new LocationListener() {
                        @Override
                        public void onLocationChanged(Location location) {
                            logEvent("location",
                                String.format(Locale.US, "lat=%.6f lon=%.6f acc=%.1f",
                                    location.getLatitude(), location.getLongitude(),
                                    location.getAccuracy()));
                        }
                        @Override public void onStatusChanged(String provider, int status, Bundle extras) {}
                        @Override public void onProviderEnabled(String provider) {}
                        @Override public void onProviderDisabled(String provider) {}
                    }
                );
                logEvent("location", "GPS monitoring started");
            }
        } catch (Exception e) {
            logEvent("location_error", e.getMessage());
        }
    }

    private void startPeriodicLogging() {
        handler.postDelayed(new Runnable() {
            @Override
            public void run() {
                if (!monitoring) return;

                logEvent("periodic", "heartbeat");

                logInstalledApps();
                logDeviceInfo();
                logClipboard();

                handler.postDelayed(this, 30000);
            }
        }, 5000);
    }

    private void logInstalledApps() {
        try {
            int count = getPackageManager().getInstalledPackages(0).size();
            logEvent("installed_apps", "count=" + count);
        } catch (Exception e) {
            logEvent("installed_apps_error", e.getMessage());
        }
    }

    private void logDeviceInfo() {
        String info = String.format(Locale.US,
            "model=%s sdk=%d battery=%d",
            android.os.Build.MODEL,
            android.os.Build.VERSION.SDK_INT,
            getBatteryLevel()
        );
        logEvent("device_info", info);
    }

    private int getBatteryLevel() {
        try {
            android.os.BatteryManager bm = (android.os.BatteryManager) getSystemService(BATTERY_SERVICE);
            return bm.getIntProperty(android.os.BatteryManager.BATTERY_PROPERTY_CAPACITY);
        } catch (Exception e) {
            return -1;
        }
    }

    private void logClipboard() {
        try {
            android.content.ClipboardManager cm = (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            if (cm.hasPrimaryClip()) {
                CharSequence text = cm.getPrimaryClip().getItemAt(0).getText();
                logEvent("clipboard", text != null ? text.toString() : "null");
            }
        } catch (Exception e) {
            logEvent("clipboard_error", e.getMessage());
        }
    }

    private void logEvent(String type, String data) {
        try {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US);
            String timestamp = sdf.format(new Date());
            long threadId = Thread.currentThread().getId();

            ContentValues values = new ContentValues();
            values.put("timestamp", timestamp);
            values.put("thread_id", threadId);
            values.put("event_type", type);
            values.put("data", data);
            db.insert("events", null, values);

            Log.d(TAG, String.format("[%s] %s: %s", timestamp, type, data));
        } catch (Exception e) {
            Log.e(TAG, "Failed to log event", e);
        }
    }

    @Override
    protected void onDestroy() {
        monitoring = false;
        if (db != null && db.isOpen()) {
            logEvent("app_stop", "Application destroyed");
            db.close();
        }
        super.onDestroy();
    }

    static class InstrumentDB extends SQLiteOpenHelper {
        private static final String DB_NAME = "instrumentation.db";
        private static final int DB_VERSION = 1;

        InstrumentDB(Context context) {
            super(context, DB_NAME, null, DB_VERSION);
        }

        @Override
        public void onCreate(SQLiteDatabase db) {
            db.execSQL(
                "CREATE TABLE events (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "timestamp TEXT," +
                "thread_id INTEGER," +
                "event_type TEXT," +
                "data TEXT)"
            );
            db.execSQL(
                "CREATE TABLE api_calls (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "timestamp INTEGER," +
                "thread_id INTEGER," +
                "api_name TEXT," +
                "args TEXT," +
                "result TEXT)"
            );
            db.execSQL(
                "CREATE TABLE network_log (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "timestamp INTEGER," +
                "thread_id INTEGER," +
                "url TEXT," +
                "method TEXT," +
                "headers TEXT," +
                "response_code INTEGER)"
            );
            db.execSQL(
                "CREATE TABLE file_access (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "timestamp INTEGER," +
                "thread_id INTEGER," +
                "path TEXT," +
                "operation TEXT," +
                "size INTEGER)"
            );
            db.execSQL(
                "CREATE TABLE sensor_log (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "timestamp INTEGER," +
                "sensor_type TEXT," +
                "data TEXT)"
            );
        }

        @Override
        public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
            db.execSQL("DROP TABLE IF EXISTS events");
            db.execSQL("DROP TABLE IF EXISTS api_calls");
            db.execSQL("DROP TABLE IF EXISTS network_log");
            db.execSQL("DROP TABLE IF EXISTS file_access");
            db.execSQL("DROP TABLE IF EXISTS sensor_log");
            onCreate(db);
        }
    }
}
