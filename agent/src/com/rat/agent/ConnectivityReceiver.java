package com.rat.agent;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Build;
import android.util.Log;

public class ConnectivityReceiver extends BroadcastReceiver {

    private static final String TAG = "RatConnectivity";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (ConnectivityManager.CONNECTIVITY_ACTION.equals(intent.getAction())) {
            ConnectivityManager cm = (ConnectivityManager)
                context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm != null) {
                NetworkInfo ni = cm.getActiveNetworkInfo();
                if (ni != null && ni.isConnected()) {
                    Log.d(TAG, "Network available, starting RatService");
                    Intent serviceIntent = new Intent(context, RatService.class);
                    if (Build.VERSION.SDK_INT >= 26) {
                        context.startForegroundService(serviceIntent);
                    } else {
                        context.startService(serviceIntent);
                    }
                }
            }
        }
    }
}
