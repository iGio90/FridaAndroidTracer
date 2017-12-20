traceMethod("android.bluetooth.BluetoothAdapter.getAddress", standardHookMethodPerform);
traceMethod("android.location.LocationManager.requestLocationUpdates", standardHookMethodPerform);
traceMethod("android.location.LocationManager.requestSingleUpdate", standardHookMethodPerform);
traceMethod("android.location.LocationManager.getLastKnownLocation", standardHookMethodPerform);
traceMethod("android.net.wifi.WifiInfo.getMacAddress", standardHookMethodPerform);
traceMethod("android.net.wifi.WifiInfo.getNetworkId", standardHookMethodPerform);
traceMethod("android.net.wifi.WifiInfo.getIpAddress", standardHookMethodPerform);
traceMethod("android.os.Debug.isDebuggerConnected", standardHookMethodPerform);
traceMethod("android.telephony.TelephonyManager.getAllCellInfo", standardHookMethodPerform);
traceMethod("android.telephony.TelephonyManager.getCellLocation", standardHookMethodPerform);
traceMethod("android.telephony.TelephonyManager.getDeviceId", standardHookMethodPerform);
traceMethod("android.telephony.TelephonyManager.getDeviceSoftwareVersion", standardHookMethodPerform);
traceMethod("android.telephony.TelephonyManager.getImei", standardHookMethodPerform);
traceMethod("android.telephony.TelephonyManager.getNeighboringCellInfo", standardHookMethodPerform);
traceMethod("android.telephony.TelephonyManager.getNetworkCountryIso", standardHookMethodPerform);
traceMethod("android.telephony.TelephonyManager.getNetworkOperatorName", standardHookMethodPerform);
traceMethod("android.telephony.TelephonyManager.getSimCountryIso", standardHookMethodPerform);
traceMethod("android.telephony.TelephonyManager.getSimOperatorName", standardHookMethodPerform);
traceMethod("android.telephony.TelephonyManager.getSimSerialNumber", standardHookMethodPerform);
traceMethod("com.google.android.gms.location.FusedLocationProviderClient.getLastLocation", standardHookMethodPerform);
traceMethod("com.google.android.gms.analytics.Tracker.setScreenName", standardHookMethodPerform);

traceMethod("android.context.ContextWrapper.startActivityForResult", onDumpIntentHookMethodPerform);
traceMethod("android.context.ContextWrapper.sendBroadcast", onDumpIntentHookMethodPerform);
traceMethod("android.context.ContextWrapper.startService", onDumpIntentHookMethodPerform);
traceMethod("android.app.Activity.startActivityForResult", onDumpIntentHookMethodPerform);

traceMethod("android.content.ContentResolver.query", onDumpContentResolverHookMethodPerform);

traceClassCtor("java.io.File", {
    "stringsOnly": true,
    "backtrace": false
});

traceNativeFunct("libc.so", "send", function (args) {
    var len = parseInt(args[2]);
    var str = hex2a(ba2hex((Memory.readByteArray(args[1], len))));
    if (exist(str, "http")) {
        var sendMessage = {};
        try {
            sendMessage = getPortsAndAddresses(args[0], true);
        } catch (err) {}

        sendMessage["function"] = "send";
        sendMessage["struct"] = {};
        sendMessage["struct"]["data"] = str;
        send(sendMessage);
    }
}, function (retval) {});

traceNativeFunct("libc.so", "open", function (args) {
    var path = Memory.readUtf8String(args[0]);
    if (// Inclusions
    (exist(path, "super") || exist(path, "/su") ||
        exist(path, ".so") || exist(path, ".jar") ||
        exist(path, "/sdcard/") || exist(path, "/storage/"))
    &&
    // Exclusions
    (!exist(path, "/vendor/") &&
        !exist(path, "/data/dalvik-cache/"))) {
        var openMsg = {};
        openMsg["function"] = "open";
        openMsg["struct"] = {};
        openMsg["struct"]["data"] = path;
        send(openMsg);
    }
}, function (retval) {});

traceNativeFunct("libc.so", "gethostbyname", function (args) {
    var name = Memory.readUtf8String(args[0]);
    var msg = {};
    msg["function"] = "gethostbyname";
    msg["struct"] = {};
    msg["struct"]["data"] = name;
    send(msg);
}, function (retval) {});

traceNativeFunct("libc.so", "gethostbyname2", function (args) {
    var name = Memory.readUtf8String(args[0]);
    var msg = {};
    msg["function"] = "gethostbyname2";
    msg["struct"] = {};
    msg["struct"]["data"] = name;
    send(msg);
}, function (retval) {});

traceNativeFunct("libc.so", "gethostbyname_r", function (args) {
    var name = Memory.readUtf8String(args[0]);
    var msg = {};
    msg["function"] = "gethostbyname_r";
    msg["struct"] = {};
    msg["struct"]["data"] = name;
    send(msg);
}, function (retval) {});

traceNativeFunct("libc.so", "gethostbyname2_r", function (args) {
    var name = Memory.readUtf8String(args[0]);
    var msg = {};
    msg["function"] = "gethostbyname2_r";
    msg["struct"] = {};
    msg["struct"]["data"] = name;
    send(msg);
}, function (retval) {});

traceNativeFunct("libc.so", "gethostbyaddr_r", function (args) {
    var name = Memory.readUtf8String(args[0]);
    var msg = {};
    msg["function"] = "gethostbyaddr_r";
    msg["struct"] = {};
    msg["struct"]["data"] = name;
    send(msg);
}, function (retval) {});

traceNativeFunct("libc.so", "gethostbyaddr", function (args) {
    var name = Memory.readUtf8String(args[0]);
    var msg = {};
    msg["function"] = "gethostbyaddr";
    msg["struct"] = {};
    msg["struct"]["data"] = name;
    send(msg);
}, function (retval) {});

Interceptor.attach(addresses["SSL_write"], {
    onEnter: function (args) {
        var sslWriteMessage = {};
        sslWriteMessage["function"] = "SSL_write";

        sslWriteMessage["struct"] = {};

        var sslInfo = getPortsAndAddresses(SSL_get_fd(args[0]), false);
        sslInfo["ssl_session_id"] = getSslSessionId(args[0]);
        sslWriteMessage["struct"]["sslInfo"] = sslInfo;

        sslWriteMessage["struct"]["data"] = hex2a(ba2hex(Memory.readByteArray(args[1], parseInt(args[2]))));
        send(sslWriteMessage);
    },
    onLeave: function (retval) {
    }
});
