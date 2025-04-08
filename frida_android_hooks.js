/*
 * Android API Hooking Script for CAPA Analysis
 * This script hooks common Android APIs to capture app behaviors
 */

Java.perform(function() {
    // Send events back to Python
    function logEvent(type, api, args, returnValue) {
        var event = {
            type: type,
            api: api,
            args: args ? Array.from(args).map(function(arg) {
                try {
                    return arg ? arg.toString() : null;
                } catch(e) {
                    return "Cannot stringify";
                }
            }) : [],
            timestamp: new Date().toISOString(),
            return_value: returnValue ? returnValue.toString() : null
        };

        send(event);
    }

    console.log("[+] Starting Android API hooks");

    // ======= Network Operations =======
    try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function() {
        var result = this.openConnection();
        logEvent("api_call", "URL.openConnection", [this.toString()], result);
        return result;
        };
    } catch(e) {
        console.log("[-] Error hooking URL: " + e);
    }

    try {
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.connect.implementation = function() {
            var result = this.connect();
            logEvent("api_call", "HttpURLConnection.connect", [this.getURL().toString()], null);
            return result;
        };

        HttpURLConnection.getInputStream.implementation = function() {
            var result = this.getInputStream();
            logEvent("api_call", "HttpURLConnection.getInputStream", [this.getURL().toString()], null);
            return result;
        };

        HttpURLConnection.setRequestMethod.implementation = function(method) {
            var result = this.setRequestMethod(method);
            logEvent("api_call", "HttpURLConnection.setRequestMethod", [this.getURL().toString(), method], null);
            return result;
        };
    } catch(e) {
        console.log("[-] Error hooking HttpURLConnection: " + e);
    }

    // OkHttp (common HTTP library)
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        OkHttpClient.newCall.implementation = function(request) {
            var result = this.newCall(request);
            logEvent("api_call", "OkHttpClient.newCall", [request.url().toString(), request.method()], null);
            return result;
        };
    } catch(e) {
        // OkHttp might not be used in the app
    }

    // ======= File Operations =======
    try {
        var File = Java.use('java.io.File');
        File.$init.overload('java.lang.String').implementation = function(path) {
            logEvent("api_call", "File.new", [path], null);
            return this.$init(path);
        };

        File.exists.implementation = function() {
            var result = this.exists();
            logEvent("api_call", "File.exists", [this.getAbsolutePath()], result);
            return result;
        };

        File.delete.implementation = function() {
            var result = this.delete();
            logEvent("api_call", "File.delete", [this.getAbsolutePath()], result);
            return result;
        };
    } catch(e) {
        console.log("[-] Error hooking File: " + e);
    }

    try {
        var FileOutputStream = Java.use('java.io.FileOutputStream');
        FileOutputStream.$init.overload('java.io.File').implementation = function(file) {
            logEvent("api_call", "FileOutputStream.new", [file.getAbsolutePath()], null);
            return this.$init(file);
        };

        FileOutputStream.$init.overload('java.lang.String').implementation = function(path) {
            logEvent("api_call", "FileOutputStream.new", [path], null);
            return this.$init(path);
        };
    } catch(e) {
        console.log("[-] Error hooking FileOutputStream: " + e);
    }

    try {
        var FileInputStream = Java.use('java.io.FileInputStream');
        FileInputStream.$init.overload('java.io.File').implementation = function(file) {
            logEvent("api_call", "FileInputStream.new", [file.getAbsolutePath()], null);
            return this.$init(file);
        };

        FileInputStream.$init.overload('java.lang.String').implementation = function(path) {
            logEvent("api_call", "FileInputStream.new", [path], null);
            return this.$init(path);
        };
    } catch(e) {
        console.log("[-] Error hooking FileInputStream: " + e);
    }

    // ======= SMS Operations =======
    try {
        var SmsManager = Java.use('android.telephony.SmsManager');
        SmsManager.sendTextMessage.implementation = function(dest, src, text, sentIntent, deliveryIntent) {
            logEvent("api_call", "SmsManager.sendTextMessage", [dest, text], null);
            return this.sendTextMessage(dest, src, text, sentIntent, deliveryIntent);
        };

        // SMS reading
        var Cursor = Java.use('android.database.Cursor');
        if (Cursor) {
            Cursor.getString.implementation = function(column) {
                var result = this.getString(column);
                if (this.getColumnName && this.getColumnName(column) &&
                    (this.getColumnName(column).toString().indexOf("address") >= 0 ||
                     this.getColumnName(column).toString().indexOf("body") >= 0)) {
                    logEvent("api_call", "Cursor.getString", ["sms_data", this.getColumnName(column).toString(), result], null);
                }
                return result;
            };
        }
    } catch(e) {
        console.log("[-] Error hooking SMS: " + e);
    }

    // ======= Device Info Collection =======
    try {
        var TelephonyManager = Java.use('android.telephony.TelephonyManager');
        TelephonyManager.getDeviceId.overload().implementation = function() {
            var id = this.getDeviceId();
            logEvent("api_call", "TelephonyManager.getDeviceId", [], id);
            return id;
        };

        TelephonyManager.getSubscriberId.overload('int').implementation = function(subId) {
          var id = this.getSubscriberId(subId);
          logEvent("api_call", "TelephonyManager.getSubscriberId", [subId], id);
          return id;
        };

        TelephonyManager.getLine1Number.overload().implementation = function() {
          var num = this.getLine1Number();
          logEvent("api_call", "TelephonyManager.getLine1Number", [], num);
          return num;
        };

        TelephonyManager.getSimSerialNumber.implementation = function() {
            var num = this.getSimSerialNumber();
            logEvent("api_call", "TelephonyManager.getSimSerialNumber", [], num);
            return num;
        };
    } catch(e) {
        console.log("[-] Error hooking TelephonyManager: " + e);
    }

    // Device ID info
    try {
        var Settings = Java.use('android.provider.Settings$Secure');
        Settings.getString.implementation = function(resolver, name) {
            var result = this.getString(resolver, name);
            if (name === "android_id") {
                logEvent("api_call", "Settings.Secure.getString", [name], result);
            }
            return result;
        };
    } catch(e) {
        console.log("[-] Error hooking Settings: " + e);
    }

    // ======= Crypto Operations =======
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.getInstance.overload('java.lang.String').implementation = function(transformation) {
            var result = this.getInstance(transformation);
            logEvent("api_call", "Cipher.getInstance", [transformation], null);
            return result;
        };

        Cipher.doFinal.overload('[B').implementation = function(input) {
            var result = this.doFinal(input);
            logEvent("api_call", "Cipher.doFinal", ["<binary data>"], "<binary result>");
            return result;
        };

        Cipher.init.overload('int', 'java.security.Key').implementation = function(mode, key) {
            var modeStr = "UNKNOWN";
            if (mode === 1) modeStr = "ENCRYPT_MODE";
            else if (mode === 2) modeStr = "DECRYPT_MODE";
            else if (mode === 3) modeStr = "WRAP_MODE";
            else if (mode === 4) modeStr = "UNWRAP_MODE";

            logEvent("api_call", "Cipher.init", [modeStr, key.toString()], null);
            return this.init(mode, key);
        };
    } catch(e) {
        console.log("[-] Error hooking Cipher: " + e);
    }

    // ======= Contacts & Content Operations =======
    try {
        var ContentResolver = Java.use('android.content.ContentResolver');
        ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
            logEvent("api_call", "ContentResolver.query", [uri.toString()], null);
            return this.query(uri, projection, selection, selectionArgs, sortOrder);
        };
    } catch(e) {
        console.log("[-] Error hooking ContentResolver: " + e);
    }

    // ======= Location Operations =======
    try {
        var LocationManager = Java.use('android.location.LocationManager');
        LocationManager.requestLocationUpdates.overload('java.lang.String', 'long', 'float', 'android.location.LocationListener').implementation = function(provider, minTime, minDistance, listener) {
            logEvent("api_call", "LocationManager.requestLocationUpdates", [provider, minTime, minDistance], null);
            return this.requestLocationUpdates(provider, minTime, minDistance, listener);
        };

        LocationManager.getLastKnownLocation.implementation = function(provider) {
            var location = this.getLastKnownLocation(provider);
            var locString = "null";
            if (location) {
                locString = "lat:" + location.getLatitude() + ",lng:" + location.getLongitude();
            }
            logEvent("api_call", "LocationManager.getLastKnownLocation", [provider], locString);
            return location;
        };
    } catch(e) {
        console.log("[-] Error hooking LocationManager: " + e);
    }

    // ======= Camera Operations =======
    try {
        var Camera = Java.use('android.hardware.Camera');
        Camera.open.overload('int').implementation = function(cameraId) {
            var result = this.open(cameraId);
            logEvent("api_call", "Camera.open", [cameraId], null);
            return result;
        };

        Camera.takePicture.overload(
          'android.hardware.Camera$ShutterCallback',
          'android.hardware.Camera$PictureCallback',
          'android.hardware.Camera$PictureCallback',
          'android.hardware.Camera$PictureCallback'
        ).implementation = function(shutter, raw, jpeg, postview) {
          logEvent("api_call", "Camera.takePicture", [], null);
          return this.takePicture(shutter, raw, jpeg, postview);
        };
    } catch(e) {
        console.log("[-] Error hooking Camera: " + e);
    }

    // ======= Runtime Exec (shell commands) =======
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
            logEvent("api_call", "Runtime.exec", [cmd], null);
            return this.exec(cmd);
        };

        Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmds) {
            logEvent("api_call", "Runtime.exec", [cmds.join(" ")], null);
            return this.exec(cmds);
        };
    } catch(e) {
        console.log("[-] Error hooking Runtime: " + e);
    }

    // ======= Package Manager (app enumeration) =======
    try {
        var PackageManager = Java.use('android.content.pm.PackageManager');
        PackageManager.getInstalledPackages.implementation = function(flags) {
            var result = this.getInstalledPackages(flags);
            logEvent("api_call", "PackageManager.getInstalledPackages", [flags], null);
            return result;
        };

        PackageManager.getInstalledApplications.implementation = function(flags) {
            var result = this.getInstalledApplications(flags);
            logEvent("api_call", "PackageManager.getInstalledApplications", [flags], null);
            return result;
        };
    } catch(e) {
        console.log("[-] Error hooking PackageManager: " + e);
    }

    // ======= WebView (JavaScript) =======
    try {
        var WebView = Java.use('android.webkit.WebView');
        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            logEvent("api_call", "WebView.loadUrl", [url], null);
            return this.loadUrl(url);
        };

        WebView.addJavascriptInterface.implementation = function(obj, name) {
            logEvent("api_call", "WebView.addJavascriptInterface", [obj.getClass().getName(), name], null);
            return this.addJavascriptInterface(obj, name);
        };

        WebView.evaluateJavascript.implementation = function(script, resultCallback) {
            logEvent("api_call", "WebView.evaluateJavascript", [script], null);
            return this.evaluateJavascript(script, resultCallback);
        };
    } catch(e) {
        console.log("[-] Error hooking WebView: " + e);
    }

    console.log("[+] All Android API hooks installed successfully");
});