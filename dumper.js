function traceMethod(targetClassMethod, onPerformingHook) {
    var delim = targetClassMethod.lastIndexOf(".");
    if (delim === -1) return;

    var targetClass = targetClassMethod.slice(0, delim);
    var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length);

    var hook;
    try {
        hook = Java.use(targetClass);
    } catch (err) {
        return;
    }

    if (typeof hook[targetMethod] == 'undefined') {
        return;
    }

    var overloadCount = hook[targetMethod].overloads.length;

    console.log("[*] Tracing java method " + targetClassMethod + " [" + overloadCount + " overload(s)]");

    for (var i = 0; i < overloadCount; i++) {
        hook[targetMethod].overloads[i].implementation = function() {
            var retval = this[targetMethod].apply(this, arguments);

            var args = arguments;
            Java.perform(function() {
                onPerformingHook(targetClassMethod, args);
            });
            return retval;
        }
    }
}

function traceClassCtor(className, configs) {
    var hook = Java.use(className);
    var overloadCount = hook["$init"].overloads.length;

    console.log("[*] Tracing java CTor " + className + " [" + overloadCount + " overload(s)]");

    for (var i = 0; i < overloadCount; i++) {
        hook["$init"].overloads[i].implementation = function() {
            var retval = this["$init"].apply(this, arguments);

            var args = arguments;
            Java.perform(function() {
                var hookMsg = {
                    "function": className,
                    "struct": {}
                };

                hookMsg["struct"]["args"] = [];
                for (var j = 0; j < args.length; j++) {
                    if (configs["stringsOnly"] && typeof args[j] == 'string' || args[j] instanceof String)
                        hookMsg["struct"]["args"].push(args[j]);
                    else if (configs["stringsOnly"])
                        hookMsg["struct"]["args"].push(args[j]);
                }

                if (configs["backtrace"]) {
                    hookMsg["struct"]["backtrace"] = Java.use("android.util.Log")
                        .getStackTraceString(Java.use("java.lang.Exception").$new());
                }
                send(hookMsg);
            });

            return retval;
        }
    }
}

function traceModule(impl, name) {
    console.log("Tracing " + name);

    Interceptor.attach(impl, {
        onEnter: function(args) {
            // debug only the intended calls
            this.flag = true;

            if (this.flag) {
                console.warn("\n*** entered " + name);
                // print backtrace
                console.log("\nBacktrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join("\n"));
            }
        },

        onLeave: function(retval) {
            if (this.flag) {
                // print retval
                console.log("\nretval: " + retval);
                console.warn("\n*** exiting " + name);
            }
        }
    });
}


function traceNativeFunct(exp, funct, onEnterCb, onLeaveCb) {
    console.log("[*] Tracing native funct " + funct + " in " + exp);

    Interceptor.attach(Module.findExportByName(exp, funct), {
        onEnter: function (args) {
            onEnterCb(args);
        },
        onLeave: function (retval) {
            onLeaveCb(retval);
        }
    });
}

function uniqBy(array, key) {
    var seen = {};
    return array.filter(function(item) {
        var k = key(item);
        return seen.hasOwnProperty(k) ? false : (seen[k] = true);
    });
}

function ba2hex(bufArray) {
    var uint8arr = new Uint8Array(bufArray);
    if (!uint8arr) {
        return '';
    }

    var hexStr = '';
    for (var i = 0; i < uint8arr.length; i++) {
        var hex = (uint8arr[i] & 0xff).toString(16);
        hex = (hex.length === 1) ? '0' + hex : hex;
        hexStr += hex;
    }

    return hexStr.toUpperCase();
}

function hex2a(hexx) {
    var hex = hexx.toString();
    var str = '';
    for (var i = 0; i < hex.length; i += 2)
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
}

function getPortsAndAddresses(sockfd, isRead) {
    var message = {};
    var addrlen = Memory.alloc(4);
    var addr = Memory.alloc(16);
    var src_dst = ["src", "dst"];
    for (var i = 0; i < src_dst.length; i++) {
        Memory.writeU32(addrlen, 16);
        if ((src_dst[i] == "src") ^ isRead) {
            getsockname(sockfd, addr, addrlen);
        } else {
            getpeername(sockfd, addr, addrlen);
        }
        message[src_dst[i] + "_port"] = ntohs(Memory.readU16(addr.add(2)));
        message[src_dst[i] + "_addr"] = ntohl(Memory.readU32(addr.add(4)));
    }
    return message;
}

function getSslSessionId(ssl) {
    var session = SSL_get_session(ssl);
    if (session == 0) {
        return 0;
    }
    var len = Memory.alloc(4);
    var p = SSL_SESSION_get_id(session, len);
    len = Memory.readU32(len);
    var session_id = "";
    for (var i = 0; i < len; i++) {
        session_id +=
            ("0" + Memory.readU8(p.add(i)).toString(16).toUpperCase()).substr(-2);
    }
    return session_id;
}

function standardHookMethodPerform(targetClassMethod, args) {
    var hookMsg = {
        "function": targetClassMethod,
        "struct": {}
    };

    hookMsg["struct"]["args"] = [];
    for (var j = 0; j < args.length; j++) {
        try {
            hookMsg["struct"]["args"].push(JSON.parse(args[j]));
        } catch (err) {}
    }

    hookMsg["struct"]["backtrace"] = Java.use("android.util.Log")
        .getStackTraceString(Java.use("java.lang.Exception").$new());
    send(hookMsg);
}

function onDumpIntentHookMethodPerform(targetClassMethod, args) {
    if (typeof args[0] != 'undefined') {
        var hookMsg = {
            "function": targetClassMethod,
            "struct": {}
        };

        hookMsg["struct"]["args"] = [];
        for (var j = 0; j < args.length; j++) {
            try {
                hookMsg["struct"]["args"].push(JSON.parse(args[j]));
            } catch (err) {}
        }

        var intent = Java.use("android.content.Intent");
        var pt = ptr(args[0]["$handle"]);
        var intentCls = Java.cast(pt, intent);

        hookMsg["struct"]["action"] = intentCls.getAction();
        hookMsg["struct"]["target_component"] = intentCls.getComponent().toString();
        hookMsg["struct"]["backtrace"] = Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new());
        send(hookMsg);
    }
}

function onDumpContentResolverHookMethodPerform(targetClassMethod, args) {
    if (typeof args[0] != 'undefined') {
        var hookMsg = {
            "function": targetClassMethod,
            "struct": {}
        };

        hookMsg["struct"]["args"] = [];
        for (var j = 0; j < args.length; j++) {
            try {
                hookMsg["struct"]["args"].push(JSON.parse(args[j]));
            } catch (err) {}
        }

        var uri = Java.use("android.net.Uri");
        var pt = ptr(args[0]["$handle"]);
        var uriCls = Java.cast(pt, uri);

        hookMsg["uri"] = uriCls.toString();

        if (args[1] && typeof args[1] != 'undefined') {
            var arrayUtils = Java.use("java.util.Arrays");
            var strArray = Java.use("[Ljava.lang.String;");
            pt = ptr(args[1]["$handle"]);
            var projections = Java.cast(pt, strArray);
            hookMsg["projection"] = arrayUtils.toString(projections);
        } else {
            hookMsg["projection"] = "None";
        }

        hookMsg["struct"]["backtrace"] = Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new());
        send(hookMsg);
    }
}

function exist(src, val) {
    return src.toLowerCase().indexOf(val) != -1;
}

function initializeGlobals() {
    addresses = {};
    var resolver = new ApiResolver("module");
    var exps = [
        ["*libssl*",
            ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session",
                "SSL_SESSION_get_id"]],
        [Process.platform == "darwin" ? "*libsystem*" : "*libc*",
            ["getpeername", "getsockname", "ntohs", "ntohl"]]
    ];
    for (var i = 0; i < exps.length; i++) {
        var lib = exps[i][0];
        var names = exps[i][1];
        for (var j = 0; j < names.length; j++) {
            var name = names[j];
            var matches = resolver.enumerateMatchesSync("exports:" + lib + "!" +
                name);
            if (matches.length == 0) {
                throw "Could not find " + lib + "!" + name;
            } else if (matches.length != 1) {
                // Sometimes Frida returns duplicates.
                var address = 0;
                var s = "";
                var duplicates_only = true;
                for (var k = 0; k < matches.length; k++) {
                    if (s.length != 0) {
                        s += ", ";
                    }
                    s += matches[k].name + "@" + matches[k].address;
                    if (address == 0) {
                        address = matches[k].address;
                    }
                    else if (!address.equals(matches[k].address)) {
                        duplicates_only = false;
                    }
                }
                if (!duplicates_only) {
                    throw "More than one match found for " + lib + "!" + name + ": " +
                    s;
                }
            }
            addresses[name] = matches[0].address;
        }
    }

    SSL_get_fd = new NativeFunction(addresses["SSL_get_fd"], "int",
        ["pointer"]);
    SSL_get_session = new NativeFunction(addresses["SSL_get_session"],
        "pointer", ["pointer"]);
    SSL_SESSION_get_id = new NativeFunction(addresses["SSL_SESSION_get_id"],
        "pointer", ["pointer", "pointer"]);
    getpeername = new NativeFunction(addresses["getpeername"], "int", ["int",
        "pointer", "pointer"]);
    getsockname = new NativeFunction(addresses["getsockname"], "int", ["int",
        "pointer", "pointer"]);
    ntohs = new NativeFunction(addresses["ntohs"], "uint16", ["uint16"]);
    ntohl = new NativeFunction(addresses["ntohl"], "uint32", ["uint32"]);
}

function inject() {
    Java.perform(function () {
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
    });
}

setTimeout(function () {
    initializeGlobals();
    inject();
}, 0);
