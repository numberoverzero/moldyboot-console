"use strict";
(function(){
var crypto = (window.crypto || window.msCrypto).subtle;

Object.filter = function(src, predicate) {
    var dst = {}, key;
    for (key in src) {
        if (src.hasOwnProperty(key) && predicate(key)) {
            dst[key] = src[key];
        }
    }
    return dst;
};


Object.merge = function (dst, src) {
    for (var key in src) {
        if (src.hasOwnProperty(key)) {
            dst[key] = src[key];
        }
    }
    return dst;
};


// https://gist.github.com/joni/3760795
function toUTF8Array(str) {
    var utf8 = [];
    for (var i=0; i < str.length; i++) {
        var charcode = str.charCodeAt(i);
        if (charcode < 0x80) utf8.push(charcode);
        else if (charcode < 0x800) {
            utf8.push(0xc0 | (charcode >> 6),
                      0x80 | (charcode & 0x3f));
        }
        else if (charcode < 0xd800 || charcode >= 0xe000) {
            utf8.push(0xe0 | (charcode >> 12),
                      0x80 | ((charcode>>6) & 0x3f),
                      0x80 | (charcode & 0x3f));
        }
        // surrogate pair
        else {
            i++;
            // UTF-16 encodes 0x10000-0x10FFFF by
            // subtracting 0x10000 and splitting the
            // 20 bits of 0x0-0xFFFFF into two halves
            charcode = 0x10000 + (((charcode & 0x3ff)<<10)
                      | (str.charCodeAt(i) & 0x3ff))
            utf8.push(0xf0 | (charcode >>18),
                      0x80 | ((charcode>>12) & 0x3f),
                      0x80 | ((charcode>>6) & 0x3f),
                      0x80 | (charcode & 0x3f));
        }
    }
    return new Uint8Array(utf8);
}


// http://stackoverflow.com/a/12713326
function Uint8ToString(u8a){
    var CHUNK_SZ = 0x8000;
    var c = [];
    for (var i=0; i < u8a.length; i+=CHUNK_SZ) {
        c.push(String.fromCharCode.apply(null, u8a.subarray(i, i+CHUNK_SZ)));
    }
    return c.join("");
}


function sha256(str) {
    return new Promise(function(resolve, reject) {
        var strArray = toUTF8Array(str);
        crypto.digest("SHA-256", strArray)
        .then(hash=>btoa(Uint8ToString(new Uint8Array(hash))))
        .then(resolve)
        .catch(reject);
    });
}


window.errors = (function() {
    var self = {};
    var _cache = {};
    Object.defineProperty(self, "cached", {get: ()=>Object.keys(_cache)});

    self.newCls = function(name) {
        if (name in _cache) {return _cache[name];}
        var ErrorClass = _cache[name] = function() {
            var tmp = Error.apply(this, arguments);
            tmp.name = this.name = name;
            this.message = tmp.message;
            Object.defineProperty(this, "stack", {get: ()=>tmp.stack});
            return this;
        };
        var Intermediate = function () {};
        Intermediate.prototype = Error.prototype;
        ErrorClass.prototype = new Intermediate();
        return ErrorClass;
    };
    self.t = function(name, message) {return new (self.newCls(name))(message);};
    self.is = function(err, name) {return err instanceof self.newCls(name);};
    return self;
}());


window.keys = (function() {
    var keysSelf = {};
    var database = null;

    function calculateMaxSaltLength (keyLen, hash) {
        var digestLen;
        if (hash === "SHA-256") digestLen = 32;
        else throw errors.t("InvalidHash", "Unknown hash function '" + hash + "'");
        // RFC 3447
        var emLen = Math.ceil((keyLen-1) / 8);
        return emLen - digestLen - 2;
    }

    keysSelf.generate = function (keyLen, hash) {
        var keyLen = (typeof keyLen === 'undefined') ? 2048 : keyLen;
        var hash = (typeof hash === 'undefined') ? "SHA-256" : hash;
        return new Promise(function (resolve, reject) {
            crypto.generateKey(
                {
                    name: "RSA-PSS",
                    modulusLength: keyLen,
                    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                    hash: {name: hash}
                },
                true,  // exportable
                ["sign"]  // only used to sign outgoing
            )
            .then(keyBlob=>{
                keyBlob.saltLen = calculateMaxSaltLength(keyLen, hash);
                resolve(keyBlob);
            })
            .catch(reject)
        });
    };

    keysSelf.sign = function(keyBlob, message) {
        return new Promise(function (resolve, reject) {
            crypto.sign(
                {name: "RSA-PSS", saltLength: keyBlob.saltLen},
                keyBlob.privateKey,
                toUTF8Array(message)
            )
            .then(signature=>{
                // ArrayBuffer -> Uint8Array -> String -> B64Encode
                var b64Str = btoa(Uint8ToString(
                    new Uint8Array(signature)));
                resolve(b64Str);
            })
            .catch(reject);
        });
    };

    keysSelf.export = function(keyBlob) {
        return new Promise(function (resolve, reject) {
            Promise.all([
                crypto.exportKey("jwk", keyBlob.publicKey),
                crypto.exportKey("jwk", keyBlob.privateKey)
            ])
            .then(jwks=>resolve({publicKey: jwks[0], privateKey: jwks[1]}))
            .catch(reject);
        });
    };

    keysSelf.storage = (function() {
        var storageSelf = {};

        storageSelf.open = function() {
            return new Promise(function (resolve, reject) {
                if (database) {
                    resolve(storageSelf);
                    return;
                }
                var openPromise = indexedDB.open("{{webcrypto.databaseName}}", "{{webcrypto.databaseVersion}}");
                openPromise.onsuccess = event=>{
                    database = event.target.result;
                    resolve(storageSelf);
                };
                openPromise.onupgradeneeded = event=>{
                    database = event.target.result;
                    var createKeyStore = new Promise(function(resolveKeyStore, rejectKeyStore) {
                        if (database.objectStoreNames.contains("{{webcrypto.keyStoreName}}")) {
                            resolveKeyStore();
                            return;
                        }
                        var keyTransaction = database.createObjectStore(
                            "{{webcrypto.keyStoreName}}",
                            {autoIncrement: false}
                        ).transaction;
                        keyTransaction.oncomplete = resolveKeyStore;
                        keyTransaction.onerror = keyTransaction.onabort = rejectKeyStore;
                    });
                    var createMetaStore = new Promise(function(resolveMetaStore, rejectMetaStore) {
                        if (database.objectStoreNames.contains("{{webcrypto.metaStoreName}}")) {
                            resolveMetaStore();
                            return;
                        }
                        var metaTransaction = database.createObjectStore(
                            "{{webcrypto.metaStoreName}}",
                            {autoIncrement: false}
                        ).transaction;
                        metaTransaction.oncomplete = resolveMetaStore;
                        metaTransaction.onerror = metaTransaction.onabort = rejectMetaStore;
                    });
                    Promise.all([createKeyStore, createMetaStore])
                    .then(()=>resolve(storageSelf))
                    .catch(reject);
                };
                openPromise.onerror = event=>reject(event.error);
                openPromise.onblocked = ()=>reject(errors.t("DatabaseOpen", "{{webcrypto.databaseName}} is already open."));
            });
        };

        storageSelf.close = function() {
            return new Promise(function (resolve, reject) {
                if (!database) {
                    resolve(storageSelf);
                } else {
                    database.close();
                    database = null;
                    resolve(storageSelf);
                }
            });
        };

        storageSelf.loadKey = function (username, regenerate, keyLen, hash) {
            var regenerate = (typeof regenerate === 'undefined') ? false : regenerate;
            return new Promise(function (resolve, reject) {
                storageSelf.open()
                .then(()=>{
                    var mode = regenerate ? "readwrite" : "readonly",
                        transaction = database.transaction(["{{webcrypto.keyStoreName}}"], mode),
                        request = transaction.objectStore("{{webcrypto.keyStoreName}}").get(username);
                    request.onsuccess = event=>{
                        var keyBlob = event.target.result;
                        if (keyBlob) {
                            resolve(keyBlob);
                        } else if (regenerate) {
                            window.keys.generate(keyLen, hash)
                            .then(keys=>{
                                var keyBlob = {
                                    privateKey: keys.privateKey,
                                    publicKey: keys.publicKey,
                                    saltLen: keys.saltLen
                                };
                                storageSelf.saveKey(keyBlob, username)
                                .then(()=>resolve(keyBlob))
                                .catch(reject);
                            })
                            .catch(reject);
                        } else {
                            reject(errors.t("NoKey", "No key found for user " + username));
                        }
                    };
                    request.onerror = reject;
                })
                .catch(reject);
            });
        };

        storageSelf.saveKey = function (keyBlob, username) {
            return new Promise(function (resolve, reject) {
                storageSelf.open()
                .then(()=>{
                    var transaction = database.transaction(["{{webcrypto.keyStoreName}}"], "readwrite");
                    transaction.oncomplete = ()=>resolve(keyBlob);
                    transaction.onerror = transaction.onabort = event=>reject(event.error);
                    transaction.objectStore("{{webcrypto.keyStoreName}}").put(keyBlob, username);
                })
                .catch(reject);
            });
        };

        storageSelf.deleteKey = function (username) {
            return new Promise(function (resolve, reject) {
                storageSelf.open()
                .then(()=>{
                    var transaction = database.transaction(["{{webcrypto.keyStoreName}}"], "readwrite");
                    transaction.oncomplete = resolve;
                    transaction.onerror = transaction.onabort = event=>reject(event.error);
                    transaction.objectStore("{{webcrypto.keyStoreName}}").delete(username);
                })
                .catch(reject);
            });
        };
        return storageSelf;
    }());

    keysSelf.getActiveUser = function() {
        return new Promise(function (resolve, reject) {
            keysSelf.storage.open()
            .then(()=>{
                var transaction = database.transaction(["{{webcrypto.metaStoreName}}"], "readonly"),
                    request = transaction.objectStore("{{webcrypto.metaStoreName}}").get("activeUser");
                request.onsuccess = event=>{
                    var userBlob = event.target.result;
                    if (userBlob) {
                        resolve(userBlob.username);
                    } else {
                        reject(errors.t("NoActiveUser", "There is no active user."));
                    }
                };
                request.onerror = reject;
            })
            .catch(reject);
        });
    };

    keysSelf.setActiveUser = function(username) {
        return new Promise(function (resolve, reject) {
            keysSelf.storage.open()
            .then(()=>{
                var transaction = database.transaction(["{{webcrypto.metaStoreName}}"], "readwrite");
                transaction.oncomplete = ()=>resolve(username);
                transaction.onerror = transaction.onabort = event=>reject(event.error);
                transaction.objectStore("{{webcrypto.metaStoreName}}").put({username: username}, "activeUser");
            })
            .catch(reject);
        });
    };

    return keysSelf;
}());


window.request = (function() {
    var self = {};
    self.endpoint = "{{endpoints.api}}";

    self.sign = function(keyBlob, method, path, headers, body) {
        return sha256(body)
        .then(xContentSha256=>{
            var headers = Object.merge({
                    "x-date": new Date().toISOString(),
                    "content-type": "application/json",
                    "content-length": "" + body.length,
                    // fixed sha256 of the empty string
                    "x-content-sha256": xContentSha256,
                    "(request-target)": method + " " + path}, (headers || {})),
                signed_headers = Object.keys(headers),
                string_to_sign = signed_headers.map(name=>name.toLowerCase() + ": " + headers[name]).join("\n");

            return window.keys.sign(keyBlob, string_to_sign)
            .then(signature=>{
                var authorization = [
                   'Signature',
                   'headers="' + signed_headers.join(" ") + '"',
                   'id="' + keyBlob.id + '"',
                   'signature="' + signature + '"'
                ].join(" ");
                headers = Object.merge(headers, {"authorization": authorization});
                headers = Object.filter(headers, h=>h !== "(request-target)");
                return headers;
            });
        });
    };

    self.get = function(keyBlob, path, headers, sign) {
        var sign = (typeof sign === "undefined") ? true : sign;
        return new Promise(function (resolve, reject) {
            var preRequest = sign ?
                self.sign(keyBlob, "get", path, headers, "") :
                Promise.resolve(headers);
            preRequest
            .then(headers=>{
                var url = self.endpoint + path,
                    opts = {h: headers, r: "json"};
                return rq(url, opts);
            })
            .then(resolve)
            .catch(reject);
        });
    };

    self.post = function(keyBlob, path, headers, body, sign) {
        var strBody = body;
        if (typeof strBody === "undefined") {
            strBody = "";
        } else if (typeof body !== "string") {
            strBody = JSON.stringify(body);
        } // else already a string
        var sign = (typeof sign === "undefined") ? true : sign;

        return new Promise(function (resolve, reject) {
            var preRequest = sign ?
                self.sign(keyBlob, "post", path, (headers || {}), strBody) :
                Promise.resolve(headers);
            preRequest
            .then(headers=>{
                var url = self.endpoint + path,
                    opts = {m:"POST", h: headers, b:strBody, r: "json"};
                return rq(url, opts);
            })
            .then(resolve)
            .catch(reject);
        });
    };
    return self;
}());


window.Client = function(username) {
    var self = this;
    self.username = username;

    // Promise to hang execution off of.
    self.withKey = () => window.keys.storage.loadKey(self.username, false);

    self.login = function(password) {
        return new Promise(function (resolve, reject) {
            self.withKey()
            .then(keyBlob=>window.keys.export(keyBlob)
                .then(jwk=>{
                    var credentials = {
                        username: username,
                        password: password,
                        public_key: {
                            e: jwk.publicKey.e,
                            n: jwk.publicKey.n
                        }
                    };
                    return request.post(keyBlob, "/keys", {}, credentials, false);
                })
                .then(xhr=>{
                    keyBlob.until = xhr.response.until;
                    keyBlob.id = xhr.response.key_id;

                    window.keys.storage.saveKey(keyBlob, username)
                        .then(()=>window.keys.setActiveUser(username))
                        .then(()=>resolve(xhr))
                        .catch(reject);
                })
                .catch(reject))
            .catch(reject);
        });
    };

    self.getKey = function() {
        return new Promise(function(resolve, reject) {
            self.withKey()
            .then(keyBlob=>request.get(keyBlob, "/keys"))
            .then(resolve)
            .catch(reject);
        });
    };
};
window.Client.forActiveUser = function() {
    return new Promise(function (resolve, reject) {
        window.keys.getActiveUser()
        .then(username=>new Client(username))
        .then(resolve)
        .catch(reject);
    });
};
}());
