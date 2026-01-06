#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <ESP32WebServerSecure.h>
#include <Ascon128.h>

const char* ssid = "Prof";
const char* wifiPassword = "12345678";

const int ledPin = 26;

Ascon128 ascon;

static const uint8_t KEY[16] = {
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
  0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
};

static const uint8_t NONCE[16] = {
  0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
  0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
};

const char* PASSWORD_CLEAR = "admin123";
String PASSWORD_ENCRYPTED;

bool authenticated = false;
unsigned long lastAuthTime = 0;
const unsigned long SESSION_TIMEOUT = 5 * 60 * 1000;

int failedAttempts = 0;
const int MAX_ATTEMPTS = 5;



static const uint8_t serverCert[] PROGMEM = {
  -----BEGIN CERTIFICATE-----
MIID0TCCArmgAwIBAgIUPhHSlv2K+rNBGmEfIkqymXwF/rAwDQYJKoZIhvcNAQEL
BQAweDELMAkGA1UEBhMCVE4xEDAOBgNVBAgMB1RVTklTSUExDjAMBgNVBAcMBVRV
TklTMQ0wCwYDVQQKDARFTlNJMQ0wCwYDVQQLDARFTlNJMQ0wCwYDVQQDDARMQVRZ
MRowGAYJKoZIhvcNAQkBFgtsQGdtYWlsLmNvbTAeFw0yNjAxMDYyMTA0MjFaFw0y
NzAxMDYyMTA0MjFaMHgxCzAJBgNVBAYTAlROMRAwDgYDVQQIDAdUVU5JU0lBMQ4w
DAYDVQQHDAVUVU5JUzENMAsGA1UECgwERU5TSTENMAsGA1UECwwERU5TSTENMAsG
A1UEAwwETEFUWTEaMBgGCSqGSIb3DQEJARYLbEBnbWFpbC5jb20wggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCssnTtwiSlo0G2T56X92IhEeUBStVAHYPY
U35uto1Km6Bsrzc8kByNoZOEq+vBjO6SnPKDHhrUrSEI0KTML/nr1M0Dt9TxklUF
surQGPnZkIPphRdyOBc+39mnJRvpYLqoH3S6P92KNCfHtFY3SIg22O1Kne7Hfhmp
HWM+IwN0sx035iXr6bTCoTVnnXESuAsGk24W5C336N7ETNJWflwY8NmcQZ6BMcN2
Rcyra36Yy0LGRlFAUla/52wYqBn6B0AZVZh5VaGdBRSutBpRXjFEkqePsj1c4tMk
QdHx9QE9M7nIGUGFZIweY2fiQF4bwPp8hzwZUkun6YIac8RSV1AXAgMBAAGjUzBR
MB0GA1UdDgQWBBQ7xFa5gVP5Ew66OXL0Y9U31JJfmDAfBgNVHSMEGDAWgBQ7xFa5
gVP5Ew66OXL0Y9U31JJfmDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4IBAQBH8EabqOMs0NZdq7GDwM5v8WW4zovCWEsQUootimztKcr295+o5CRowGus
sXTU+gZ0bNVutuWigiVT2GrOj1n72zOlWxVIqq1OE0GJVfdCtNIsLw51eHoQdxEL
8B9ZRXY5chQdAHZVN4ILT8uV8N6mYb/6IY697Ezc4Oe9Bn7gK5ImxnGBmKJWTMTB
tx9dasQ5bMXvKzJrMPMVUEQrhvJPIYfnr03H967oKauEvBm6e2dGW/zfqfFYwMlf
YW81DyKVFLARKFbO4MUnwE1reftDYD0OAsg+L3smwqF/qMRIiDnMEyYHItsuqrpq
KdLQFHjgr7AllEUIg6AncNNKMuRj
-----END CERTIFICATE-----

};

static const uint8_t serverKey[] PROGMEM = {
  -----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCssnTtwiSlo0G2
T56X92IhEeUBStVAHYPYU35uto1Km6Bsrzc8kByNoZOEq+vBjO6SnPKDHhrUrSEI
0KTML/nr1M0Dt9TxklUFsurQGPnZkIPphRdyOBc+39mnJRvpYLqoH3S6P92KNCfH
tFY3SIg22O1Kne7HfhmpHWM+IwN0sx035iXr6bTCoTVnnXESuAsGk24W5C336N7E
TNJWflwY8NmcQZ6BMcN2Rcyra36Yy0LGRlFAUla/52wYqBn6B0AZVZh5VaGdBRSu
tBpRXjFEkqePsj1c4tMkQdHx9QE9M7nIGUGFZIweY2fiQF4bwPp8hzwZUkun6YIa
c8RSV1AXAgMBAAECggEAN1hdxtCgRAElDxNHJTaf2S9N7/MWkpyi41Imw753W4Cy
kgI5NoyMygsNJsieHoJW9t+bjM+6E4yEeLm9Br8dXintphJlCSI3Y0Mqo5RNhh8d
V1pS4ET/liPRMhLfdhSM3VJvaz0Kd78tPIAb3U2+ca1lprMkkgRknuEPLBu2gNBb
bHVbD59QCg1fc0nTzy+IcTgK+ZjJW0AXYaTa6D9+eZrF1i4ROEJNFgUSlPp1qWdv
xeSe7kLKqOqRBD1E/yAavOLFGG4p1R4hSwvdjsTGMX4IaMgTGNVLNQS8dRgi6OCv
CGv4QLchZBqt/F2ihLF67KMPDGaSsvBYT0Jrrc6vMQKBgQDX7DZrQACxyJDG5hum
S3Poj39PaLv9Uw3hr83G4n6FDRjEx+pBF1tNv0hcAzGO3PWGNB9OpYGjUyudlyNX
J7Q+DURIPrzleooHGXSL9l++r7Th78gqlvX0zKBirHBZPnI5r9A4mJB3Nea//D7S
Rx5sfdAnWZcKC+9NMpD/RCPP+QKBgQDMwFXX1uUzX7N2SVNjbhCXzyLj5f8aNDz9
kiKGiKFIf3Bi7FqwAzPFx1ho0bQ+G+SkKkA02SCflcU0erB9x58OIFTQmSQ4NmwB
1LaMHf9ZmoHFyQ7ALvNp043drd7zSOem9qT0PqJyphsxkdXTnkXzBqZ1npIOoTfO
NVYZrdhEjwKBgQCS3B+7XMHcKf2GuvXtan6AnDFMMoFCcN4NNcTxVBYXquvA0/SZ
pyg7vjGaG7X2ZIU+bW8pz9pX2vbcbfLkkaW/WsiplrpmHq2I3KBvnfhLOzj9P1jW
1uydPxyLYJvdp2KLp/AovmPsISY8SHX2Edc4lW4hhYb8l1eBGzaR2Ke/CQKBgQCq
nb8qq5y0cZPnBnUhTq8vAWEujRJFcLA+EI8KkkHrWp55IED1mMWEkneeaNiMRMwC
7F4ya5gewzvgXjhBp51ntRNX+7TNzrOz1uAC5GBK91AaU08iYD1fuvTle6RkECVQ
4QhVqvfNF5NjfAW1YJcjSzBcpLVK0ZbiE1na7h1gCwKBgQCNRB6ncgm3tI6DRHV9
985/bx370iawd3EBJs7iCT7w2M580Vz7V1IXlqBsNkj9r3GRyIS2fwldd73Hvit9
HYffPFF2LMZRaycz7P9vfJNmWXK8y+v7nSvIImUmXk4iL9Kp2WId4yxngMYsW6TH
j0YFfhdOI9hvNO6ecCVu0DYkVQ==
-----END PRIVATE KEY-----

};

BearSSL::ESP32WebServerSecure server(443);

String asconEncryptFixedNonce(String plain) {
  uint8_t input[plain.length()];
  uint8_t output[plain.length()];

  plain.getBytes(input, plain.length() + 1);

  ascon.clear();
  ascon.setKey(KEY, 16);
  ascon.setIV(NONCE, 16);
  ascon.encrypt(output, input, plain.length());

  String res = "";
  for (int i = 0; i < plain.length(); i++) {
    res += (char)output[i];
  }
  return res;
}

String loginPage = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Connexion ESP32</title>
<style>
body{font-family:Arial;background:linear-gradient(135deg,#6C63FF,#FF6584);
height:100vh;display:flex;justify-content:center;align-items:center;}
.box{background:white;padding:35px;border-radius:15px;width:320px;
box-shadow:0 10px 25px rgba(0,0,0,.2);}
input{width:100%;padding:12px;border-radius:8px;border:1px solid #ccc;}
button{width:100%;margin-top:20px;padding:12px;border:none;background:#6C63FF;
color:white;font-size:16px;border-radius:8px;}
#msg{color:red;text-align:center;margin-top:10px;}
</style>
</head>
<body>
<div class="box">
<h2>Connexion ESP32</h2>
<input id="pwd" type="password" placeholder="Mot de passe">
<button onclick="login()">Connexion</button>
<p id="msg"></p>
</div>
<script>
function login(){
fetch("/login",{method:"POST",
body:new URLSearchParams({password:pwd.value})})
.then(r=>r.text()).then(t=>{
if(t==="OK")location.href="/";
else msg.innerText="Accès refusé";
});
}
</script>
</body>
</html>
)rawliteral";

String homepage = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>ESP32 Control</title>
<style>
body{font-family:Arial;background:linear-gradient(135deg,#6C63FF,#FF6584);
height:100vh;display:flex;justify-content:center;align-items:center;}
.container{background:white;padding:35px;border-radius:15px;width:350px;
box-shadow:0 10px 25px rgba(0,0,0,.2);text-align:center;}
button{padding:15px 30px;margin:10px;font-size:18px;border-radius:8px;border:none;}
.on{background:green;color:white;}
.off{background:red;color:white;}
.logout{background:gray;color:white;}
</style>
</head>
<body>
<div class="container">
<h1>ESP32 Control</h1>
<p id="value">---</p>
<button class="on" onclick="fetch('/on')">ON</button>
<button class="off" onclick="fetch('/off')">OFF</button>
<br><br>
<button class="logout" onclick="location.href='/logout'">Déconnexion</button>
</div>
<script>
setInterval(()=>{fetch('/value').then(r=>r.text()).then(v=>value.innerHTML=v)},2000);
</script>
</body>
</html>
)rawliteral";

/*  ROUTES */
void handleRoot() {
  if (authenticated && millis() - lastAuthTime < SESSION_TIMEOUT) {
    server.send(200, "text/html", homepage);
  } else {
    authenticated = false;
    server.send(200, "text/html", loginPage);
  }
}

void handleLogin() {
  if (failedAttempts >= MAX_ATTEMPTS) {
    server.send(403, "text/plain", "BLOCKED");
    return;
  }

  if (asconEncryptFixedNonce(server.arg("password")) == PASSWORD_ENCRYPTED) {
    authenticated = true;
    lastAuthTime = millis();
    failedAttempts = 0;
    server.send(200, "text/plain", "OK");
  } else {
    failedAttempts++;
    server.send(401, "text/plain", "FAIL");
  }
}

void handleLogout() {
  authenticated = false;
  server.send(200, "text/html", loginPage);
}

void handleOn() {
  if (!authenticated) return;
  digitalWrite(ledPin, HIGH);
  server.send(200, "text/plain", "ON");
}

void handleOff() {
  if (!authenticated) return;
  digitalWrite(ledPin, LOW);
  server.send(200, "text/plain", "OFF");
}

void handleValue() {
  if (!authenticated) return;
  server.send(200, "text/plain", String(random(20, 30)));
}

void setup() {
  Serial.begin(115200);
  pinMode(ledPin, OUTPUT);

  PASSWORD_ENCRYPTED = asconEncryptFixedNonce(PASSWORD_CLEAR);

  WiFi.begin(ssid, wifiPassword);
  while (WiFi.status() != WL_CONNECTED) delay(500);

  Serial.print("HTTPS IP: ");
  Serial.println(WiFi.localIP());

  server.getServer().setRSACert(
    new BearSSL::X509List(serverCert),
    new BearSSL::PrivateKey(serverKey)
  );

  server.on("/", handleRoot);
  server.on("/login", HTTP_POST, handleLogin);
  server.on("/logout", handleLogout);
  server.on("/on", handleOn);
  server.on("/off", handleOff);
  server.on("/value", handleValue);

  server.begin();
}

void loop() {
  server.handleClient();
}
