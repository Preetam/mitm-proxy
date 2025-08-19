# mitm-proxy

A lightweight, file-based HTTP/HTTPS man-in-the-middle proxy and logger written in Go.

It generates TLS certificates on the fly to intercept encrypted traffic and logs all requests and responses to a local SQLite database for inspection.

---

## Features

- **HTTP & HTTPS Interception**: Captures and logs both plain-text and encrypted web traffic.
- **On-the-Fly Certificate Generation**: Creates server certificates signed by your own local root CA.
- **SQLite Logging**: Stores all traffic details (headers, bodies, etc.) in a `proxy.db` file for easy querying.
- **Simple & Portable**: Single Go binary with minimal dependencies.

---

## Setup & Usage

Follow these steps to generate a local Certificate Authority (CA), run the proxy, and configure your device to trust it.

### **Step 1: Generate the Certificate Authority (CA)**

You need to create your own root certificate and private key. This CA will be used to sign the certificates the proxy generates.

```bash
# Generate a 4096-bit RSA private key
openssl genrsa -out ca.key 4096

# Create a self-signed root CA certificate valid for 5 years
# You can leave the informational fields blank.
openssl req -x509 -new -nodes -key ca.key -sha256 -days 1825 -out ca.crt
```

You will now have two files: `ca.key` (your private key, keep it safe) and `ca.crt` (your public certificate, which you will install on your devices).

### **Step 2: Trust the CA Certificate**

You must install and trust the `ca.crt` file on any device you want to monitor.

#### **iOS**

1.  Get the `ca.crt` file onto your device (e.g. via AirDrop).
2.  Open the file. You will be prompted to review and install the profile in **Settings**.
3.  After installing, go to **Settings \> General \> About \> Certificate Trust Settings**.
4.  Find your CA certificate and **toggle the switch ON** to enable full trust. This step is crucial.

### **Step 3: Run the Proxy**

Build and run the application from your terminal.

```bash
# Build the binary
go build .

# Run the proxy, pointing to your CA files
./mitm-proxy -cert ca.crt -key ca.key
```

By default, the proxy runs on port `:5559` and creates a `proxy.db` file. You can see other options with `./mitm-proxy -h`.

### **Step 4: Configure Your Device's Proxy**

1.  Find the **local IP address** of the computer running the proxy (e.g., `192.168.1.123`).
2.  On your mobile device, go to your current **Wi-Fi settings** and configure a manual HTTP proxy.
    - **Server:** Your computer's local IP address.
    - **Port:** `5559`
3.  Start browsing! All HTTP and HTTPS traffic from your device will now be logged.

---

## Database Example

You can inspect the captured traffic by querying the `proxy.db` file.

```shell
$ sqlite3 proxy.db
```

```
sqlite> select id, timestamp, protocol, method, host, path, request_headers, request_body, response_status, response_headers, substr(response_body, 0, 10) from traffic where path like '%favicon.ico%' limit 1;
                          id = 22
                   timestamp = 2025-08-18 22:25:28.507759-07:00
                    protocol = HTTPS
                      method = GET
                        host = preet.am
                        path = /favicon.ico
             request_headers = {"Accept":["*/*"],"Accept-Encoding":["gzip, deflate, br"],"Accept-Language":["en-US,en;q=0.9"],"Connection":["keep-alive"],"Priority":["u=3, i"],"Referer":["https://preet.am/"],"Sec-Fetch-Dest":["image"],"Sec-Fetch-Mode":["no-cors"],"Sec-Fetch-Site":["same-origin"],"User-Agent":["Mozilla/5.0 (iPhone; CPU iPhone OS 18_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1"]}
                request_body =
             response_status = 404
            response_headers = {"Connection":["keep-alive"],"Content-Encoding":["br"],"Content-Type":["text/html; charset=utf-8"],"Date":["Tue, 19 Aug 2025 05:25:28 GMT"],"Server":["nginx"],"X-Backend":["phl-web-03"],"X-Backend-Ip":["10.202.2.213"],"X-Frontend":["phl-frontend-01"],"X-Trace-Id":["ti_7eecc83e8cc96a5df2bf017aa3271d45"]}
substr(response_body, 0, 10) = <!DOCTYPE
```

---

## License

MIT
