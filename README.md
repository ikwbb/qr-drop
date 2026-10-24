# QR Drop

Send a file straight from one device to another. A QR code carries the key, the file goes over WebRTC, and nothing in between ever holds a readable copy.

It's a single static page (HTML, CSS and plain JavaScript, no build step), hosted on GitHub Pages.

## How it works

1. **Sender** picks a file. The page creates a random AES-256 key and a WebRTC offer, and shows them as a QR code: `https://…/#o=<offer>&k=<key>`. Everything after `#` stays in the browser and is never sent to GitHub or anyone else.
2. **Receiver** scans it. Their page applies the offer, creates a WebRTC answer and shows it as a reply QR code (or as text to paste).
3. **Sender** scans the reply. The two browsers connect directly over a WebRTC data channel.
4. The file is split into 64 KB chunks. Each chunk is encrypted with AES-256-GCM using the key from step 1, and its IV is its sequence number, so chunks can't be read, changed, reordered or dropped in transit. The receiver checks the chunk count and size, then offers the file to save.

There is no signaling server: the QR codes are the signaling. The only third party contacted is a public STUN server (`stun.l.google.com`), which tells each browser its public IP address and never sees the file.

## Why the extra encryption

WebRTC data channels are already encrypted with DTLS. The AES-GCM layer on top means the file stays unreadable even if:

- the reply text is pasted through a chat app and someone swaps it for their own (they'd connect, but couldn't decrypt or forge a single chunk without the key from the first QR code);
- a TURN relay is added later to get through strict networks.

The page's Content-Security-Policy sets `connect-src 'none'`, so it can't upload anything with `fetch` or XHR even if it wanted to.

## Limits

- **Networks:** works reliably when both devices are on the same Wi-Fi or ordinary home networks. Without a TURN relay, some mobile carrier and corporate networks block direct connections.
- **Size:** the receiver keeps the file in memory until it's saved, so very large files (several GB) may not fit on a phone.
- **One shot:** each QR code is for one transfer. The sender's page must stay open until it finishes.

## Run locally

```sh
python3 -m http.server 8000
```

Then open http://localhost:8000. Camera access and WebCrypto need `localhost` or HTTPS.

## Deploy

Settings → Pages → Build and deployment → Source: **Deploy from a branch**, Branch: **main**, folder **/ (root)**.

## Third-party code

Vendored in `vendor/` so the page loads nothing from a CDN:

- [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) 1.4.4 (MIT), draws the QR codes
- [jsQR](https://github.com/cozmo/jsQR) 1.4.0 (Apache-2.0), reads QR codes from the camera when the browser has no built-in `BarcodeDetector`
