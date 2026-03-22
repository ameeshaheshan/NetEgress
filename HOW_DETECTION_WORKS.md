# How Your SSRF Scanner Detects Vulnerabilities

## Overview

Your scanner uses a **baseline comparison approach** combined with **anomaly detection** to identify SSRF vulnerabilities. Here's the complete detection workflow:

---

## Step-by-Step Detection Process

### Phase 1: Baseline Establishment

**What happens:**

```python
# Scanner makes 10 requests to the target with normal/safe values
baseline = await scanner.establish_baseline(10)
```

**What it records:**

1. **Status Codes** - What HTTP status codes are normal (e.g., 400, 404, 200)
2. **Response Size** - Average content length (e.g., 30 bytes)
3. **Content Hash** - MD5 hash of the response body
4. **Response Time** - Average time to respond (e.g., 0.93 seconds)
5. **Headers Fingerprint** - Which headers are present

**Example Baseline:**

```json
{
  "avg_response_size": 30,
  "status_codes": { "400": 10 },
  "content_hash": "abc123...",
  "avg_response_time": 0.93,
  "headers_fingerprint": "content-type,date,server"
}
```

---

### Phase 2: Payload Testing

**What happens:**

```python
# Scanner tests each SSRF payload
for payload in payloads:
    result = await scanner.test_payload(
        payload="http://127.0.0.1/admin",
        param="stockApi",
        method="POST"
    )
```

**For each payload, it:**

1. Injects the payload into the target parameter
2. Sends the request (GET or POST)
3. Captures the response
4. Compares against baseline

---

### Phase 3: Anomaly Detection

**The scanner checks for differences from baseline:**

#### 1. **Status Code Change** ✅ Most Reliable

```python
# Baseline: Always returns 400
# Test with localhost: Returns 200
# ANOMALY DETECTED!

if response['status_code'] not in baseline.status_codes:
    reasons.append(f"Unusual status code: {response['status_code']}")
```

**Example:**

- Baseline: `400 Bad Request` (invalid stockApi value)
- Payload `http://127.0.0.1`: `200 OK` (server accessed localhost!)
- **Vulnerability detected!**

#### 2. **Response Size Deviation**

```python
# Baseline: 30 bytes average
# Test with localhost: 3000 bytes
# Size deviation: 9900% > 30% threshold
# ANOMALY DETECTED!

size_diff = abs(response_length - baseline.avg_response_size)
size_deviation = size_diff / baseline.avg_response_size

if size_deviation > 0.30:  # 30% threshold
    reasons.append(f"Response size deviation: {size_deviation:.2%}")
```

**Example:**

- Baseline: 30 bytes (error message)
- Payload `http://192.168.1.1`: 2500 bytes (internal admin page!)
- **Vulnerability detected!**

#### 3. **Content Hash Mismatch**

```python
# Baseline: Same error message every time
# Test with localhost: Different content
# ANOMALY DETECTED!

content_hash = hashlib.md5(response['content']).hexdigest()
if content_hash != baseline.content_hash:
    reasons.append("Content hash mismatch")
```

#### 4. **Response Time Deviation**

```python
# Baseline: 0.93 seconds
# Test with closed port: 15 seconds (timeout)
# Time deviation: 1500% > 200% threshold
# ANOMALY DETECTED!

time_diff = abs(response_time - baseline.avg_response_time)
time_deviation = time_diff / baseline.avg_response_time

if time_deviation > 2.0:  # 200% threshold
    reasons.append(f"Response time deviation: {time_deviation:.2%}")
```

---

### Phase 4: Verification

**After detecting an anomaly, the verifier confirms it:**

```python
# verification.py
verified = verifier.verify_vulnerability(result, oob_domain)
```

**Verification checks:**

1. **Confidence Score Calculation**
   - Status code change: +40%
   - Content indicators found: +30%
   - Response size change: +20%
   - Timing anomaly: +10%

2. **Content Pattern Matching**

   ```python
   SSRF_INDICATORS = [
       b'root:', b'admin:',           # User lists
       b'AWS', b'metadata',            # Cloud metadata
       b'BEGIN RSA', b'api_key'        # Sensitive data
   ]
   ```

3. **Vulnerability Classification**
   - `SSRF_CONFIRMED` - High confidence (>80%)
   - `SSRF_LIKELY` - Medium confidence (60-80%)
   - `SSRF_POSSIBLE` - Low confidence (40-60%)

---

## Real Example: Your Scan Results

### Target

```
URL: https://0ac600e70357a0e3dc0dd88f00de00f4.web-security-academy.net/product/stock
Method: POST
Parameter: stockApi
Additional Data: productId=1&storeId=1
```

### Baseline (Normal Request)

```http
POST /product/stock HTTP/1.1
Content-Type: application/x-www-form-urlencoded

stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1

Response:
Status: 400 Bad Request
Size: 30 bytes
Content: "Invalid stock API endpoint"
```

### Test with Payload: `http://127.0.0.1`

```http
POST /product/stock HTTP/1.1
Content-Type: application/x-www-form-urlencoded

stockApi=http://127.0.0.1&productId=1&storeId=1

Response:
Status: 200 OK  ← DIFFERENT FROM BASELINE!
Size: 2500 bytes  ← MUCH LARGER!
Content: "<html>Internal Admin Panel...</html>"  ← DIFFERENT CONTENT!
```

### Detection Logic

```python
# 1. Status code changed: 400 → 200
anomaly_reasons.append("Unusual status code: 200")

# 2. Size deviation: (2500 - 30) / 30 = 8233%
anomaly_reasons.append("Response size deviation: 8233%")

# 3. Content hash different
anomaly_reasons.append("Content hash mismatch")

# Result: VULNERABILITY DETECTED!
confidence = 60%  # MEDIUM severity
vulnerability_type = "SSRF_ANOMALY_DETECTED"
```

---

## Why This Approach Works

### ✅ Advantages

1. **No False Positives from Normal Errors**
   - If baseline is always 404, another 404 won't trigger
   - Only flags _changes_ from normal behavior

2. **Works Without Knowing Expected Response**
   - Don't need to know what localhost returns
   - Just detects "something different happened"

3. **Detects Multiple SSRF Types**
   - Internal network access (different response)
   - Port scanning (timing differences)
   - Cloud metadata (content changes)
   - File access (size/content changes)

4. **Handles Both GET and POST**
   - Your scanner supports both methods
   - Most scanners only do GET

### ⚠️ Limitations

1. **Requires Stable Baseline**
   - If target returns random responses, baseline won't work
   - Solution: Increase baseline probes (you use 10)

2. **May Miss Blind SSRF**
   - If server makes request but returns same response
   - Solution: Use `--oob-domain` for out-of-band detection

3. **Threshold Tuning**
   - 30% size deviation might be too sensitive or not sensitive enough
   - Can be adjusted in `core.py`

---

## Code Flow Diagram

```
┌─────────────────────────────────────────┐
│ 1. BASELINE ESTABLISHMENT               │
│    - Make 10 normal requests            │
│    - Record status, size, hash, time    │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│ 2. PAYLOAD GENERATION                   │
│    - Load payloads from files           │
│    - Generate dynamic payloads          │
│    - 447 total payloads                 │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│ 3. PAYLOAD TESTING (for each payload)  │
│    - Inject into parameter              │
│    - Send POST/GET request              │
│    - Capture response                   │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│ 4. ANOMALY DETECTION                    │
│    - Compare status code                │
│    - Compare response size              │
│    - Compare content hash               │
│    - Compare response time              │
└─────────────┬───────────────────────────┘
              │
              ▼
         Is Anomalous?
              │
        ┌─────┴─────┐
        │           │
       YES          NO
        │           │
        ▼           ▼
┌─────────────┐  Continue
│ 5. VERIFY   │  to next
│    - Check  │  payload
│      content│
│    - Calc   │
│      confidence
│    - Classify
└──────┬──────┘
       │
       ▼
  Vulnerable?
       │
      YES
       │
       ▼
┌─────────────┐
│ 6. REPORT   │
│    - Log    │
│    - Save   │
│    - Alert  │
└─────────────┘
```

---

## Key Files in Your Scanner

### [core.py](file:///C:/Users/User/OneDrive/Desktop/Final%20Project/SSRF%20Automation/ssrf_scanner/core.py)

- `establish_baseline()` - Creates baseline metrics
- `test_payload()` - Tests each payload
- `is_anomalous()` - Detects anomalies

### [verification.py](file:///C:/Users/User/OneDrive/Desktop/Final%20Project/SSRF%20Automation/ssrf_scanner/verification.py)

- `verify_vulnerability()` - Confirms findings
- Pattern matching for SSRF indicators
- Confidence scoring

### [attack_modules.py](file:///C:/Users/User/OneDrive/Desktop/Final%20Project/SSRF%20Automation/ssrf_scanner/attack_modules.py)

- Generates all 447 payloads
- 10 attack phases
- Dynamic payload generation

---

## Summary

**Your scanner detects SSRF by:**

1. **Learning normal behavior** (baseline)
2. **Testing malicious payloads** (attack)
3. **Detecting differences** (anomaly detection)
4. **Verifying findings** (confirmation)
5. **Reporting results** (output)

**Why it works:**

- Compares "normal" vs "abnormal" responses
- Doesn't need to know what localhost returns
- Detects any significant change from baseline
- Works for both GET and POST parameters

**Your advantage:**

- POST parameter support (most scanners don't have this!)
- 10 baseline probes (more accurate than 3)
- Multiple verification layers
- Comprehensive reporting

This is why your scanner successfully detected the `stockApi` vulnerability! 🎯
