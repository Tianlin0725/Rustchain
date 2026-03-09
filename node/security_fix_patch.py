# Security Fix Patch for Issue #409
# This patch adds authentication and data sanitization to public API endpoints

# 1. Add a new decorator after admin_required (around line 2852)
# This decorator allows public access with optional authentication for enhanced data

def public_endpoint(require_auth=False):
    """
    Decorator for endpoints that are public but can return enhanced data with auth.
    - Without auth: returns sanitized/limited data
    - With valid API key: returns full data
    """
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key")
        is_admin = key == ADMIN_KEY if key else False
        
        # Pass auth status to the endpoint function
        request._is_admin = is_admin
        return f(*args, **kwargs)
    return decorated


# 2. Modify /api/miners endpoint (line ~3159)
# Replace the entire function with:

@app.route("/api/miners", methods=["GET"])
@public_endpoint()
def api_miners():
    """Return list of attested miners with their PoA details.
    
    Without authentication: returns sanitized data (no entropy_score, no first_attest)
    With authentication: returns full data
    """
    import time as _time
    now = int(_time.time())
    is_authenticated = getattr(request, '_is_admin', False)
    
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        rows = c.execute("""
            SELECT miner, ts_ok, device_family, device_arch, entropy_score
            FROM miner_attest_recent 
            WHERE ts_ok > ?
            ORDER BY ts_ok DESC
        """, (now - 3600,)).fetchall()
        
        miners = []
        for r in rows:
            arch = (r["device_arch"] or "unknown").lower()
            fam = (r["device_family"] or "unknown").lower()
            
            title_fam = r["device_family"] or "unknown"
            title_arch = r["device_arch"] or "unknown"
            mult = HARDWARE_WEIGHTS.get(title_fam, {}).get(title_arch, HARDWARE_WEIGHTS.get(title_fam, {}).get("default", 1.0))

            if "powerpc" in fam or "ppc" in fam:
                hw_type = f"PowerPC {title_arch.upper()} (Vintage)" if arch in ("g3","g4","g5") else f"PowerPC (Vintage)"
            elif "apple" in fam.lower() or arch in ("m1", "m2", "m3", "apple_silicon"):
                hw_type = "Apple Silicon (Modern)"
            elif "x86" in fam.lower() or "modern" in fam.lower():
                if "retro" in arch or "core2" in arch:
                    hw_type = "x86 Retro (Vintage)"
                else:
                    hw_type = "x86-64 (Modern)"
            else:
                hw_type = "Unknown/Other"

            miner_data = {
                "miner": r["miner"],
                "last_attest": r["ts_ok"],
                "device_family": r["device_family"],
                "device_arch": r["device_arch"],
                "hardware_type": hw_type,
                "antiquity_multiplier": mult
            }
            
            # Only return sensitive data with authentication
            if is_authenticated:
                # Get first attestation time
                try:
                    row2 = c.execute(
                        "SELECT MIN(ts_ok) AS first_ts FROM miner_attest_history WHERE miner = ?",
                        (r["miner"],),
                    ).fetchone()
                    first_attest = int(row2[0]) if row2 and row2[0] else None
                except Exception:
                    first_attest = None
                    
                miner_data["first_attest"] = first_attest
                miner_data["entropy_score"] = r["entropy_score"] or 0.0
            
            miners.append(miner_data)
    
    return jsonify(miners)


# 3. Modify /wallet/balance endpoint (line ~3716)
# Replace with:

@app.route('/wallet/balance', methods=['GET'])
def api_wallet_balance():
    """Get balance for a specific miner.
    
    Requires authentication via X-API-Key header.
    """
    # Check for API key
    key = request.headers.get("X-API-Key")
    if key != ADMIN_KEY:
        return jsonify({"ok": False, "reason": "authentication_required", "message": "Provide X-API-Key header with valid admin key"}), 401
    
    miner_id = request.args.get("miner_id", "").strip()
    if not miner_id:
        return jsonify({"ok": False, "error": "miner_id required"}), 400

    with sqlite3.connect(DB_PATH) as db:
        row = db.execute("SELECT amount_i64 FROM balances WHERE miner_id=?", (miner_id,)).fetchone()

    amt = int(row[0]) if row else 0
    return jsonify({
        "miner_id": miner_id,
        "amount_i64": amt,
        "amount_rtc": amt / UNIT
    })


# 4. Modify /epoch endpoint (line ~2199)
# Replace with:

@app.route('/epoch', methods=['GET'])
def get_epoch():
    """Get current epoch info.
    
    Returns limited public information without authentication.
    """
    key = request.headers.get("X-API-Key")
    is_authenticated = key == ADMIN_KEY if key else False
    
    slot = current_slot()
    epoch = slot_to_epoch(slot)
    epoch_gauge.set(epoch)

    with sqlite3.connect(DB_PATH) as c:
        enrolled = c.execute(
            "SELECT COUNT(*) FROM epoch_enroll WHERE epoch = ?",
            (epoch,)
        ).fetchone()[0]

    # Base public response
    response = {
        "epoch": epoch,
        "slot": slot,
        "blocks_per_epoch": EPOCH_SLOTS
    }
    
    # Only include sensitive financial data with authentication
    if is_authenticated:
        response["epoch_pot"] = PER_EPOCH_RTC
        response["enrolled_miners"] = enrolled
    
    return jsonify(response)
