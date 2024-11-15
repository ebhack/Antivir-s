
import os  # İşletim sistemi ile etkileşim kurmak için os modülünü içe aktarır.
import hashlib  # Dosya hash'lerini hesaplamak için hashlib modülünü içe aktarır.
import shutil  # Dosya taşıma ve kopyalama işlemleri için shutil modülünü içe aktarır.
import sqlite3  # SQLite veritabanı ile etkileşim kurmak için sqlite3 modülünü içe aktarır.
import tkinter as tk  # Tkinter modülünü içe aktarır, GUI oluşturmak için kullanılır.
from tkinter import filedialog, messagebox  # Tkinter'dan dosya diyaloğu ve mesaj kutusu fonksiyonlarını içe aktarır.
import psutil  # Sistem işlemleri ve ağ bağlantılarını izlemek için psutil modülünü içe aktarır.

# SQLite veritabanı bağlantısı
def init_db():
    conn = sqlite3.connect('antivirus.db')  # Veritabanı bağlantısını kurar.
    c = conn.cursor()  # Veritabanı imlecini oluşturur.
    c.execute('''CREATE TABLE IF NOT EXISTS virus_signatures (name TEXT, signature TEXT)''')  # Virüs imzaları tablosunu oluşturur.
    c.execute('''CREATE TABLE IF NOT EXISTS logs (timestamp TEXT, action TEXT, details TEXT)''')  # Loglar tablosunu oluşturur.
    conn.commit()  # Değişiklikleri kaydeder.
    conn.close()  # Veritabanı bağlantısını kapatır.

init_db()  # Veritabanını başlatır.

# Virüs imzalarını eklemek için bir fonksiyon
def add_virus_signature(name, signature):
    conn = sqlite3.connect('antivirus.db')  # Veritabanı bağlantısını kurar.
    c = conn.cursor()  # Veritabanı imlecini oluşturur.
    c.execute('INSERT INTO virus_signatures (name, signature) VALUES (?, ?)', (name, signature))  # Yeni virüs imzası ekler.
    conn.commit()  # Değişiklikleri kaydeder.
    conn.close()  # Veritabanı bağlantısını kapatır.

# Örnek virüs imzası ekleyelim
add_virus_signature('eicar_test_file', '44d88612fea8a8f36de82e1278abb02f')

# Virüs imzalarını veritabanından çekmek için bir fonksiyon
def get_virus_signatures():
    conn = sqlite3.connect('antivirus.db')  # Veritabanı bağlantısını kurar.
    c = conn.cursor()  # Veritabanı imlecini oluşturur.
    c.execute('SELECT * FROM virus_signatures')  # Tüm virüs imzalarını seçer.
    virus_signatures = c.fetchall()  # Sonuçları alır.
    conn.close()  # Veritabanı bağlantısını kapatır.
    return {name: signature for name, signature in virus_signatures}  # Virüs imzalarını sözlük olarak döndürür.

# Hareket ve eylem loglarını veritabanına eklemek için bir fonksiyon
def log_action(action, details):
    conn = sqlite3.connect('antivirus.db')  # Veritabanı bağlantısını kurar.
    c = conn.cursor()  # Veritabanı imlecini oluşturur.
    c.execute('INSERT INTO logs (timestamp, action, details) VALUES (datetime("now"), ?, ?)', (action, details))  # Yeni log ekler.
    conn.commit()  # Değişiklikleri kaydeder.
    conn.close()  # Veritabanı bağlantısını kapatır.

# Dosyanın MD5 hash değerini hesaplayan fonksiyon
def compute_md5(file_path):
    """Dosyanın MD5 hash değerini hesaplar."""  # Bu işlev, dosyanın MD5 hash değerini hesaplar.
    with open(file_path, 'rb') as file:  # Dosyayı okuma modunda açar.
        file_data = file.read()  # Dosya içeriğini okur.
        md5_hash = hashlib.md5(file_data).hexdigest()  # MD5 hash'ini hesaplar.
    return md5_hash  # Hesaplanan MD5 hash değerini döndürür.

# Dosyayı virüs imzalarına karşı tarayan fonksiyon
def scan_file(file_path):
    """Dosyayı virüs imzalarına karşı tarar."""  # Bu işlev, dosyayı virüs imzalarına karşı tarar.
    file_md5 = compute_md5(file_path)  # Dosyanın MD5 hash değerini hesaplar.
    virus_signatures = get_virus_signatures()  # Virüs imzalarını veritabanından alır.
    for virus_name, virus_signature in virus_signatures.items():  # Tüm virüs imzalarını kontrol eder.
        if file_md5 == virus_signature:  # Eğer dosyanın hash değeri bir virüs imzası ile eşleşirse
            quarantine_file(file_path)  # Dosyayı karantinaya alır.
            log_action('Quarantine', f'{file_path} - {virus_name}')  # Log kaydı oluşturur.
            return virus_name  # Virüs ismini döndürür.
    log_action('Scan', f'{file_path} - Clean')  # Log kaydı oluşturur.
    return None  # Eşleşme yoksa None döndürür.

# Virüslü dosyayı karantinaya alan fonksiyon
def quarantine_file(file_path):
    """Virüslü dosyayı karantinaya alır."""  # Bu işlev, virüslü dosyayı karantinaya alır.
    if not os.path.exists(QUARANTINE_DIR):  # Karantina dizini yoksa
        os.makedirs(QUARANTINE_DIR)  # Karantina dizinini oluşturur.
    shutil.move(file_path, os.path.join(QUARANTINE_DIR, os.path.basename(file_path)))  # Dosyayı karantina dizinine taşır.

# Belirtilen dizini tarayan fonksiyon
def scan_directory(directory_path):
    """Belirtilen dizini tarar."""  # Bu işlev, belirtilen dizini tarar.
    infected_files = []  # Virüslü dosyaları saklamak için bir liste oluşturur.
    for root, _, files in os.walk(directory_path):  # Dizin içindeki tüm dosyaları tarar.
        for file in files:  # Her dosya için
            file_path = os.path.join(root, file)  # Dosya yolunu alır.
            virus_name = scan_file(file_path)  # Dosyayı tarar.
            if virus_name:  # Eğer dosya virüslü ise
                infected_files.append((file_path, virus_name))  # Virüslü dosyayı listeye ekler.
    return infected_files  # Bulunan tüm virüslü dosyaları döndürür.

# Dış ağ bağlantılarını izleyen fonksiyon
def monitor_network():
    """Dış ağ bağlantılarını izler."""  # Bu işlev, dış ağ bağlantılarını izler.
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'ESTABLISHED':
            log_action('Network Connection', f'PID: {conn.pid}, Local: {conn.laddr}, Remote: {conn.raddr}')
            process = psutil.Process(conn.pid)
            print(f'Process: {process.name()}, Connection: {conn.laddr} -> {conn.raddr}')
            # Şüpheli bağlantıları kontrol edebilir ve gerekli işlemleri yapabiliriz

# Dizin seçme diyalogunu açan fonksiyon
def browse_directory():
    """Dizin seçme diyalogunu açar."""  # Bu işlev, kullanıcıya taranacak dizini seçme imkanı sağlar.
    directory_path = filedialog.askdirectory()  # Dizin seçme diyalogunu açar.
    if directory_path:  # Eğer bir dizin seçildiyse
        result.set(f'Taranıyor: {directory_path}')  # Tarama işlemi başladığını gösterir.
        infected_files = scan_directory(directory_path)  # Seçilen dizini tarar.
        if infected_files:  # Eğer virüslü dosya bulunduysa
            result.set(f'{len(infected_files)} virüslü dosya bulundu ve karantinaya alındı.')  # Sonuçları gösterir.
            messagebox.showwarning('Virüs Tespit Edildi', f'Virüslü dosyalar bulundu: {infected_files}')  # Uyarı mesajı gösterir.
        else:  # Eğer virüslü dosya bulunmadıysa
            result.set('Hiçbir virüslü dosya bulunamadı.')  # Hiçbir virüs bulunmadığını gösterir.

# Tkinter
