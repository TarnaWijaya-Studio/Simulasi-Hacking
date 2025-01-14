import random

soal_jawaban = [
    {
        "soal": "Apa itu serangan brute force?",
        "pilihan": ["Mencoba semua kombinasi password", "Mengirim email phishing", "Memanfaatkan celah XSS", "Menggunakan malware"],
        "jawaban": 0
    },
    {
        "soal": "Apa yang dimaksud dengan 'firewall'?",
        "pilihan": ["Perangkat lunak atau perangkat keras untuk mencegah akses tidak sah", "Teknik enkripsi data", "Metode penghapusan malware", "Jenis serangan DDoS"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu enkripsi?",
        "pilihan": ["Proses mengubah data menjadi format yang tidak terbaca tanpa kunci", "Proses menghapus data secara permanen", "Proses membuat cadangan data", "Proses memindai virus"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu VPN?",
        "pilihan": ["Virtual Private Network", "Virtual Protected Network", "Virtual Public Network", "Virtual Personal Network"],
        "jawaban": 0
    },
    {
        "soal": "Apa fungsi dari SSL dalam keamanan siber?",
        "pilihan": ["Mengamankan koneksi antara server dan browser", "Memblokir malware", "Mengelola firewall", "Mendeteksi serangan DDoS"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu malware?",
        "pilihan": ["Perangkat lunak berbahaya", "Perangkat lunak antivirus", "Protokol jaringan", "Enkripsi data"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu ransomware?",
        "pilihan": ["Malware yang mengenkripsi data dan meminta tebusan", "Serangan phishing", "Serangan brute force", "Pemindai virus"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu DDoS?",
        "pilihan": ["Distributed Denial of Service", "Distributed Data on Server", "Data Damage on System", "Denial of Data Service"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu SQL Injection?",
        "pilihan": ["Teknik menyuntikkan perintah SQL ke dalam input aplikasi", "Serangan brute force", "Malware", "Enkripsi data"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu XSS?",
        "pilihan": ["Cross-Site Scripting", "Cross-System Scripting", "Xtreme Secure System", "X-Ray Secure System"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu honeypot dalam keamanan siber?",
        "pilihan": ["Sistem yang digunakan untuk menarik serangan dan mempelajari tekniknya", "Alat enkripsi data", "Protokol keamanan jaringan", "Jenis malware"],
        "jawaban": 0
    },
    {
        "soal": "Apa yang dimaksud dengan 'zero-day exploit'?",
        "pilihan": ["Kerentanan yang belum diketahui oleh vendor perangkat lunak", "Serangan DDoS", "Protokol keamanan", "Jenis malware"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu social engineering?",
        "pilihan": ["Teknik manipulasi psikologis untuk mendapatkan informasi rahasia", "Proses menghapus malware", "Proses enkripsi data", "Teknik brute force"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu hashing?",
        "pilihan": ["Proses mengubah data menjadi nilai tetap", "Proses enkripsi data", "Proses brute force", "Proses scanning malware"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu rootkit?",
        "pilihan": ["Perangkat lunak yang memungkinkan akses tidak sah ke komputer", "Proses enkripsi data", "Proses scanning malware", "Jenis firewall"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu sniffing?",
        "pilihan": ["Menyadap data yang dikirimkan melalui jaringan", "Proses enkripsi data", "Jenis malware", "Metode brute force"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu cyber threat intelligence?",
        "pilihan": ["Informasi yang dikumpulkan untuk memprediksi dan mencegah serangan siber", "Protokol keamanan", "Jenis malware", "Teknik brute force"],
        "jawaban": 0
    },
    {
        "soal": "Apa yang dimaksud dengan 'backdoor'?",
        "pilihan": ["Jalur rahasia yang digunakan untuk mengakses sistem tanpa otorisasi", "Proses scanning malware", "Proses enkripsi data", "Teknik brute force"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu IDS dalam keamanan siber?",
        "pilihan": ["Intrusion Detection System", "Information Data System", "Internal Data Security", "Information Detection System"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu keylogger?",
        "pilihan": ["Perangkat lunak yang merekam penekanan tombol", "Jenis firewall", "Proses enkripsi data", "Proses scanning malware"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu CAPTCHA?",
        "pilihan": ["Tes untuk membedakan manusia dan bot", "Proses enkripsi data", "Proses scanning malware", "Teknik brute force"],
        "jawaban": 0
    },
    {
        "soal": "Apa fungsi dari antivirus?",
        "pilihan": ["Mendeteksi dan menghapus perangkat lunak berbahaya", "Proses enkripsi data", "Jenis firewall", "Teknik brute force"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu multi-factor authentication?",
        "pilihan": ["Metode otentikasi yang memerlukan lebih dari satu cara verifikasi", "Proses enkripsi data", "Jenis firewall", "Proses scanning malware"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu steganografi?",
        "pilihan": ["Teknik menyembunyikan data di dalam file lain", "Proses enkripsi data", "Proses scanning malware", "Teknik brute force"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu man-in-the-middle attack?",
        "pilihan": ["Serangan di mana penyerang menyadap komunikasi antara dua pihak", "Proses enkripsi data", "Proses scanning malware", "Jenis firewall"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu data breach?",
        "pilihan": ["Pelanggaran keamanan yang mengakibatkan data terekspos", "Proses enkripsi data", "Proses scanning malware", "Jenis firewall"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu penetration testing?",
        "pilihan": ["Proses menguji keamanan sistem dengan mensimulasikan serangan", "Proses enkripsi data", "Jenis firewall", "Teknik brute force"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu Botnet?",
        "pilihan": ["Jaringan komputer yang dikendalikan untuk melakukan serangan", "Proses enkripsi data", "Proses scanning malware", "Jenis firewall"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu trojan horse?",
        "pilihan": ["Malware yang menyamar sebagai perangkat lunak yang sah", "Jenis firewall", "Proses enkripsi data", "Proses scanning malware"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu spyware?",
        "pilihan": ["Perangkat lunak yang memata-matai aktivitas pengguna", "Proses enkripsi data", "Jenis firewall", "Teknik brute force"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu spoofing?",
        "pilihan": ["Memalsukan identitas atau informasi untuk menipu", "Proses enkripsi data", "Proses scanning malware", "Jenis firewall"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu insider threat?",
        "pilihan": ["Ancaman dari orang dalam organisasi", "Proses enkripsi data", "Jenis firewall", "Teknik brute force"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu cryptojacking?",
        "pilihan": ["Penggunaan tidak sah perangkat komputer untuk menambang cryptocurrency", "Proses enkripsi data", "Proses scanning malware", "Jenis firewall"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu buffer overflow?",
        "pilihan": ["Serangan di mana data melebihi kapasitas buffer dan menyebabkan kerusakan sistem", "Proses enkripsi data", "Proses scanning malware", "Jenis firewall"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu cybersecurity?",
        "pilihan": ["Perlindungan sistem komputer dan jaringan dari ancaman", "Proses enkripsi data", "Proses scanning malware", "Jenis firewall"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu patching?",
        "pilihan": ["Memperbaiki kerentanan perangkat lunak dengan pembaruan", "Proses enkripsi data", "Proses scanning malware", "Jenis firewall"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu risk assessment?",
        "pilihan": ["Proses mengevaluasi risiko keamanan sistem", "Proses enkripsi data", "Proses scanning malware", "Jenis firewall"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu secure coding?",
        "pilihan": ["Praktik menulis kode yang aman dari kerentanan", "Proses enkripsi data", "Proses scanning malware", "Jenis firewall"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu cyber resilience?",
        "pilihan": ["Kemampuan sistem untuk bertahan dan pulih dari serangan siber", "Proses enkripsi data", "Proses scanning malware", "Jenis firewall"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu cyber hygiene?",
        "pilihan": ["Kebiasaan menjaga keamanan perangkat dan data secara rutin", "Proses enkripsi data", "Proses scanning malware", "Jenis firewall"],
        "jawaban": 0
    },
    {
        "soal": "Apa itu penetration testing?",
        "pilihan": ["Proses menguji keamanan sistem dengan mensimulasikan serangan", "Proses enkripsi data", "Proses scanning malware", "Jenis firewall"],
        "jawaban": 0
    }
]

def tampilkan_soal(soal_jawaban):
    random.shuffle(soal_jawaban)
    for index, item in enumerate(soal_jawaban[:45], start=1):
        print(f"Soal {index}: {item['soal']}")
        for i, pilihan in enumerate(item['pilihan']):
            print(f"  {chr(65 + i)}. {pilihan}")
        jawaban_benar = chr(65 + item['jawaban'])
        print(f"Jawaban yang benar: {jawaban_benar}\n")

tampilkan_soal(soal_jawaban)