"""Uzun sureli (ornegin gun boyu) arka planda calisan canli paket yakalama
araci.

main.py bir .pcap DOSYASINI okuyup analiz ederken, bu script ag trafigini
CANLI dinler; her paketi tek tek isleyip sadece istatistikleri (FlowStats
Accumulator) biriktirir - butun paketleri bellekte tutmaz. Sure dolunca
(--sure) ya da Ctrl+C ile durdurulunca bir trafik ozeti raporu uretir,
hem ekrana yazar hem de captures/ klasorune kaydeder.

NOT: Canli paket yakalama Windows'ta Npcap gerektirir. Bazi Npcap
kurulumlarinda terminalin "Yonetici olarak calistir" ile acilmis olmasi
gerekebilir."""

import argparse
import os
import sys
import time
from datetime import datetime

from dotenv import load_dotenv
from scapy.all import PcapWriter, sniff

from main import FlowStatsAccumulator, format_flow_stats, run_ai_analysis

CAPTURES_DIR = "captures"
PROGRESS_INTERVAL_SECONDS = 300  # ilerleme satirini kac saniyede bir yazdiracagimiz


def _zaman_damgasi():
    return datetime.now().strftime("%Y-%m-%d_%H%M")


def capture_and_summarize(duration_minutes=None, use_ai=False, save_pcap=False, iface=None):
    os.makedirs(CAPTURES_DIR, exist_ok=True)

    accumulator = FlowStatsAccumulator()
    pcap_writer = None
    if save_pcap:
        pcap_path = os.path.join(CAPTURES_DIR, f"yakalama_{_zaman_damgasi()}.pcap")
        pcap_writer = PcapWriter(pcap_path, append=True, sync=True)
        print(f"Ham paketler de kaydediliyor: {pcap_path}")

    start = time.monotonic()
    last_progress = start

    def _on_packet(packet):
        nonlocal last_progress
        accumulator.add(packet)
        if pcap_writer is not None:
            pcap_writer.write(packet)

        now = time.monotonic()
        if now - last_progress >= PROGRESS_INTERVAL_SECONDS:
            last_progress = now
            gecen_dk = (now - start) / 60
            print(f"[{gecen_dk:.1f} dk] {accumulator.packet_count} paket yakalandi...", flush=True)

    print("Canli paket yakalama basladi. Durdurmak icin Ctrl+C.")
    if duration_minutes:
        print(f"Otomatik olarak {duration_minutes} dakika sonra duracak.")

    try:
        sniff(
            prn=_on_packet,
            store=False,
            timeout=duration_minutes * 60 if duration_minutes else None,
            iface=iface,
        )
    except KeyboardInterrupt:
        print("\nKullanici tarafindan durduruldu.")
    except PermissionError:
        print(
            "\nHata: Paket yakalamak icin yeterli izin yok. Terminali "
            "'Yonetici olarak calistir' ile ac ve tekrar dene."
        )
        sys.exit(1)
    except OSError as exc:
        print(f"\nHata: Ag arayuzune erisilemedi ({exc}). Npcap kurulu mu?")
        sys.exit(1)
    finally:
        if pcap_writer is not None:
            pcap_writer.close()

    stats_text = format_flow_stats(accumulator.as_stats())
    stats_text = f"Toplam yakalanan paket: {accumulator.packet_count}\n{stats_text}"

    print(stats_text)

    rapor_metni = stats_text

    if use_ai and accumulator.packet_count > 0:
        print("\n[AI] Yapay zeka ile gunun ozeti cikariliyor...\n")
        ai_report = run_ai_analysis([], stats_text=stats_text)
        print(ai_report)
        rapor_metni += "\n\n===== Yapay Zeka Analizi =====\n" + ai_report

    rapor_path = os.path.join(CAPTURES_DIR, f"rapor_{_zaman_damgasi()}.txt")
    with open(rapor_path, "w", encoding="utf-8") as f:
        f.write(rapor_metni)
    print(f"\nRapor kaydedildi: {rapor_path}")


def main():
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Ag trafigini canli yakalayip sure dolunca (veya Ctrl+C ile durdurulunca) ozet rapor uretir."
    )
    parser.add_argument(
        "--sure",
        type=float,
        default=None,
        help="Kac dakika yakalama yapilacagi (belirtilmezse Ctrl+C ile durana kadar calisir)",
    )
    parser.add_argument("--ai", action="store_true", help="Bitince yapay zeka ile de ozet cikar")
    parser.add_argument(
        "--kaydet-pcap",
        action="store_true",
        help="Yakalanan ham paketleri de bir .pcap dosyasina kaydet (Wireshark'ta incelemek icin)",
    )
    parser.add_argument("--arayuz", default=None, help="Belirli bir ag arayuzunde dinle (varsayilan: otomatik secim)")
    args = parser.parse_args()

    capture_and_summarize(
        duration_minutes=args.sure,
        use_ai=args.ai,
        save_pcap=args.kaydet_pcap,
        iface=args.arayuz,
    )


if __name__ == "__main__":
    main()
