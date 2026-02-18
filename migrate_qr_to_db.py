"""Migrerar befintliga QR-bilder till databasen."""
import os
import base64
import sys

# Lägg till projektets root i path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import db
from config import Config


def migrate_existing_qr():
    """Migrerar alla befintliga QR-bilder från static/qr till databasen."""
    
    qr_folder = getattr(Config, 'QR_FOLDER', 'static/qr')
    
    if not os.path.exists(qr_folder):
        print(f"QR-mappen finns inte: {qr_folder}")
        return
    
    files = [f for f in os.listdir(qr_folder) if f.startswith('qr_') and f.endswith('.png')]
    
    print(f"Hittade {len(files)} QR-bilder att migrera...")
    
    migrated = 0
    failed = 0
    skipped = 0
    
    for filename in files:
        # Extrahera QR-id från filnamn (qr_XXXXX.png)
        qr_id = filename[3:-4]  # Ta bort "qr_" och ".png"
        
        # Kolla om bilden redan finns i databasen
        if db.qr_image_exists(qr_id):
            print(f"⏭️  Hoppar över (finns redan i DB): {qr_id}")
            skipped += 1
            continue
        
        filepath = os.path.join(qr_folder, filename)
        
        try:
            # Läs filen
            with open(filepath, 'rb') as f:
                image_data = f.read()
            
            # Konvertera till base64
            img_base64 = base64.b64encode(image_data).decode('utf-8')
            
            # Spara i databasen
            if db.save_qr_image(qr_id, img_base64):
                print(f"✅ Migrerad: {qr_id}")
                migrated += 1
            else:
                print(f"❌ Misslyckades spara: {qr_id}")
                failed += 1
            
        except Exception as e:
            print(f"❌ Misslyckades: {qr_id} - {e}")
            failed += 1
    
    print(f"\n=== MIGRATION KLAR ===")
    print(f"Lyckade: {migrated}")
    print(f"Hoppar över: {skipped}")
    print(f"Misslyckade: {failed}")
    print(f"Totalt: {len(files)}")


if __name__ == '__main__':
    # Initiera databasen först
    print("Initierar databasen...")
    db.init_tables()
    print("Databas initierad.\n")
    
    migrate_existing_qr()