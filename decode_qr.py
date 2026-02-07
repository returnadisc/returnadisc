from pyzbar.pyzbar import decode
from PIL import Image

img = Image.open("static/qr/DISC-68EZJC.png")

for d in decode(img):
    print(d.data.decode("utf-8"))
