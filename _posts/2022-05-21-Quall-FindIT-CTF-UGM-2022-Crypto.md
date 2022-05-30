---
title: "Quall FindIT CTF UGM 2022 Crypto"
date: "2022-05-21"
published: true
---  

## **EzRSA**

Pada soal telah disediakan modulus, exponent, dan ciphertext dari sebuah RSA sebagai berikut:

```
c=48194219261855563203215132311565813649624212082168963448568445899090
e=65537
n=634700503487766158115038509619422295969417670380913058190145906857689
```

Pertama kali lihat adalah nilai n yang sangat kecil, sehingga mudah difaktorkan. Sehingga dengan menggunakan [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool.git), plaintext dapat didapatkan dengan mudah.

```cmd
python3 RsaCtfTool.py -n 634700503487766158115038509619422295969417670380913058190145906857689 --uncipher 48194219261855563203215132311565813649624212082168963448568445899090 -e 65537
```

Flag: FindITCTF{3a5y\_12iGht?}

  
<br/>
## **Number**

Pada soal terdapat suatu rangkaian text yang hanya berisi angka:

```
70202105202110202100202732028420267202842027020212320252202832026720233202732029520289202482028520295202712024820284202952024920284202125
```

Bila diteliti lebih lanjut, terdapat suatu susunan angka yang selalu berulang, yaitu angka 202. Bila semua susunan angka ini dihapus dan diganti dengan spasi, maka akan didapatkan representasi _decimal_ dari range _ascii printable_:

```
70 105 110 100 73 84 67 84 70 123 52 83 67 33 73 95 89 48 85 95 71 48 84 95 49 84 125
```

Menggunakan tool konversi [kode decimal ascii ke huruf ascii](https://www.rapidtables.com/convert/number/ascii-hex-bin-dec-converter.html) akan didapatkan teks sebagai berikut:

Flag: FindITCTF{4SC!I\_Y0U\_G0T\_1T}  
  
  
<br/>
## **Vigenere**

Pada soal diberikan sebuah teks berisi:

```
Hint: vigorous and sincere. 45 5A 43 52 59 50 54 4F.
Code: XGQLYGMOZHIVLTKSID
Note: Masukkan jawaban yang ditemukan ke dalam format flag CTF Find IT untuk mendapatkan flag seutuhnya.
```

Sesuai dengan namanya, soal ini pasti berhubungan dengan Vigenere Cipher. Dengan adanya ciphertext, maka yang dibutuhkan adalah keynya.

Pada hint terdapat rangkaian hexcode ascii range printable, setelah diubah menjadi huruf ascii, maka menjadi:

```
EZCRYPTO
```

Dengan menggunakan tool online [Vigenere Cipher](https://www.dcode.fr/vigenere-cipher), key dan ciphertext dimasukkan sehingga ditemukan:

```
THOUARTAVIGENEREEE
```

Maka Flag: FindITCTF{THOUARTAVIGENEREEE}  
  
  
<br/>
## **RevTrans**

Pada challenge diberikan sebuah file python dan ciphertext.

```
eiluFIFatv_{Tiy_esyCn}y_ooTd
```

```py
flag = "FindITCTF{REDACTED}"

def split_len(seq, length):
   return [seq[i:i + length] for i in range(0, len(seq), length)]

def encode(key, plaintext):
   order = {
      int(val): num for num, val in enumerate(key)
   }
   reversetext =''
   ciphertext = ''
   i=len(plaintext)-1
   while i >= 0:
      reversetext = reversetext + plaintext[i]
      i=i-1
   for index in sorted(order.keys()):
      for part in split_len(reversetext, len(key)):
         try:ciphertext += part[order[index]]
         except IndexError:
            continue            
   return ciphertext
print(encode('4321', flag))
```

Dari kode tersebut, akan dilakukan reverse dari plaintext, membaginya menjadi sebanyak _order_ sama rata, kemudian menyusun ciphertext perbagian mengikuti _order_ dengan key _index_:

```py
flag = 'FindItCTF{REDACTED}'
 
# bagi into chunks
def split_len(seq, length):
   return [seq[i:i + length] for i in range(0, len(seq), length)]
 
def encode(key, plaintext):
   order = {
      int(val): num for num, val in enumerate(key)
   }
   reversetext =''
   ciphertext = ''
   i=len(plaintext)-1
   while i >= 0:
      reversetext = reversetext + plaintext[i]
      i=i-1
   "untuk setiap order"
   for index in sorted(order.keys()):
      " bagi 4 4 bagian"
      for part in split_len(reversetext, len(key)):
         try:ciphertext += part[order[index]]
         except IndexError:
            continue     
   return ciphertext
 
print(encode('4321', flag))
```

![](https://lh5.googleusercontent.com/1ImxFeQcQgZJDBXIyDwrfYdP1Jwv11hCMLq7xHnJLvGXg1HRI5ZNNW9hKkCn1AfQ08Dfwo1cYUYT-QQ4pJvmgnj7Fs0hROAZ5C0XEYyxJFIXz81_wORBeqANoRMLASOptdw3utgPnRjfn1U2Vw)

Dari percobaan tersebut, saya merasa teknik enkripsi seperti ini dapat dilakukan secara brute force dengan melakukan mapping dari posisi awal ke posisi setelah dilakukan enkripsi. Untuk mengetes hipotesis, saya mengganti flag dengan flag buatan yang menyamai panjang dari output dan tetap mempertahankan posisi kurung kurawal.

```
flag = '123456789{qwertyuiopasdfghj}'
```

dari flag buatan tersebut dikeluarkan seperti ini:

```
gaue951hsir{62jdotq73}fpyw84 #flag buatan
eiluFIFatv_{Tiy_esyCn}y_ooTd #flag asli
```

kurung kurawal berada pada tempat yang sama. Merasa yakin, saya membuat script untuk melakukan mapping index dari posisi awal ke akhir:

```py
sample     = "123456789{qwertyuiopasdfghj}"
sample_enc = "gaue951hsir{62jdotq73}fpyw84"
enc_flag   = "eiluFIFatv_{Tiy_esyCn}y_ooTd"
 
mapping = {}
 
for i in range(len(sample)):
    mapping[i] = sample_enc.index(sample[i])
 
for i in range(len(enc_flag)):
    print(enc_flag[mapping[i]], end="")
```

Dengan output:

```
FindITCTF{you_solve_it_yeay}
```

  
  
<br/>
## **Happy Forever**

Pada challenge, diberikan:

```py
from secret import HAPPY_NUM, FLAG
import base64
 
"""reverse kemudian baca jadi hex """
FLAGenc = FLAG[::-1].encode().hex()
 
ciphertext = [(ord(c)^(HAPPY_NUM[i]+i)) for i,c in enumerate(FLAGenc)]
 
"""setiap hex char di xor happy_num + i"""
"""assume happy_num list of num"""
for i, c in enumerate(FLAGenc):
    ciphertext += ord(c)^(HAPPY_NUM[i]+i)
 
print(f"ciphertext = {ciphertext}")
```

```py
ciphertext = [54, 108, 63, 41, 36, 37, 17, 31, 27, 12, 8, 118, 97, 101, 85, 3, 88, 9, 64, 64, 79, 186, 164, 160, 174, 149, 246, 249, 237, 189, 232, 131, 223, 146, 206, 305, 317, 291, 294, 286, 284, 374, 379, 358, 362, 367, 337, 270, 344, 328, 333, 332, 328, 439, 425, 405, 403, 400, 415, 469, 388, 399, 500, 500, 509, 424, 480, 488, 458, 608, 547, 553, 533, 512, 512, 515, 599, 588, 692, 738, 693, 640, 652, 675, 759, 763, 740, 736, 738, 750, 726, 732, 735, 724, 705, 714, 823, 876, 827, 800, 788, 796]
```

Menurut [wikipedia](https://en.wikipedia.org/wiki/Happy_number), Happy Number merupakan sebuah angka spesial yang mengikuti sebuah aturan. Saya tidak membaca dengan detil dan langsung melakukan scroll ke bawah dan menemukan:

![](https://lh4.googleusercontent.com/GCaMJ8k7_NsdCW1yWPsMHbG2rrZuW6lbx18SsCgNxiAUrwXwpeShyLo8Y45zR6-kIaQL6BSOSJGsN1oefJUAkOfixv9dYD6SefmmyRDfNlCknx6eauDqwdxPNVAUhZY5s5fXOuogxBKxQhjFqA)

Saya langsung mengkopi sequence tersebut dan mencoba melakukan dekripsi:

```py
ciphertext = [54, 108, 63, 41, 36, 37, 17, 31, 27, 12, 8, 118, 97, 101, 85, 3, 88, 9, 64, 64, 79, 186, 164, 160, 174, 149, 246, 249, 237, 189, 232, 131, 223, 146, 206, 305, 317, 291, 294, 286, 284, 374, 379, 358, 362, 367, 337, 270, 344, 328, 333, 332, 328, 439, 425, 405, 403, 400, 415, 469, 388, 399, 500, 500, 509, 424, 480, 488, 458, 608, 547, 553, 533, 512, 512, 515, 599, 588, 692, 738, 693, 640, 652, 675, 759, 763, 740, 736, 738, 750, 726, 732, 735, 724, 705, 714, 823, 876, 827, 800, 788, 796]
 
not_happy_number = [1, 7, 10, 13, 19, 23, 28, 31, 32, 44, 49, 68, 70, 79, 82, 86, 91, 94, 97, 100, 103, 109, 129, 130, 133, 139, 167, 176, 188, 190, 192, 193, 203, 208, 219, 226, 230, 236, 239, 262, 263, 280, 291, 293, 301, 302, 310, 313, 319, 320, 326, 329, 331, 338, 356, 362, 365, 367, 368, 376, 379, 383, 386, 391, 392, 397, 404, 409, 440, 446, 464, 469, 478, 487, 490, 496, 536, 556, 563, 565, 566, 608, 617, 622, 623, 632, 635, 637, 638, 644, 649, 653, 655, 656, 665, 671, 673, 680, 683, 694, 700, 709, 716, 736, 739, 748, 761, 763, 784, 790, 793, 802, 806, 818, 820, 833, 836, 847, 860, 863, 874, 881, 888, 899, 901, 904, 907, 910, 912, 913, 921, 923, 931, 932, 937, 940, 946, 964, 970, 973, 989, 998, 1000]
 
new_hex = ""
for i, ec in enumerate(ciphertext):
    new_hex += chr(ec^(not_happy_number[i] + i))
 
p = bytes.fromhex(new_hex).decode('utf-8')
print(p[::-1])
```

Dengan output berupa flag:

```
FindITCTF{1_5H0Uld_B3_h4pPy_4f73r4Ll_r19H7?_999999}
```

  
  
<br/>
## **RandomSHA**

Pada soal diberikan:

```py
import random,string
import hashlib

flag = "FindITCTF{REDACTED}"
enc_flag = ""
random.seed("FINDIT")
now = ""
ct = []
for c in flag:
  if c.islower():
	  enc_flag += chr((ord(c)-ord('a')+random.randrange(0,26))%26 + ord('a'))
  elif c.isupper():
	  enc_flag += chr((ord(c)-ord('A')+random.randrange(0,26))%26 + ord('A'))
  elif c.isdigit():
	  enc_flag += chr((ord(c)-ord('0')+random.randrange(0,10))%10 + ord('0'))
  else:
	  enc_flag += c

for c in enc_flag:
    now += c
    ct.append(
            int(hashlib.sha512(now.encode()).hexdigest(), 16)>>256
        )

print(f"ct = {ct}")
```

```
ct = [16827491998982303935845912726250001246506259002934220576276361965668860811468, 62713198357581005397268349101156886804274040256360973798128860841455571633780, 
.....]
```

Dari output dan chall.py kita tahu program menyimpan hasil hashing setiap penambahan character, kita tinggal mengikuti jejak hashnya dan mendapatkan flagnya. Yang membuatnya tidak semudah itu adalah adanya campur tangan random, untungnya kita diberikan seednya dan dapat melakukan brute force dengan mengikuti alur program.

```py
import random,string
import hashlib
ct =[ 16827491998982303935845912726250001246506259002934220576276361965668860811468,
..,
..,
32141083108499196137603954986721075935614843412879401775449594747381368240336
]
 
crip_flag = ""
brute = """abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ#$%&\\'()+,-./:;<=>?@[\\]^_`|~\}{\""""
for i, hashc in enumerate(ct): # string main
    for cc in brute: # guessing game
        random.seed("FINDIT")
        enc_fl_guess =""
        for c in crip_flag + cc:
            if c.islower():
     			enc_fl_guess += chr((ord(c)-ord('a')+random.randrange(0,26)) % 26 + ord('a'))
            elif c.isupper():
                enc_fl_guess += chr((ord(c)-ord('A')+random.randrange(0,26))%26 + ord('A'))
            elif c.isdigit():
                enc_fl_guess += chr((ord(c)-ord('0')+random.randrange(0,10))%10 + ord('0'))
            else:
                enc_fl_guess += c
 
        if int(hashlib.sha512(enc_fl_guess.encode()).hexdigest(), 16)>>256 == ct[len(enc_fl_guess) - 1]:
            crip_flag += cc
            print(crip_flag)
```

Dengan output:

```
FindITCTF{W3ll_R4nd0m_4nd_SHA_r1ghtt?}
```
[home](/)