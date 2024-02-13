---
title: "Quall FindIT CTF UGM 2022 Digital Forensics"
date: "2024-02-13"
published: true
---  



## **Citra**


Pada challenge ini diberikan sebuah file attachment txt. Sekilas, tidak terlihat apapun melihat teks tesebut. Namun, tiap line pada teks tersebut berisi 1920 angka, dan terdapat 1113 line. File ini juga memiliki separator koma (,) pada tiap angka yang ada, sehingga asumsi file tersebut memiliki format csv. Kemungkinan besar teks ini juga mengarah kepada data gambar karena beberapa alasan berikut:
- Nilai yang ada pada csv tersebut masih dalam range nilai unsigned 8-bit (0-255)
- Semua cell pada csv tersebut terisi
![[Pasted image 20240208222659.png]]

Terdapat juga pada salah satu clue yang dirilis oleh problem setter pada challenge tersebut:

```
Hint soal Citra txt-> csv
```

Dengan asumsi bahwa file tersebut adalah gambar, maka yang perlu dilakukan adalah:
- Membaca file csv, mengubahnya menjadi data gambar. Untungnya, karena semua cell terisi penuh dan tidak ada yang kosong, maka tidak perlu dilakukan pre processing data
- Menyimpannya dalam format gambar dan dapat dilihat

Berikut script Python yang telah dibuat:
```Python
from numpy import genfromtxt
import matplotlib
from matplotlib import pyplot
from matplotlib.image import imread

# read raw image pixel data
im_raw = genfromtxt('chall.csv', delimiter=',')
matplotlib.image.imsave('out.png', im_raw)
image_1 = imread('out.png')

# plot raw pixel data
pyplot.imshow(image_1)

# show image
pyplot.show()
```

Didapatkan gambar sebagai berikut:

![[out.png]]

Dari gambar didapatkan text dengan format hexadecimal sebagai berikut:
```
46696E6449544354467B59345F4E6 4346B5F5461755F4B306B5F4E6434 4B5F54346E79415F4D34737433725 F39393939393939393939397D
```

Hexadecimal tersebut kemudian dilakukan decode menjadi tipe data ASCII sehingga didapatkan flag:

```
FindITCTF{Y4_Nd4k_Tau_K0k_Nd4K_T4nyA_M4st3r_99999999999}
```


## **Hierarchical UGM**

Oleh soal diberikan sebuah attachment berupa gambar, yaitu chall.png. 

![[Pasted image 20240208225953.png]]


Sekilas tidak terlihat apapun pada gambar tersebut, namun saat dioperasikan binwalk pada gambar tersebut, terdapat beberapa file yang tersembunyi, yaitu sebuah archive dan gambar. [Binwalk](https://github.com/ReFirmLabs/binwalk) adalah alat analisis forensik digital powerful yang sering digunakan untuk menyelidiki file binary, seperti firmware perangkat, gambar disk, atau file sistem. Ini memiliki beberapa fungsi penting untuk analisis struktur file, extraksi data, dan analisis signature.

Setelah dilakukan analisis dan ekstraksi file menggunakan binwalk, didapatkan suatu archive zip pada offset file `0x3910`:

![[Pasted image 20240208230900.png]]

Apabila archive tersebut dilakukan extract, maka didapatkan gambar bernama `pict1.png` sebagai berikut: 

![[Pasted image 20240208230810.png]]

Proses yang sama dilakukan pada file yang dihasilkan, sehingga dihasilkan pula `pict2.png` berikut:

![[Pasted image 20240208230803.png]]

Sama seperti step sebelumnya, proses binwalk juga dilakukan pada`pict2.png` yang didapatkan. Hasil yang didapatkan adalah sebuah file PNG baru yang berbeda lagi pada offset `0x38E6`
![[Pasted image 20240213112111.png]]

Ketika PNG tersebut dibuka dengan cara seperti biasa, muncul error sebagai berikut:
![[Pasted image 20240213112501.png]]

Ketika dilakukan cek error png menggunakan `pngcheck` didapatkan hasil sebagai berikut:
![[Pasted image 20240213112554.png]]

Ketika dilakukan analisis hexdump pada file tersebut, ditemukan bahwa terdapat content file yang tidak sesuai dengan signature file PNG yang biasanya [PNG-Gradient hex - PNG - Wikipedia](https://en.wikipedia.org/wiki/PNG#/media/File:PNG-Gradient_hex.png). Pada chunk IHDR file PNG yang muncul mulai pada offset byte ke 13, seharusnya berisi `IHDR` atau `49 48 44 52` dalam hexadesimal. Namun file ini berisi `|HDR`, sehingga terdapat error tersebut. Hal ini diperbaiki dengan mengubah content file tersebut menjadi `IHDR` menggunakan hex editor, dalam hal ini kita gunakan GHex

![[Pasted image 20240213113527.png]]

Setelah dibuka lagi, didapatkan error yang berbeda dari yang sebelumnya sebagai berikut:
![[Pasted image 20240213113629.png]]

CRC (Cyclic Redundancy Check) pada file PNG, terutama pada suatu chunk pada file PNG tersebut bertujuan untuk mendeteksi error pada data chunk tersebut, apabila data apapun yang ada dalam chunk tersebut diubah, maka data CRC dalam chunk tersebut juga harus diubah. Ketika dilakukan pngcheck pada gambar tersebut juga menandakan bahwa CRC pada chunk IHDR tersebut harus diganti:

![[Pasted image 20240213114738.png]]

Pada suatu chunk, bytes CRC terletak pada 4 bytes terakhir pada chunk tersebut. Karena chunk IHDR (Image Header) selalu muncul di awal, maka mencarinya mudah, tinggal menghitung offset bytesnya. Berikut struktur chunk IHDR yang ada pada PNG:
```
The IHDR chunk must appear FIRST. It contains:

   Width:              4 bytes
   Height:             4 bytes
   Bit depth:          1 byte
   Color type:         1 byte
   Compression method: 1 byte
   Filter method:      1 byte
   Interlace method:   1 byte
```

Apabila dihitung dari awal header file tersebut, maka range 4 bytes CRC IHDR terdapat pada 29-32. Kita cuma perlu mengganti CRC IHDR tersebut dari `0xE6A88069` menjadi `0X07D6EDB4` sesuai dengan hasil hitung pngcheck sebelumnya menggunakan hex editor:

![[Pasted image 20240213114852.png]]

Didapatkan gambar berikut apabila dibuka:
![[Pasted image 20240213115131.png]]

Mulai dari sini berbeda dari yang sebelum-sebelumnya, bila binwalk dilakukan pada gambar tersebut, tidak ada lagi informasi berguna yang didapatkan. Namun, pada saat dilakukan pngcheck lagi pada gambar tersebut didapatkan informasi sebagai berikut:

![[Pasted image 20240213115234.png]]

Telah dilakukan kompresi yang cukup berat pada gambar tersebut. Hal ini sangat aneh karena pada saat melihat gambar tersebut, resolusi gambar juga sudah cukup tinggi untuk ukuran 2MB (MegaBytes). Setelah melakukan riset singkat dan clue dari panitia:

```
Clue HierarchicalUGM Hex resize the PNG
```

Ternyata menyembunyikan pixel gambar dengan mengubah informasi IHDR pada suatu gambar PNG dapat dilakukan tanpa mengurangi atau menghilangkan data pixel yang ada pada gambar tersebut.

Maka yang dilakukan adalah menggunakan hex editor untuk mengubah informasi IHDR yang ada pada gambar tersebut, dan pada waktu yang sama memperbaiki juga CRC yang dihasilkan setiap kali mengubah informasi gambar. IHDR pada PNG secara garis besar terdiri dari 4 byte width dan 4 byte height. Karena mengubah width dapat mengubah keseluruhan dari gambar tersebut (skew) sehingga dapat merusak kontek gambar tersebut, maka salah satu yang dapat dilakukan adalah mengubah informasi height dari gambar tersebut:

![[Pasted image 20240213115512.png]]

Height dari `0x000002bc` (700 pixel) diubah menjadi `0x000005bc` (1468 pixel). CRC kemudian juga dicek dengan pngcheck dan diubah dengan hex editor berdasarkan outputnya. Sehingga didapatkan gambar sebagai berikut:

![[Pasted image 20240213115642.png]]

```
FindITCTF{y0u_g0t_m3}
```

## **RouterOS**


Oleh soal disediakan sebuah attachment berupa .ova. File ekstension ova merupakan suatu file yang menyimpan suatu data sebuah virtual machine, biasanya dipakai pada software virtual machine manager seperti virtualbox dan VMWare. Pada challenge ini saya akan menggunakan virtualbox.
Pada virtualbox, attachment ova tersebut di-import menjadi sebuah virtual machine:

![[Pasted image 20240213115804.png]]

Berdasarkan namanya, virtual machine yang disediakan adalah Mikrotik RouterOS, ketika dilakukan command linux biasa seperti ls maupun cd tidak menghasilkan efek apapun, namun ketika dilakukan double tab dan mengetikkan nama folder, akan menuju ke folder tersebut, dan ketika mengetik nama program, akan mengeksekusi program tersebut.

Untuk melihat seluruh konfigurasi yang ada pada RouterOS tersebut, saya melakukan command
```bash
export
```

![[Pasted image 20240213120033.png]]

Langsung dapet flagnya :/

```
FindITCTF{You_Got_Me!_7789a}
```

[home](/)