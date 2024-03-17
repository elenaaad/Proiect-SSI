import os
from PIL import Image
import hashlib


def write_ppm_header(file, width, height):
    file.write(f"P6\n")
    file.write(f"{width} {height}\n")
    file.write(f"255\n")


hValues = ["602a4a8fff652291fdc0e049e3900dae608af64e5e4d2c5d4332603c9938171d",
"f40e838809ddaa770428a4b2adc1fff0c38a84abe496940d534af1232c2467d5",
"aa105295e25e11c8c42e4393c008428d965d42c6cb1b906e30be99f94f473bb5",
"70f87d0b880efcdbe159011126db397a1231966991ae9252b278623aeb9c0450",
"77a39d581d3d469084686c90ba08a5fb6ce621a552155730019f6c02cb4c0cb6",
"456ae6a020aa2d54c0c00a71d63033f6c7ca6cbc1424507668cf54b80325dc01",
"bd0fd461d87fba0d5e61bed6a399acdfc92b12769f9b3178f9752e30f1aeb81d",
"372df01b994c2b14969592fd2e78d27e7ee472a07c7ac3dfdf41d345b2f8e305"]

# incerc numere a,b de 3 cifre si le trec prin functia SHA-256 ca sa vad daca vreunul se
# gaseste in hValues

import hashlib

# Define the range for x and y
a_range = range(99, 1001)
b_range = range(99, 1001)

listHeaders = []
listSorted = []

listDimensions = []


# Loop through all pairs of x and y
for a in a_range:
    for b in b_range:
        # Convert x and y to bytes and concatenate them
        data = bytes(f"P6 {a} {b} 255", 'utf-8')
        # Calculate the SHA-256 hash
        sha256_hash = hashlib.sha256(data).hexdigest()
        if sha256_hash in hValues:
            print(f"Match found! Hash: {sha256_hash}")
            product = a*b
            listSorted.append((product, a, b, sha256_hash))

            #listHeaders.append()
    if len(listSorted) == 8:
        continue

listSorted.sort(key=lambda x: x[0])
print(listSorted)

#am lista cu toate valorile de header sortate + hashurile fiecaruia

path = r"C:\Users\elena\PycharmProjects\proiectSSI\encrypted"
ppm_files = [os.path.join(path, file_name) for file_name in os.listdir(path) if file_name.lower().endswith('.ppm')]

print(ppm_files)

dimensions_list = []

for path in ppm_files:
    size= os.path.getsize(path)
    dimensions_list.append((size, path))

dimensions_list.sort(key=lambda x: x[0])
print(dimensions_list)

for i in range(0,8):
    lines = ["P6", str(listSorted[i][1])+ " " +str(listSorted[i][2]), "255"]
    with open(dimensions_list[i][1],'rb') as ppmfile:
        fileContent = ppmfile.read()
    with open(dimensions_list[i][1],'wb') as ppmfile:
        for line in lines:
            ppmfile.write(line.encode('utf-8') + b'\n')
        ppmfile.write(fileContent)

