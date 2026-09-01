import struct, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
img = open(r'build-recheck54\data\image.bin','rb').read()
# image.bin 布局: 从 recovered_metadata.cpp 的 recovered_image_regions 读
src = open(r'build-recheck54\src\recovered_metadata.cpp', encoding='utf-8').read()
i = src.find('recovered_image_regions[]')
print(src[i:i+600])
