import xml.etree.ElementTree as ET

tree = ET.parse(r'checkksec\filter.xml')
root = tree.getroot()

recipe_bins = {}

for file in root.findall('file'):
    canary = file.get('canary', '').strip()
    relro = file.get('relro').strip()
    nx = file.get('nx').strip()
    filename = file.get('filename').strip()

    # Lọc điều kiện canary = no
    if canary == 'no':
        # Lấy tên recipe từ path, ví dụ './go-connections/xxx' → 'go-connections'
        parts = filename.strip('./').split('/')
        if len(parts) > 1:
            recipe = parts[0]
            recipe_bins.setdefault(recipe, []).append(filename)

# # Xuất kết quả
with open("output.txt", "w", encoding="utf-8") as out:
    for recipe, files in recipe_bins.items():
        out.write(f"\n🔧 Recipe: {recipe} ({len(files)} files)\n")
        for f in files:
            out.write(f"  - {f}\n")

with open("output.txt", "w", encoding="utf-8") as out_all, \
     open("recipes_only.txt", "w", encoding="utf-8") as out_recipe:

    for recipe, files in recipe_bins.items():
        header = f"\n🔧 Recipe: {recipe} ({len(files)} files)\n"
        out_all.write(header)
        out_recipe.write(header)
        for f in files:
            out_all.write(f"  - {f}\n")
