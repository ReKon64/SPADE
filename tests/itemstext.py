hash = {
    "Hashmap1": {
        "description": "desc1",
        "add": "lol",
    },
    "Hashmap2": {
        "description": "desc2",
        "add": "kek",
    },
    "Hashmap3": {
        "description": "desc3",
        "add": "lol",
    },
}

for hash, details in hash.items():
    print(f"{hash} hash details: {details}")
    print(f"Hash has descrition of {details['description']}")
